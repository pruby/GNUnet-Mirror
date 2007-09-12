/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file transports/http.c
 * @brief Implementation of the HTTP transport service
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_transport.h"
#include "gnunet_stats_service.h"
#include "gnunet_upnp_service.h"
#include <microhttpd.h>
#include <curl/curl.h>
#include "platform.h"
#include "ip.h"

#define DEBUG_HTTP NO

/**
 * Disable GET (for debugging only!).  Must be YES
 * in production use!
 */
#define DO_GET YES

/**
 * After how much time of the core not being associated with a http
 * connection anymore do we close it?
 *
 * Needs to be larger than SECONDS_INACTIVE_DROP in
 * core's connection.s
 */
#define HTTP_TIMEOUT (600 * cronSECONDS)

/**
 * Default maximum size of the HTTP read and write buffer.
 */
#define HTTP_BUF_SIZE (64 * 1024)

/**
 * Text of the response sent back after the last bytes of a PUT
 * request have been received (just to formally obey the HTTP 
 * protocol).
 */
#define HTTP_PUT_RESPONSE "Thank you!"

/**
 * Host-Address in a HTTP network.
 */
typedef struct
{
  /**
   * claimed IP of the sender, network byte order
   */
  IPaddr ip;

  /**
   * claimed port of the sender, network byte order
   */
  unsigned short port;

  /**
   * reserved (set to 0 for signature verification)
   */
  unsigned short reserved;

} HostAddress;

/**
 * Client-side data per PUT request.
 */
struct HTTPPutData
{
  /**
   * This is a linked list.
   */
  struct HTTPPutData *next;

  /**
   * Handle to our CURL request.
   */
  CURL *curl_put;

  /**
   * Last time we made progress with the PUT.
   */
  cron_t last_activity;

  /**
   * The message we are sending.
   */
  char *msg;

  /**
   * Size of msg.
   */
  unsigned int size;

  /**
   * Current position in msg.
   */
  unsigned int pos;

  /**
   * Are we done sending?  Set to 1 after we
   * completed sending and started to receive
   * a response ("Thank you!") or once the
   * timeout has been reached.
   */
  int done;

};

/**
 * Server-side data per PUT request.
 */
struct MHDPutData
{
  /**
   * This is a linked list.
   */
  struct MHDPutData *next;

  /**
   * MHD connection handle for this request.
   */
  struct MHD_Connection *session;

  /**
   * Last time we received data on this PUT
   * connection.
   */
  cron_t last_activity;

  /**
   * Read buffer for the header (from PUT)
   */
  char rbuff1[sizeof (MESSAGE_HEADER)];

  /**
   * The read buffer (used only receiving PUT data).
   */
  char *rbuff2;

  /**
   * Number of valid bytes in rbuff1
   */
  unsigned int rpos1;

  /**
   * Number of valid bytes in rbuff2
   */
  unsigned int rpos2;


  /**
   * Size of the rbuff2 buffer.
   */
  unsigned int rsize2;

  /**
   * Should we sent a response for this PUT yet?
   */
  int ready;

  /**
   * Have we sent a response for this PUT yet?
   */
  int done;

};

/**
 * Server-side data for a GET request.
 */
struct MHDGetData
{

  /**
   * This is a linked list.
   */
  struct MHDGetData *next;

  /**
   * mutex for synchronized access to struct
   */
  struct MUTEX *lock;

  /**
   * MHD connection handle for this request.
   */
  struct MHD_Connection *session;

  /**
   * GET session response handle
   */
  struct MHD_Response *get;

  /**
   * My HTTP session.
   */
  struct HTTPSession *httpsession;

  /**
   * The write buffer (for sending GET response)
   */
  char *wbuff;

  /**
   * What was the last time we were able to
   * transmit data using the current get handle?
   */
  cron_t last_get_activity;

  /**
   * Current write position in wbuff
   */
  unsigned int woff;

  /**
   * Number of valid bytes in wbuff (starting at woff)
   */
  unsigned int wpos;

  /**
   * Size of the write buffer.
   */
  unsigned int wsize;

};

/**
 * Transport Session handle.
 */
typedef struct HTTPSession
{

  /**
   * TSession for this session.
   */
  TSession *tsession;

  /**
   * mutex for synchronized access to struct
   */
  struct MUTEX *lock;

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  PeerIdentity sender;

  /**
   * number of users of this session
   */
  unsigned int users;

  /**
   * Has this session been destroyed?
   */
  int destroyed;

  /**
   * Are we client or server?  Determines which of the
   * structs in the union below is being used for this
   * connection!
   */
  int is_client;

  /**
   * Is MHD still using this session handle?
   */
  int is_mhd_active;

  /**
   * Data maintained for the http client-server connection
   * (depends on if we are client or server).
   */
  union
  {

    struct
    {
      /**
       * Active PUT requests (linked list).
       */
      struct MHDPutData *puts;

#if DO_GET
      /**
       * Active GET requests (linked list; most
       * recent received GET is the head of the list).
       */
      struct MHDGetData *gets;
#endif

    } server;

    struct
    {

      /**
       * Address of the other peer.
       */
      HostAddress address;

#if DO_GET
      /**
       * Last time the GET was active.
       */
      cron_t last_get_activity;

      /**
       * GET operation
       */
      CURL *get;

      /**
       * Read buffer for the header (from GET).
       */
      char rbuff1[sizeof (MESSAGE_HEADER)];

      /**
       * The read buffer (used only receiving GET data).
       */
      char *rbuff2;

      /**
       * Number of valid bytes in rbuff1
       */
      unsigned int rpos1;

      /**
       * Number of valid bytes in rbuff2
       */
      unsigned int rpos2;

      /**
       * Current size of the read buffer rbuff2.
       */
      unsigned int rsize2;
#endif

      /**
       * URL of the get and put operations.
       */
      char *url;

      /**
       * Linked list of PUT operations.
       */
      struct HTTPPutData *puts;

    } client;

  } cs;

} HTTPSession;

/* *********** globals ************* */

/**
 * apis (our advertised API and the core api )
 */
static CoreAPIForTransport *coreAPI;

static Stats_ServiceAPI *stats;

static int stat_bytesReceived;

static int stat_bytesSent;

static int stat_bytesDropped;

static int signal_pipe[2];

static char *proxy;

/**
 * Daemon for listening for new connections.
 */
static struct MHD_Daemon *mhd_daemon;

/**
 * Curl multi for managing client operations.
 */
static CURLM *curl_multi;

/**
 * Set to YES while the transport is running.
 */
static int http_running;

/**
 * Thread running libcurl activities.
 */
static struct PTHREAD *curl_thread;

/**
 * Array of currently active HTTP sessions.
 */
static TSession **tsessions;

/**
 * Number of valid entries in tsessions.
 */
static unsigned int tsessionCount;

/**
 * Sie of the tsessions array.
 */
static unsigned int tsessionArrayLength;

/**
 * Blacklist configuration
 */
static struct CIDRNetwork *filteredNetworks_;

/**
 * Universal plug & play (firewall hole punching)
 */
static UPnP_ServiceAPI *upnp;

/**
 * Lock for access to mutable state of the module,
 * that is the configuration and the tsessions array.
 * Note that we ONLY need to synchronize access to
 * the tsessions array when adding or removing sessions,
 * since removing is done only by one thread and we just
 * need to avoid another thread adding an element at the
 * same point in time. We do not need to synchronize at
 * every access point since adding new elements does not
 * prevent the select thread from operating and removing
 * is done by the only therad that reads from the array.
 */
static struct MUTEX *httplock;


/**
 * Signal select thread that its selector
 * set may have changed.
 */
static void
signal_select ()
{
  static char c;
  write (signal_pipe[1], &c, sizeof (c));
}

/**
 * Check if we are allowed to connect to the given IP.
 */
static int
acceptPolicyCallback (void *cls,
                      const struct sockaddr *addr, socklen_t addr_len)
{
  IPaddr ip;
  int ret;

  if (addr_len == sizeof (struct sockaddr_in))
    {
      memcpy (&ip, &((struct sockaddr_in *) addr)->sin_addr, sizeof (IPaddr));
    }
  else if (addr_len == sizeof (IPaddr))
    {
      memcpy (&ip, addr, addr_len);
    }
  else
    {
#if DEBUG_HTTP
      GE_LOG (coreAPI->ectx,
              GE_DEBUG | GE_DEVELOPER | GE_BULK,
              "Rejecting HTTP connection\n");
#endif
      return MHD_NO;
    }
  MUTEX_LOCK (httplock);
  ret = check_ipv4_listed (filteredNetworks_, ip);
  MUTEX_UNLOCK (httplock);
  if (YES == ret)
    {
#if DEBUG_HTTP
      GE_LOG (coreAPI->ectx,
              GE_DEBUG | GE_DEVELOPER | GE_BULK,
              "Rejecting HTTP connection\n");
#endif
      return MHD_NO;
    }
#if DEBUG_HTTP
  GE_LOG (coreAPI->ectx,
          GE_DEBUG | GE_DEVELOPER | GE_BULK, "Accepting HTTP connection\n");
#endif
  return MHD_YES;
}

/**
 * Disconnect from a remote node. May only be called
 * on sessions that were acquired by the caller first.
 * For the core, aquiration means to call associate or
 * connect. The number of disconnects must match the
 * number of calls to connect+associate.
 * 
 * Sessions are actually discarded in cleanup_connections.
 * 
 *
 * @param tsession the session that is closed
 * @return OK on success, SYSERR if the operation failed
 */
static int
httpDisconnect (TSession * tsession)
{
  HTTPSession *httpsession = tsession->internal;
  if (httpsession == NULL)
    {
      FREE (tsession);
      return OK;
    }
  MUTEX_LOCK (httpsession->lock);
  httpsession->users--;
  MUTEX_UNLOCK (httpsession->lock);
  return OK;
}

static void
destroy_tsession (TSession * tsession)
{
  HTTPSession *httpsession = tsession->internal;
  struct HTTPPutData *pos;
  struct HTTPPutData *next;
  struct MHDPutData *mpos;
  struct MHDPutData *mnext;
#if DO_GET
  struct MHDGetData *gpos;
  struct MHDGetData *gnext;
#endif
  struct MHD_Response *r;
  int i;

  MUTEX_LOCK (httplock);
  for (i = 0; i < tsessionCount; i++)
    {
      if (tsessions[i] == tsession)
        {
          tsessions[i] = tsessions[--tsessionCount];
          break;
        }
    }
  MUTEX_UNLOCK (httplock);
  if (httpsession->is_client)
    {
#if DO_GET
      curl_multi_remove_handle (curl_multi, httpsession->cs.client.get);
      signal_select ();
      curl_easy_cleanup (httpsession->cs.client.get);
      GROW (httpsession->cs.client.rbuff2, httpsession->cs.client.rsize2, 0);
#endif
      FREE (httpsession->cs.client.url);
      pos = httpsession->cs.client.puts;
      while (pos != NULL)
        {
          next = pos->next;
          curl_multi_remove_handle (curl_multi, pos->curl_put);
          signal_select ();
          curl_easy_cleanup (pos->curl_put);
          FREE (pos->msg);
          FREE (pos);
          pos = next;
        }
      MUTEX_DESTROY (httpsession->lock);
      FREE (httpsession);
      FREE (tsession);
    }
  else
    {
      httpsession->destroyed = YES;
      mpos = httpsession->cs.server.puts;
      /* this should be NULL already, but just
         in case it is not, we free it anyway... */
      while (mpos != NULL)
        {
          mnext = mpos->next;
          GROW (mpos->rbuff2, mpos->rsize2, 0);
          FREE (mpos);
          mpos = mnext;
        }
      httpsession->cs.server.puts = NULL;
#if DO_GET
      gpos = httpsession->cs.server.gets;
      while (gpos != NULL)
        {
          GROW (gpos->wbuff, gpos->wsize, 0);
          r = gpos->get;
          gpos->get = NULL;
          /* contentReaderFreeCallback WILL
             destroy session->lock/tesssion */
          gnext = gpos->next;
          MHD_destroy_response (r);
          gpos = gnext;
        }
      httpsession->cs.server.gets = NULL;
#endif
      MUTEX_DESTROY (httpsession->lock);
      FREE (httpsession->tsession);
      FREE (httpsession);
    }
}

/**
 * MHD is done handling a request.  Cleanup
 * the respective transport state.
 */
static void
requestCompletedCallback (void *unused,
                          struct MHD_Connection *session,
                          void **httpSessionCache)
{
  HTTPSession *httpsession = *httpSessionCache;
  struct MHDPutData *pprev;
  struct MHDPutData *ppos;
#if DO_GET
  struct MHDGetData *gprev;
  struct MHDGetData *gpos;
#endif

  if (httpsession == NULL)
    return;                     /* oops */
  GE_ASSERT (NULL, !httpsession->is_client);
  pprev = NULL;
  ppos = httpsession->cs.server.puts;
  while (ppos != NULL)
    {
      if (ppos->session == session)
        {
          ppos->last_activity = 0;
          signal_select ();
          return;
        }
      pprev = ppos;
      ppos = ppos->next;
    }
#if DO_GET
  gprev = NULL;
  gpos = httpsession->cs.server.gets;
  while (gpos != NULL)
    {
      if (gpos->session == session)
        {
          gpos->last_get_activity = 0;
          signal_select ();
          return;
        }
      gprev = gpos;
      gpos = gpos->next;
    }
#endif
  httpsession->is_mhd_active--;
}

/**
 * Get the GNUnet HTTP port from the configuration, or from
 * /etc/services if it is not specified in the config file.
 */
static unsigned short
getGNUnetHTTPPort ()
{
  unsigned long long port;

  if (-1 == GC_get_configuration_value_number (coreAPI->cfg,
                                               "HTTP",
                                               "PORT", 0, 65535, 1080, &port))
    port = 1080;
  return (unsigned short) port;
}

/**
 * Get the GNUnet HTTP port from the configuration, or from
 * /etc/services if it is not specified in the config file.
 */
static unsigned short
getGNUnetAdvertisedHTTPPort ()
{
  unsigned long long port;

  if (!GC_have_configuration_value (coreAPI->cfg, "HTTP", "ADVERTISED-PORT"))
    {
      port = getGNUnetHTTPPort ();
    }
  else if (-1 == GC_get_configuration_value_number (coreAPI->cfg,
                                                    "HTTP",
                                                    "ADVERTISED-PORT", 0,
                                                    65535, 80, &port))
    port = getGNUnetHTTPPort ();
  return (unsigned short) port;
}

/**
 * A (core) Session is to be associated with a transport session. The
 * transport service may want to know in order to call back on the
 * core if the connection is being closed. Associate can also be
 * called to test if it would be possible to associate the session
 * later, in this case the argument session is NULL. This can be used
 * to test if the connection must be closed by the core or if the core
 * can assume that it is going to be self-managed (if associate
 * returns OK and session was NULL, the transport layer is responsible
 * for eventually freeing resources associated with the tesession). If
 * session is not NULL, the core takes responsbility for eventually
 * calling disconnect.
 *
 * @param tsession the session handle passed along
 *   from the call to receive that was made by the transport
 *   layer
 * @return OK if the session could be associated,
 *         SYSERR if not.
 */
static int
httpAssociate (TSession * tsession)
{
  HTTPSession *httpSession;

  if (tsession == NULL)
    {
      GE_BREAK (NULL, 0);
      return SYSERR;
    }
  httpSession = tsession->internal;
  MUTEX_LOCK (httpSession->lock);
  if (httpSession->destroyed == YES)
    {
      MUTEX_UNLOCK (httpSession->lock);
      return SYSERR;
    }
  httpSession->users++;
  MUTEX_UNLOCK (httpSession->lock);
  return OK;
}


/**
 * Verify that a hello-Message is correct (a node
 * is reachable at that address). Since the reply
 * will be asynchronous, a method must be called on
 * success.
 * @param helo the hello message to verify
 *        (the signature/crc have been verified before)
 * @return OK on success, SYSERR on error
 */
static int
verifyHello (const P2P_hello_MESSAGE * hello)
{
  const HostAddress *haddr;

  haddr = (const HostAddress *) &hello[1];
  if ((ntohs (hello->senderAddressSize) != sizeof (HostAddress)) ||
      (ntohs (hello->header.size) != P2P_hello_MESSAGE_size (hello)) ||
      (ntohs (hello->header.type) != p2p_PROTO_hello) ||
      (ntohs (hello->protocol) != HTTP_PROTOCOL_NUMBER) ||
      (MHD_NO == acceptPolicyCallback (NULL,
                                       (const struct sockaddr *) haddr,
                                       sizeof (IPaddr))))
    {
      GE_BREAK_OP (NULL, 0);
      return SYSERR;            /* obviously invalid */
    }
  return OK;
}

/**
 * Create a hello-Message for the current node. The hello is
 * created without signature and without a timestamp. The
 * GNUnet core will sign the message and add an expiration time.
 *
 * @return hello on success, NULL on error
 */
static P2P_hello_MESSAGE *
createhello ()
{
  P2P_hello_MESSAGE *msg;
  HostAddress *haddr;
  unsigned short port;

  port = getGNUnetAdvertisedHTTPPort ();
  if (0 == port)
    {
#if DEBUG_HTTP
      GE_LOG (NULL,
              GE_DEBUG | GE_REQUEST | GE_USER,
              "HTTP port is 0, will only send using HTTP.\n");
#endif
      return NULL;              /* HTTP transport is configured SEND-only! */
    }
  msg = MALLOC (sizeof (P2P_hello_MESSAGE) + sizeof (HostAddress));
  haddr = (HostAddress *) & msg[1];

  if (!(((upnp != NULL) &&
         (OK == upnp->get_ip (port,
                              "TCP",
                              &haddr->ip))) ||
        (SYSERR != getPublicIPAddress (coreAPI->cfg,
                                       coreAPI->ectx, &haddr->ip))))
    {
      FREE (msg);
      GE_LOG (coreAPI->ectx,
              GE_WARNING | GE_ADMIN | GE_USER | GE_BULK,
              _("HTTP: Could not determine my public IP address.\n"));
      return NULL;
    }
#if DEBUG_HTTP
  GE_LOG (coreAPI->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "HTTP uses IP address %u.%u.%u.%u.\n",
          PRIP (ntohl (*(int *) &haddr->ip)));
#endif
  haddr->port = htons (port);
  haddr->reserved = htons (0);
  msg->senderAddressSize = htons (sizeof (HostAddress));
  msg->protocol = htons (HTTP_PROTOCOL_NUMBER);
  msg->MTU = htonl (0);
  return msg;
}

/**
 * Add a new session to the array watched by the select thread.  Grows
 * the array if needed.  If the caller wants to do anything useful
 * with the return value, it must have the lock on httplock before
 * calling.  It is ok to call this function without holding httplock if
 * the return value is ignored.
 */
static unsigned int
addTSession (TSession * tsession)
{
  unsigned int i;

  MUTEX_LOCK (httplock);
  if (tsessionCount == tsessionArrayLength)
    GROW (tsessions, tsessionArrayLength, tsessionArrayLength * 2);
  i = tsessionCount;
  tsessions[tsessionCount++] = tsession;
  MUTEX_UNLOCK (httplock);
  return i;
}

#if DO_GET
/**
 * Callback for processing GET requests if our side is the
 * MHD HTTP server.
 *
 * @param cls the HTTP session
 * @param pos read-offset in the stream
 * @param buf where to write the data
 * @param max how much data to write (at most)
 * @return number of bytes written, 0 is allowed!
 */
static int
contentReaderCallback (void *cls, size_t pos, char *buf, int max)
{
  struct MHDGetData *mgd = cls;
  cron_t now;

  MUTEX_LOCK (mgd->lock);
  if (mgd->wpos < max)
    max = mgd->wpos;
  memcpy (buf, &mgd->wbuff[mgd->woff], max);
  mgd->wpos -= max;
  mgd->woff += max;
  now = get_time ();
  if (max > 0)
    mgd->last_get_activity = now;
  if (mgd->wpos == 0)
    mgd->woff = 0;
  MUTEX_UNLOCK (mgd->lock);
#if DEBUG_HTTP
  GE_LOG (coreAPI->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "HTTP returns %u bytes in MHD GET handler.\n", max);
#endif
  if (stats != NULL)
    stats->change (stat_bytesSent, max);
  if ((max == 0) && (mgd->httpsession->cs.server.gets != mgd))
    return -1;                  /* end of response (another GET replaces this one) */
  return max;
}
#endif

#if DO_GET
/**
 * Notification that libmicrohttpd no longer needs the
 * response object.
 */
static void
contentReaderFreeCallback (void *cls)
{
  struct MHDGetData *mgd = cls;

  GE_ASSERT (NULL, mgd->get == NULL);
  MUTEX_DESTROY (mgd->lock);
  GROW (mgd->wbuff, mgd->wsize, 0);
  FREE (mgd);
}
#endif

/**
 * Process GET or PUT request received via MHD.  For
 * GET, queue response that will send back our pending
 * messages.  For PUT, process incoming data and send
 * to GNUnet core.  In either case, check if a session
 * already exists and create a new one if not.
 */
static int
accessHandlerCallback (void *cls,
                       struct MHD_Connection *session,
                       const char *url,
                       const char *method,
                       const char *version,
                       const char *upload_data,
                       unsigned int *upload_data_size,
                       void **httpSessionCache)
{
  TSession *tsession;
  struct MHDPutData *put;
  struct MHDGetData *get;
  HTTPSession *httpSession;
  struct MHD_Response *response;
  HashCode512 client;
  int i;
  unsigned int have;
  MESSAGE_HEADER *hdr;
  P2P_PACKET *mp;
  unsigned int cpy;
  unsigned int poff;

  /* convert URL to sender peer id */
  if ((strlen (url) < 2) || (OK != enc2hash (&url[1], &client)))
    {
      /* invalid request */
      GE_BREAK_OP (NULL, 0);
      return MHD_NO;
    }

  /* check if we already have a session for this */
  httpSession = *httpSessionCache;
  if (httpSession == NULL)
    {
      MUTEX_LOCK (httplock);
      for (i = 0; i < tsessionCount; i++)
        {
          tsession = tsessions[i];
          httpSession = tsession->internal;
          if ((0 ==
               memcmp (&httpSession->sender, &client, sizeof (HashCode512)))
              && (httpSession->is_client == NO))
            break;
          tsession = NULL;
          httpSession = NULL;
        }
      MUTEX_UNLOCK (httplock);
    }
  /* create new session if necessary */
  if (httpSession == NULL)
    {
#if DEBUG_HTTP
      GE_LOG (coreAPI->ectx,
              GE_DEBUG | GE_REQUEST | GE_USER,
              "HTTP/MHD creates new session for request from `%s'.\n",
              &url[1]);
#endif
      httpSession = MALLOC (sizeof (HTTPSession));
      memset (httpSession, 0, sizeof (HTTPSession));
      httpSession->sender.hashPubKey = client;
      httpSession->lock = MUTEX_CREATE (YES);
      httpSession->users = 0;   /* MHD */
      tsession = MALLOC (sizeof (TSession));
      memset (tsession, 0, sizeof (TSession));
      tsession->ttype = HTTP_PROTOCOL_NUMBER;
      tsession->internal = httpSession;
      tsession->peer.hashPubKey = client;
      httpSession->tsession = tsession;
      addTSession (tsession);
    }
  if (*httpSessionCache == NULL) {
    httpSession->is_mhd_active++;
    *httpSessionCache = httpSession;
  }
  MUTEX_LOCK (httpSession->lock);
#if DO_GET
  if (0 == strcasecmp (MHD_HTTP_METHOD_GET, method))
    {
#if DEBUG_HTTP
      GE_LOG (coreAPI->ectx,
              GE_DEBUG | GE_REQUEST | GE_USER,
              "HTTP/MHD receives GET request from `%s'.\n", &url[1]);
#endif

      /* handle get; create response object if we do not 
         have one already */
      get = MALLOC (sizeof (struct MHDGetData));
      memset (get, 0, sizeof (struct MHDGetData));
      get->lock = MUTEX_CREATE (NO);
      get->next = httpSession->cs.server.gets;
      httpSession->cs.server.gets = get;
      get->session = session;
      get->httpsession = httpSession;
      get->last_get_activity = get_time ();
      get->get = MHD_create_response_from_callback (-1,
                                                    64 * 1024,
                                                    contentReaderCallback,
                                                    get,
                                                    contentReaderFreeCallback);
      MHD_queue_response (session, MHD_HTTP_OK, get->get);
      MUTEX_UNLOCK (httpSession->lock);
      return MHD_YES;
    }
#endif
  if (0 == strcasecmp (MHD_HTTP_METHOD_PUT, method))
    {
#if DEBUG_HTTP
      GE_LOG (coreAPI->ectx,
              GE_DEBUG | GE_REQUEST | GE_USER,
              "HTTP/MHD receives PUT request from `%s' with %u bytes.\n",
              &url[1], *upload_data_size);
#endif
      put = httpSession->cs.server.puts;
      while ((put != NULL) && (put->session != session))
        put = put->next;
      if (put == NULL)
        {
          put = MALLOC (sizeof (struct MHDPutData));
          memset (put, 0, sizeof (struct MHDPutData));
          put->next = httpSession->cs.server.puts;
          httpSession->cs.server.puts = put;
          put->session = session;
        }
      put->last_activity = get_time ();

      /* handle put (upload_data!) */
      poff = 0;
      have = *upload_data_size;
      if (stats != NULL)
        stats->change (stat_bytesReceived, have);
      *upload_data_size = 0;    /* we will always process everything */
      if ((have == 0) && (put->done == NO) && (put->ready == YES))
        {
          put->done = YES;
          /* end of upload, send response! */
#if DEBUG_HTTP
          GE_LOG (coreAPI->ectx,
                  GE_DEBUG | GE_REQUEST | GE_USER,
                  "HTTP/MHD queues dummy response to completed PUT request.\n");
#endif
          response =
            MHD_create_response_from_data (strlen (HTTP_PUT_RESPONSE),
                                           HTTP_PUT_RESPONSE, MHD_NO, MHD_NO);
          MHD_queue_response (session, MHD_HTTP_OK, response);
          MHD_destroy_response (response);
          MUTEX_UNLOCK (httpSession->lock);
          return MHD_YES;
        }
      while (have > 0)
        {
          put->ready = NO;
          if (put->rpos1 < sizeof (MESSAGE_HEADER))
            {
              cpy = sizeof (MESSAGE_HEADER) - put->rpos1;
              if (cpy > have)
                cpy = have;
              memcpy (&put->rbuff1[put->rpos1], &upload_data[poff], cpy);
              put->rpos1 += cpy;
              have -= cpy;
              poff += cpy;
              put->rpos2 = 0;
            }
          if (put->rpos1 < sizeof (MESSAGE_HEADER))
            break;
          hdr = (MESSAGE_HEADER *) put->rbuff1;
          GROW (put->rbuff2,
                put->rsize2, ntohs (hdr->size) - sizeof (MESSAGE_HEADER));
          if (put->rpos2 < ntohs (hdr->size) - sizeof (MESSAGE_HEADER))
            {
              cpy = ntohs (hdr->size) - sizeof (MESSAGE_HEADER) - put->rpos2;
              if (cpy > have)
                cpy = have;
              memcpy (&put->rbuff2[put->rpos2], &upload_data[poff], cpy);
              have -= cpy;
              poff += cpy;
              put->rpos2 += cpy;
            }
          if (put->rpos2 < ntohs (hdr->size) - sizeof (MESSAGE_HEADER))
            break;
          mp = MALLOC (sizeof (P2P_PACKET));
          mp->msg = put->rbuff2;
          mp->sender = httpSession->sender;
          mp->tsession = httpSession->tsession;
          mp->size = ntohs (hdr->size) - sizeof (MESSAGE_HEADER);
#if DEBUG_HTTP
          GE_LOG (coreAPI->ectx,
                  GE_DEBUG | GE_REQUEST | GE_USER,
                  "HTTP/MHD passes %u bytes to core (received via PUT request).\n",
                  mp->size);
#endif
          coreAPI->receive (mp);
          put->rbuff2 = NULL;
          put->rpos2 = 0;
          put->rsize2 = 0;
          put->rpos1 = 0;
          put->ready = YES;
        }
      MUTEX_UNLOCK (httpSession->lock);
      return MHD_YES;
    }
  MUTEX_UNLOCK (httpSession->lock);
  GE_BREAK_OP (NULL, 0);        /* invalid request */
  return MHD_NO;
}

#if DO_GET
/**
 * Process downloaded bits (from GET via CURL).
 */
static size_t
receiveContentCallback (void *ptr, size_t size, size_t nmemb, void *ctx)
{
  HTTPSession *httpSession = ctx;
  const char *inbuf = ptr;
  size_t have = size * nmemb;
  size_t poff = 0;
  size_t cpy;
  MESSAGE_HEADER *hdr;
  P2P_PACKET *mp;

  httpSession->cs.client.last_get_activity = get_time ();
#if DEBUG_HTTP
  GE_LOG (coreAPI->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "HTTP/CURL receives %u bytes as response to GET.\n", size * nmemb);
#endif
  while (have > 0)
    {
      if (httpSession->cs.client.rpos1 < sizeof (MESSAGE_HEADER))
        {
          cpy = sizeof (MESSAGE_HEADER) - httpSession->cs.client.rpos1;
          if (cpy > have)
            cpy = have;
          memcpy (&httpSession->cs.client.
                  rbuff1[httpSession->cs.client.rpos1], &inbuf[poff], cpy);
          httpSession->cs.client.rpos1 += cpy;
          have -= cpy;
          poff += cpy;
          httpSession->cs.client.rpos2 = 0;
        }
      if (httpSession->cs.client.rpos1 < sizeof (MESSAGE_HEADER))
        break;
      hdr = (MESSAGE_HEADER *) httpSession->cs.client.rbuff1;
      GROW (httpSession->cs.client.rbuff2,
            httpSession->cs.client.rsize2,
            ntohs (hdr->size) - sizeof (MESSAGE_HEADER));
      if (httpSession->cs.client.rpos2 <
          ntohs (hdr->size) - sizeof (MESSAGE_HEADER))
        {
          cpy =
            ntohs (hdr->size) - sizeof (MESSAGE_HEADER) -
            httpSession->cs.client.rpos2;
          if (cpy > have)
            cpy = have;
          memcpy (&httpSession->cs.client.
                  rbuff2[httpSession->cs.client.rpos2], &inbuf[poff], cpy);
          have -= cpy;
          poff += cpy;
          httpSession->cs.client.rpos2 += cpy;
        }
      if (httpSession->cs.client.rpos2 <
          ntohs (hdr->size) - sizeof (MESSAGE_HEADER))
        break;
      mp = MALLOC (sizeof (P2P_PACKET));
      mp->msg = httpSession->cs.client.rbuff2;
      mp->sender = httpSession->sender;
      mp->tsession = httpSession->tsession;
      mp->size = ntohs (hdr->size) - sizeof (MESSAGE_HEADER);
      coreAPI->receive (mp);
      httpSession->cs.client.rbuff2 = NULL;
      httpSession->cs.client.rpos2 = 0;
      httpSession->cs.client.rsize2 = 0;
      httpSession->cs.client.rpos1 = 0;
    }
  if (stats != NULL)
    stats->change (stat_bytesReceived, size * nmemb);
  return size * nmemb;
}
#endif

/**
 * Provide bits for upload: we're using CURL for a PUT request
 * and now need to provide data from the message we are transmitting.
 */
static size_t
sendContentCallback (void *ptr, size_t size, size_t nmemb, void *ctx)
{
  struct HTTPPutData *put = ctx;
  size_t max = size * nmemb;

  put->last_activity = get_time ();
  if (max > put->size - put->pos)
    max = put->size - put->pos;
  memcpy (ptr, &put->msg[put->pos], max);
  put->pos += max;
#if DEBUG_HTTP
  GE_LOG (coreAPI->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "HTTP/CURL sends %u bytes in PUT request.\n", max);
#endif
  if (stats != NULL)
    stats->change (stat_bytesSent, max);
  return max;
}

#define CURL_EASY_SETOPT(c, a, b) do { ret = curl_easy_setopt(c, a, b); if (ret != CURLE_OK) GE_LOG(coreAPI->ectx, GE_WARNING | GE_USER | GE_BULK, _("%s failed at %s:%d: `%s'\n"), "curl_easy_setopt", __FILE__, __LINE__, curl_easy_strerror(ret)); } while (0);

static void
create_session_url (HTTPSession * httpSession)
{
  char *url;
  EncName enc;

  url = httpSession->cs.client.url;
  if (url == NULL)
    {
      hash2enc (&httpSession->sender.hashPubKey, &enc);
      url = MALLOC (64 + sizeof (EncName));
      SNPRINTF (url,
                64 + sizeof (EncName),
                "http://%u.%u.%u.%u:%u/%s",
                PRIP (ntohl
                      (*(int *) &httpSession->cs.client.address.ip.addr)),
                ntohs (httpSession->cs.client.address.port), &enc);
      httpSession->cs.client.url = url;
    }
}

#if DO_GET
/**
 * Try to do a GET on the other peer of the given
 * http session.
 * 
 * @return OK on success, SYSERR on error
 */
static int
create_curl_get (HTTPSession * httpSession)
{
  CURL *curl_get;
  CURLcode ret;
  CURLMcode mret;

  curl_get = httpSession->cs.client.get;
  if (curl_get != NULL)
    {
      curl_multi_remove_handle (curl_multi, curl_get);
      signal_select ();
      curl_easy_cleanup (curl_get);
      httpSession->cs.client.get = NULL;
    }
  curl_get = curl_easy_init ();
  if (curl_get == NULL)
    return SYSERR;
  /* create GET */
  CURL_EASY_SETOPT (curl_get, CURLOPT_FAILONERROR, 1);
  CURL_EASY_SETOPT (curl_get, CURLOPT_URL, httpSession->cs.client.url);
  if (strlen (proxy) > 0)
    CURL_EASY_SETOPT (curl_get, CURLOPT_PROXY, proxy);
  CURL_EASY_SETOPT (curl_get, CURLOPT_BUFFERSIZE, 32 * 1024);
  if (0 == strncmp (httpSession->cs.client.url, "http", 4))
    CURL_EASY_SETOPT (curl_get, CURLOPT_USERAGENT, "GNUnet-http");
#if 0
  CURL_EASY_SETOPT (curl_get, CURLOPT_VERBOSE, 1);
#endif
  CURL_EASY_SETOPT (curl_get, CURLOPT_CONNECTTIMEOUT, 150L);
  CURL_EASY_SETOPT (curl_get, CURLOPT_TIMEOUT, 150L);
  CURL_EASY_SETOPT (curl_get, CURLOPT_WRITEFUNCTION, &receiveContentCallback);
  CURL_EASY_SETOPT (curl_get, CURLOPT_WRITEDATA, httpSession);
  CURL_EASY_SETOPT (curl_get, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
  if (ret != CURLE_OK)
    {
      curl_easy_cleanup (curl_get);
      return SYSERR;
    }
  mret = curl_multi_add_handle (curl_multi, curl_get);
  if (mret != CURLM_OK)
    {
      GE_LOG (coreAPI->ectx,
              GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
              _("%s failed at %s:%d: `%s'\n"),
              "curl_multi_add_handle",
              __FILE__, __LINE__, curl_multi_strerror (mret));
      curl_easy_cleanup (curl_get);
      return SYSERR;
    }
  signal_select ();
  httpSession->cs.client.last_get_activity = get_time ();
  httpSession->cs.client.get = curl_get;
#if DEBUG_HTTP
  GE_LOG (coreAPI->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "HTTP/CURL initiated GET request.\n");
#endif
  return OK;
}
#endif

/**
 * Establish a connection to a remote node.
 *
 * @param hello the hello-Message for the target node
 * @param tsessionPtr the session handle that is set
 * @return OK on success, SYSERR if the operation failed
 */
static int
httpConnect (const P2P_hello_MESSAGE * hello, TSession ** tsessionPtr,
             int may_reuse)
{
  const HostAddress *haddr = (const HostAddress *) &hello[1];
  TSession *tsession;
  HTTPSession *httpSession;
  int i;

  /* check if we have a session pending for this peer */
  tsession = NULL;
  if (may_reuse)
    {
      MUTEX_LOCK (httplock);
      for (i = 0; i < tsessionCount; i++)
        {
          if (0 == memcmp (&hello->senderIdentity,
                           &tsessions[i]->peer, sizeof (PeerIdentity)))
            {
              tsession = tsessions[i];
              break;
            }
        }
      if ((tsession != NULL) && (OK == httpAssociate (tsession)))
        {
          *tsessionPtr = tsession;
          MUTEX_UNLOCK (httplock);
          return OK;
        }
      MUTEX_UNLOCK (httplock);
    }
  /* no session pending, initiate a new one! */
  httpSession = MALLOC (sizeof (HTTPSession));
  memset (httpSession, 0, sizeof (HTTPSession));
  httpSession->sender = hello->senderIdentity;
  httpSession->lock = MUTEX_CREATE (YES);
  httpSession->users = 1;       /* us only, core has not seen this tsession! */
  httpSession->is_client = YES;
  httpSession->cs.client.address = *haddr;
  tsession = MALLOC (sizeof (TSession));
  memset (tsession, 0, sizeof (TSession));
  httpSession->tsession = tsession;
  tsession->ttype = HTTP_PROTOCOL_NUMBER;
  tsession->internal = httpSession;
  tsession->peer = hello->senderIdentity;
  create_session_url (httpSession);
#if DO_GET
  if (OK != create_curl_get (httpSession))
    {
      FREE (tsession);
      FREE (httpSession);
      return SYSERR;
    }
#endif
  /* PUTs will be created as needed */
  addTSession (tsession);
  *tsessionPtr = tsession;
#if DEBUG_HTTP
  GE_LOG (coreAPI->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "HTTP/CURL initiated connection to `%s'.\n",
          httpSession->cs.client.url);
#endif
  return OK;
}

/**
 * We received the "Thank you!" response to a PUT.
 * Discard the data (not useful) and mark the PUT
 * operation as completed.
 */
static size_t
discardContentCallback (void *data, size_t size, size_t nmemb, void *put_cls)
{
  struct HTTPPutData *put = put_cls;
  /* this condition should pretty much always be
     true; just checking here in case the PUT 
     response comes early somehow */
  if (put->pos == put->size)
    put->done = YES;
  return size * nmemb;
}

/**
 * Create a new PUT request for the given PUT data.
 */
static int
create_curl_put (HTTPSession * httpSession, struct HTTPPutData *put)
{
  CURL *curl_put;
  CURLcode ret;
  CURLMcode mret;
  long size;

  /* we should have initiated a GET earlier,
     so URL must not be NULL here */
  GE_ASSERT (NULL, httpSession->cs.client.url != NULL);
  curl_put = curl_easy_init ();
  if (curl_put == NULL)
    return SYSERR;
  CURL_EASY_SETOPT (curl_put, CURLOPT_FAILONERROR, 1);
  CURL_EASY_SETOPT (curl_put, CURLOPT_URL, httpSession->cs.client.url);
  if (strlen (proxy) > 0)
    CURL_EASY_SETOPT (curl_put, CURLOPT_PROXY, proxy);
  CURL_EASY_SETOPT (curl_put, CURLOPT_BUFFERSIZE, put->size);
  if (0 == strncmp (httpSession->cs.client.url, "http", 4))
    CURL_EASY_SETOPT (curl_put, CURLOPT_USERAGENT, "GNUnet-http");
  CURL_EASY_SETOPT (curl_put, CURLOPT_UPLOAD, 1);
#if 0
  CURL_EASY_SETOPT (curl_put, CURLOPT_VERBOSE, 1);
#endif
  CURL_EASY_SETOPT (curl_put, CURLOPT_CONNECTTIMEOUT, 150L);
  CURL_EASY_SETOPT (curl_put, CURLOPT_TIMEOUT, 150L);
  size = put->size;
  CURL_EASY_SETOPT (curl_put, CURLOPT_INFILESIZE, size);
  CURL_EASY_SETOPT (curl_put, CURLOPT_READFUNCTION, &sendContentCallback);
  CURL_EASY_SETOPT (curl_put, CURLOPT_READDATA, put);
  CURL_EASY_SETOPT (curl_put, CURLOPT_WRITEFUNCTION, &discardContentCallback);
  CURL_EASY_SETOPT (curl_put, CURLOPT_WRITEDATA, put);
  CURL_EASY_SETOPT (curl_put, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
  if (ret != CURLE_OK)
    {
      curl_easy_cleanup (curl_put);
      return SYSERR;
    }
  mret = curl_multi_add_handle (curl_multi, curl_put);
  if (mret != CURLM_OK)
    {
      GE_LOG (coreAPI->ectx,
              GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
              _("%s failed at %s:%d: `%s'\n"),
              "curl_multi_add_handle",
              __FILE__, __LINE__, curl_multi_strerror (mret));
      MUTEX_UNLOCK (httplock);
      return SYSERR;
    }
  signal_select ();
  put->curl_put = curl_put;
#if DEBUG_HTTP
  GE_LOG (coreAPI->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "HTTP/CURL initiated PUT request to `%s'.\n",
          httpSession->cs.client.url);
#endif
  return OK;
}


/**
 * Test if the transport would even try to send
 * a message of the given size and importance
 * for the given session.<br>
 * This function is used to check if the core should
 * even bother to construct (and encrypt) this kind
 * of message.
 *
 * @return YES if the transport would try (i.e. queue
 *         the message or call the OS to send),
 *         NO if the transport would just drop the message,
 *         SYSERR if the size/session is invalid
 */
static int
httpTestWouldTry (TSession * tsession, const unsigned int size, int important)
{
  HTTPSession *httpSession = tsession->internal;
  struct MHDGetData *get;
  int ret;

  if (size >= MAX_BUFFER_SIZE - sizeof (MESSAGE_HEADER))
    {
      GE_BREAK (coreAPI->ectx, 0);
      return SYSERR;
    }
  if (size == 0)
    {
      GE_BREAK (coreAPI->ectx, 0);
      return SYSERR;
    }
  if (httpSession->is_client)
    {
      /* client */
      if ((important != YES) && (httpSession->cs.client.puts != NULL))
        return NO;
      return YES;
    }
  else
    {
      /* server */
      MUTEX_LOCK (httpSession->lock);
      get = httpSession->cs.server.gets;
      if (get == NULL)
        ret = NO;
      else
        {
          if (get->wsize == 0)
            ret = YES;
          else if ((get->wpos + size > get->wsize) && (important != YES))
            ret = NO;
          else
            ret = YES;
        }
      MUTEX_UNLOCK (httpSession->lock);
      return ret;
    }
}


/**
 * Send a message to the specified remote node.
 *
 * @param tsession the P2P_hello_MESSAGE identifying the remote node
 * @param msg the message
 * @param size the size of the message
 * @return SYSERR on error, OK on success, NO if queue is full
 */
static int
httpSend (TSession * tsession,
          const void *msg, unsigned int size, int important)
{
  HTTPSession *httpSession = tsession->internal;
  struct HTTPPutData *putData;
  MESSAGE_HEADER *hdr;
#if DO_GET
  struct MHDGetData *getData;
  char *tmp;
#endif

  if (httpSession->is_client)
    {
      /* we need to do a PUT (we are the client) */
      if (size >= MAX_BUFFER_SIZE)
        return SYSERR;
      if (size == 0)
        {
          GE_BREAK (NULL, 0);
          return SYSERR;
        }
      if (important != YES)
        {
          MUTEX_LOCK (httpSession->lock);
          if (httpSession->cs.client.puts != NULL)
            {
              /* do not queue more than one unimportant PUT at a time */
              if (httpSession->cs.client.puts->done == YES)
                signal_select ();       /* do clean up now! */
              MUTEX_UNLOCK (httpSession->lock);
              if (stats != NULL)
                stats->change (stat_bytesDropped, size);

              return NO;
            }
          MUTEX_UNLOCK (httpSession->lock);
        }
      putData = MALLOC (sizeof (struct HTTPPutData));
      memset (putData, 0, sizeof (struct HTTPPutData));
      putData->msg = MALLOC (size + sizeof (MESSAGE_HEADER));
      hdr = (MESSAGE_HEADER *) putData->msg;
      hdr->size = htons (size + sizeof (MESSAGE_HEADER));
      hdr->type = htons (0);
      memcpy (&putData->msg[sizeof (MESSAGE_HEADER)], msg, size);
      putData->size = size + sizeof (MESSAGE_HEADER);
      putData->last_activity = get_time ();
      if (OK != create_curl_put (httpSession, putData))
        {
          FREE (putData->msg);
          FREE (putData);
          return SYSERR;
        }
      MUTEX_LOCK (httpSession->lock);
      putData->next = httpSession->cs.client.puts;
      httpSession->cs.client.puts = putData;
      MUTEX_UNLOCK (httpSession->lock);
      return OK;
    }

  /* httpSession->isClient == false, respond to a GET (we
     hopefully have one or will have one soon) */
#if DEBUG_HTTP
  GE_LOG (coreAPI->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "HTTP/MHD queues %u bytes to be sent as response to GET as soon as possible.\n",
          size);
#endif
#if DO_GET
  MUTEX_LOCK (httpSession->lock);
  getData = httpSession->cs.server.gets;
  if (getData == NULL)
    {
      MUTEX_UNLOCK (httpSession->lock);
      return SYSERR;
    }
  MUTEX_LOCK (getData->lock);
  if (getData->wsize == 0)
    GROW (getData->wbuff, getData->wsize, HTTP_BUF_SIZE);
  size += sizeof (MESSAGE_HEADER);
  if (getData->wpos + size > getData->wsize)
    {
      /* need to grow or discard */
      if (!important)
        {
          MUTEX_UNLOCK (getData->lock);
          MUTEX_UNLOCK (httpSession->lock);
          return NO;
        }
      tmp = MALLOC (getData->wpos + size);
      memcpy (tmp, &getData->wbuff[getData->woff], getData->wpos);
      hdr = (MESSAGE_HEADER *) & tmp[getData->wpos];
      hdr->type = htons (0);
      hdr->size = htons (size);
      memcpy (&hdr[1], msg, size - sizeof (MESSAGE_HEADER));
      FREE (getData->wbuff);
      getData->wbuff = tmp;
      getData->wsize = getData->wpos + size;
      getData->woff = 0;
      getData->wpos = getData->wpos + size;
    }
  else
    {
      /* fits without growing */
      if (getData->wpos + getData->woff + size > getData->wsize)
        {
          /* need to compact first */
          memmove (getData->wbuff,
                   &getData->wbuff[getData->woff], getData->wpos);
          getData->woff = 0;
        }
      /* append */
      hdr = (MESSAGE_HEADER *) & getData->
        wbuff[getData->woff + getData->wpos];
      hdr->size = htons (size);
      hdr->type = htons (0);
      memcpy (&hdr[1], msg, size - sizeof (MESSAGE_HEADER));
      getData->wpos += size;
    }
  MUTEX_UNLOCK (getData->lock);
  MUTEX_UNLOCK (httpSession->lock);
#endif
  return OK;
}

/**
 * Function called to cleanup dead connections
 * (completed PUTs, GETs that have timed out,
 * etc.).  Also re-vives GETs that have timed out
 * if we are still interested in the connection.
 */
static void
cleanup_connections ()
{
  int i;
  HTTPSession *s;
  struct HTTPPutData *prev;
  struct HTTPPutData *pos;
  struct MHDPutData *mpos;
  struct MHDPutData *mprev;
#if DO_GET
  struct MHD_Response *r;
  struct MHDGetData *gpos;
  struct MHDGetData *gnext;
#endif
  cron_t now;

  MUTEX_LOCK (httplock);
  now = get_time ();
  for (i = 0; i < tsessionCount; i++)
    {
      s = tsessions[i]->internal;
      MUTEX_LOCK (s->lock);
      if (s->is_client)
        {
          if ((s->cs.client.puts == NULL) && (s->users == 0)
#if DO_GET
              && (s->cs.client.last_get_activity + HTTP_TIMEOUT < now)
#endif
            )
            {
              MUTEX_UNLOCK (s->lock);
#if DO_GET
#if DEBUG_HTTP
              GE_LOG (coreAPI->ectx,
                      GE_DEBUG | GE_REQUEST | GE_USER,
                      "HTTP transport destroys old (%llu ms) unused client session\n",
                      now - s->cs.client.last_get_activity);
#endif
#endif
              destroy_tsession (tsessions[i]);
              i--;
              continue;
            }

          prev = NULL;
          pos = s->cs.client.puts;
          while (pos != NULL)
            {
              if (pos->last_activity + HTTP_TIMEOUT < now)
                pos->done = YES;
              if (pos->done)
                {
                  if (prev == NULL)
                    s->cs.client.puts = pos->next;
                  else
                    prev->next = pos->next;
                  FREE (pos->msg);
                  curl_multi_remove_handle (curl_multi, pos->curl_put);
                  signal_select ();
                  curl_easy_cleanup (pos->curl_put);
                  FREE (pos);
                  if (prev == NULL)
                    pos = s->cs.client.puts;
                  else
                    pos = prev->next;
                  continue;
                }
              prev = pos;
              pos = pos->next;
            }
#if DO_GET
          if ((s->cs.client.last_get_activity + HTTP_TIMEOUT < now) &&
              ((s->users > 0) || (s->cs.client.puts != NULL)))
            create_curl_get (s);
#endif
        }
      else
        {
          mpos = s->cs.server.puts;
          mprev = NULL;
          while (mpos != NULL)
            {
              if ((mpos->done == YES) ||
                  (mpos->last_activity + HTTP_TIMEOUT < now))
                {
                  if (mprev == NULL)
                    s->cs.server.puts = mpos->next;
                  else
                    mprev->next = mpos->next;
                  GROW (mpos->rbuff2, mpos->rsize2, 0);
                  FREE (mpos);
                  if (mprev == NULL)
                    mpos = s->cs.server.puts;
                  else
                    mpos = mprev->next;
                  continue;
                }
              mprev = mpos;
              mpos = mpos->next;
            }

          /* ! s->is_client */
#if DO_GET
          gpos = s->cs.server.gets;
          while (gpos != NULL)
            {
              gnext = gpos->next;
              gpos->next = NULL;
              if ((gpos->last_get_activity + HTTP_TIMEOUT < now) ||
                  (gpos != s->cs.server.gets))
                {
                  if (gpos == s->cs.server.gets)
                    s->cs.server.gets = NULL;
                  r = gpos->get;
                  gpos->get = NULL;
                  MHD_destroy_response (r);
                }
              gpos = gnext;
            }
#endif
          if (
#if DO_GET
               (s->cs.server.gets == NULL) &&	       
#endif
	       (s->is_mhd_active == 0) &&
               (s->users == 0))
            {
              MUTEX_UNLOCK (s->lock);
#if DO_GET
#if DEBUG_HTTP
              GE_LOG (coreAPI->ectx,
                      GE_DEBUG | GE_REQUEST | GE_USER,
                      "HTTP transport destroys unused server session\n");
#endif
#endif
              destroy_tsession (tsessions[i]);
              i--;
              continue;
            }
        }
      MUTEX_UNLOCK (s->lock);
    }
  MUTEX_UNLOCK (httplock);
}

/**
 * Thread that runs the CURL and MHD requests.
 */
static void *
curl_runner (void *unused)
{
  CURLMcode mret;
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  struct timeval tv;
  int running;
  unsigned long long timeout;
  long ms;
  int have_tv;
  char buf[128];                /* for reading from pipe */

#if DEBUG_HTTP
  GE_LOG (coreAPI->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "HTTP transport select thread started\n");
#endif
  while (YES == http_running)
    {
      max = 0;
      FD_ZERO (&rs);
      FD_ZERO (&ws);
      FD_ZERO (&es);
      mret = curl_multi_fdset (curl_multi, &rs, &ws, &es, &max);
      if (mret != CURLM_OK)
        {
          GE_LOG (coreAPI->ectx,
                  GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
                  _("%s failed at %s:%d: `%s'\n"),
                  "curl_multi_fdset",
                  __FILE__, __LINE__, curl_multi_strerror (mret));
          break;
        }
      if (mhd_daemon != NULL)
        MHD_get_fdset (mhd_daemon, &rs, &ws, &es, &max);
      timeout = 0;
      have_tv = MHD_NO;
      if (mhd_daemon != NULL)
        have_tv = MHD_get_timeout (mhd_daemon, &timeout);
      if ((CURLM_OK == curl_multi_timeout (curl_multi, &ms)) &&
          (ms != -1) && ((ms < timeout) || (have_tv == MHD_NO)))
        {
          timeout = ms;
          have_tv = MHD_YES;
        }
      FD_SET (signal_pipe[0], &rs);
      if (max < signal_pipe[0])
        max = signal_pipe[0];
      tv.tv_sec = timeout / 1000;
      tv.tv_usec = (timeout % 1000) * 1000;
      SELECT (max + 1, &rs, &ws, &es, (have_tv == MHD_YES) ? &tv : NULL);
      if (YES != http_running)
        break;
      running = 0;
      do
        {
          mret = curl_multi_perform (curl_multi, &running);
        }
      while ((mret == CURLM_CALL_MULTI_PERFORM) && (http_running == YES));
      if (FD_ISSET (signal_pipe[0], &rs))
        read (signal_pipe[0], buf, 1);
      if ((mret != CURLM_OK) && (mret != CURLM_CALL_MULTI_PERFORM))
        GE_LOG (coreAPI->ectx,
                GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
                _("%s failed at %s:%d: `%s'\n"),
                "curl_multi_perform",
                __FILE__, __LINE__, curl_multi_strerror (mret));
      if (mhd_daemon != NULL)
        MHD_run (mhd_daemon);
      cleanup_connections ();
    }
#if DEBUG_HTTP
  GE_LOG (coreAPI->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "HTTP transport select thread exits.\n");
#endif
  return NULL;
}


/**
 * Start the server process to receive inbound traffic.
 * @return OK on success, SYSERR if the operation failed
 */
static int
startTransportServer ()
{
  unsigned short port;

  if ((curl_multi != NULL) || (http_running == YES))
    return SYSERR;
  curl_multi = curl_multi_init ();
  if (curl_multi == NULL)
    return SYSERR;
  port = getGNUnetHTTPPort ();
  if ((mhd_daemon == NULL) && (port != 0))
    {
      mhd_daemon = MHD_start_daemon (MHD_NO_FLAG,
                                     port,
                                     &acceptPolicyCallback,
                                     NULL, &accessHandlerCallback, NULL,
                                     MHD_OPTION_CONNECTION_TIMEOUT,
                                     (unsigned int) HTTP_TIMEOUT,
                                     MHD_OPTION_CONNECTION_MEMORY_LIMIT,
                                     (unsigned int) 1024 * 128,
                                     MHD_OPTION_CONNECTION_LIMIT,
                                     (unsigned int) 128,
                                     MHD_OPTION_NOTIFY_COMPLETED,
                                     &requestCompletedCallback, NULL,
                                     MHD_OPTION_END);
    }
  if (0 != PIPE (signal_pipe))
    {
      MHD_stop_daemon (mhd_daemon);
      curl_multi_cleanup (curl_multi);
      curl_multi = NULL;
      mhd_daemon = NULL;
      return SYSERR;
    }
  network_make_pipe_nonblocking (coreAPI->ectx, signal_pipe[0]);
  http_running = YES;
  curl_thread = PTHREAD_CREATE (&curl_runner, NULL, 32 * 1024);
  if (curl_thread == NULL)
    GE_DIE_STRERROR (coreAPI->ectx,
                     GE_FATAL | GE_ADMIN | GE_IMMEDIATE, "pthread_create");
  return OK;
}

/**
 * Shutdown the server process (stop receiving inbound
 * traffic). May be restarted later!
 */
static int
stopTransportServer ()
{
  void *unused;
  int i;
  HTTPSession *s;

  if ((http_running == NO) || (curl_multi == NULL))
    return SYSERR;
  http_running = NO;
  signal_select ();
  PTHREAD_STOP_SLEEP (curl_thread);
  PTHREAD_JOIN (curl_thread, &unused);
  CLOSE (signal_pipe[0]);
  CLOSE (signal_pipe[1]);
  if (mhd_daemon != NULL)
    {
      MHD_stop_daemon (mhd_daemon);
      mhd_daemon = NULL;
    }
  for (i = 0; i < tsessionCount; i++)
    {
      s = tsessions[i]->internal;
      if (s->users == 0)
        {
          destroy_tsession (tsessions[i]);
          i--;
        }
    }
  curl_multi_cleanup (curl_multi);
  curl_multi = NULL;
  return OK;
}

/**
 * Reload the configuration. Should never fail (keep old
 * configuration on error, syslog errors!)
 */
static int
reloadConfiguration (void *ctx,
                     struct GC_Configuration *cfg,
                     struct GE_Context *ectx,
                     const char *section, const char *option)
{
  char *ch;

  if (0 != strcmp (section, "HTTP"))
    return 0;                   /* fast path */
  MUTEX_LOCK (httplock);
  FREENONNULL (filteredNetworks_);
  ch = NULL;
  GC_get_configuration_value_string (cfg, "HTTP", "BLACKLIST", "", &ch);
  filteredNetworks_ = parse_ipv4_network_specification (ectx, ch);
  FREE (ch);
  MUTEX_UNLOCK (httplock);
  return 0;
}

/**
 * Convert HTTP hello to IP address
 */
static int
helloToAddress (const P2P_hello_MESSAGE * hello,
                void **sa, unsigned int *sa_len)
{
  const HostAddress *haddr = (const HostAddress *) &hello[1];
  struct sockaddr_in *serverAddr;

  *sa_len = sizeof (struct sockaddr_in);
  serverAddr = MALLOC (sizeof (struct sockaddr_in));
  *sa = serverAddr;
  memset (serverAddr, 0, sizeof (struct sockaddr_in));
  serverAddr->sin_family = AF_INET;
  memcpy (&serverAddr->sin_addr, haddr, sizeof (IPaddr));
  serverAddr->sin_port = haddr->port;
  return OK;
}


/* ******************** public API ******************** */

/**
 * The exported method. Makes the core api available
 * via a global and returns the udp transport API.
 */
TransportAPI *
inittransport_http (CoreAPIForTransport * core)
{
  static TransportAPI httpAPI;

  coreAPI = core;
  httplock = MUTEX_CREATE (YES);
  if (0 != GC_attach_change_listener (coreAPI->cfg,
                                      &reloadConfiguration, NULL))
    {
      MUTEX_DESTROY (httplock);
      return NULL;
    }
  if (0 != curl_global_init (CURL_GLOBAL_WIN32))
    {
      GE_BREAK (NULL, 0);
      GC_detach_change_listener (coreAPI->cfg, &reloadConfiguration, NULL);
      MUTEX_DESTROY (httplock);
      return NULL;
    }
  tsessionCount = 0;
  tsessionArrayLength = 0;
  GROW (tsessions, tsessionArrayLength, 32);
  if (GC_get_configuration_value_yesno (coreAPI->cfg,
                                        "HTTP", "UPNP", YES) == YES)
    {
      upnp = coreAPI->requestService ("upnp");

      if (upnp == NULL)
        {
          GE_LOG (coreAPI->ectx,
                  GE_ERROR | GE_USER | GE_IMMEDIATE,
                  _
                  ("The UPnP service could not be loaded. To disable UPnP, set the "
                   "configuration option \"UPNP\" in section \"HTTP\" to \"NO\"\n"));
        }
    }

  stats = coreAPI->requestService ("stats");
  if (stats != NULL)
    {
      stat_bytesReceived
        = stats->create (gettext_noop ("# bytes received via HTTP"));
      stat_bytesSent = stats->create (gettext_noop ("# bytes sent via HTTP"));
      stat_bytesDropped
        = stats->create (gettext_noop ("# bytes dropped by HTTP (outgoing)"));
    }
  GC_get_configuration_value_string (coreAPI->cfg,
                                     "GNUNETD", "HTTP-PROXY", "", &proxy);

  httpAPI.protocolNumber = HTTP_PROTOCOL_NUMBER;
  httpAPI.mtu = 0;
  httpAPI.cost = 20000;         /* about equal to udp */
  httpAPI.verifyHello = &verifyHello;
  httpAPI.createhello = &createhello;
  httpAPI.connect = &httpConnect;
  httpAPI.associate = &httpAssociate;
  httpAPI.send = &httpSend;
  httpAPI.disconnect = &httpDisconnect;
  httpAPI.startTransportServer = &startTransportServer;
  httpAPI.stopTransportServer = &stopTransportServer;
  httpAPI.helloToAddress = &helloToAddress;
  httpAPI.testWouldTry = &httpTestWouldTry;

  return &httpAPI;
}

void
donetransport_http ()
{
  GC_detach_change_listener (coreAPI->cfg, &reloadConfiguration, NULL);
  if (stats != NULL)
    {
      coreAPI->releaseService (stats);
      stats = NULL;
    }
  if (upnp != NULL)
    {
      coreAPI->releaseService (upnp);
      stats = NULL;
    }
  FREENONNULL (filteredNetworks_);
  MUTEX_DESTROY (httplock);
  curl_global_cleanup ();
  FREENONNULL (proxy);
  proxy = NULL;
  GROW (tsessions, tsessionArrayLength, 0);
}

/* end of http.c */
