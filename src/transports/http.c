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
 *
 * TODO:
 * - connection timeout (shutdown inactive connections)
 * - proper connection shutdown (free resources)
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
 * after how much time of the core not being associated with a http
 * connection anymore do we close it?
 */
#define HTTP_TIMEOUT (30 * cronSECONDS)

/**
 * Default maximum size of the HTTP read and write buffer.
 */
#define HTTP_BUF_SIZE (64 * 1024)
 
/**
 * Host-Address in a HTTP network.
 */
typedef struct {
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
 * Transport Session handle.
 */
typedef struct {

  /**
   * mutex for synchronized access to struct
   */
  struct MUTEX * lock;

  /**
   * Read buffer for the header.
   */
  char rbuff1[sizeof(MESSAGE_HEADER)];

  /**
   * The read buffer (used only for the actual data).
   */
  char * rbuff2;

  /**
   * The write buffer.
   */
  char * wbuff;

  /**
   * Last time this connection was used
   */
  cron_t lastUse;

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

  /**
   * Has this session been destroyed?
   */
  int destroyed;

  /**
   * Are we client or server?
   */
  int is_client;

  /**
   * TSession for this session.
   */
  TSession * tsession;

  /**
   * Data maintained for the http client-server connection
   * (depends on if we are client or server).
   */
  union {

    struct {

      /**
       * GET session response handle
       */
      struct MHD_Response * get;
      
    } server;

    struct {

      /**
       * GET operation
       */
      CURL * get;

      /**
       * PUT operation
       */
      CURL * put;

      /**
       * URL of the get and put operations.
       */ 
      char * url;

    } client;

  } cs;

} HTTPSession;

/* *********** globals ************* */

/**
 * apis (our advertised API and the core api )
 */
static CoreAPIForTransport * coreAPI;

static Stats_ServiceAPI * stats;

static int stat_bytesReceived;

static int stat_bytesSent;

static int stat_bytesDropped;

static char * proxy;

/**
 * Daemon for listening for new connections.
 */
static struct MHD_Daemon * mhd_daemon;

/**
 * Curl multi for managing client operations.
 */
static CURLM * curl_multi;

static int http_running;

static struct PTHREAD * curl_thread;

/**
 * Array of currently active HTTP sessions.
 */
static TSession ** tsessions;

static unsigned int tsessionCount;

static unsigned int tsessionArrayLength;

/**
 * Blacklist configuration 
 */
static struct CIDRNetwork * filteredNetworks_;

/**
 * Universal plug & play (firewall hole punching)
 */
static UPnP_ServiceAPI * upnp;

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
static struct MUTEX * httplock;

/**
 * Check if we are allowed to connect to the given IP.
 */
static int acceptPolicyCallback(void * cls,
				const struct sockaddr * addr,
				socklen_t addr_len) {
  IPaddr ip;
  int ret;

  if (addr_len == sizeof(struct sockaddr_in)) {
    memcpy(&ip,
	   &((struct sockaddr_in*) addr)->sin_addr,
	   sizeof(IPaddr));
  } else if (addr_len == sizeof(IPaddr)) {
    memcpy(&ip,
	   addr,
	   addr_len);
  } else {
    return MHD_NO;
  }
  MUTEX_LOCK(httplock);
  ret = check_ipv4_listed(filteredNetworks_,
			  ip);
  MUTEX_UNLOCK(httplock);
  if (YES == ret)
    return MHD_NO;
  return MHD_YES;
}

/**
 * Disconnect from a remote node. May only be called
 * on sessions that were acquired by the caller first.
 * For the core, aquiration means to call associate or
 * connect. The number of disconnects must match the
 * number of calls to connect+associate.
 *
 * @param tsession the session that is closed
 * @return OK on success, SYSERR if the operation failed
 */
static int httpDisconnect(TSession * tsession) {
  HTTPSession * httpsession = tsession->internal;
  
  if (httpsession != NULL) {
    MUTEX_LOCK(httpsession->lock);
    httpsession->users--;
    if (httpsession->users > 0) {
      MUTEX_UNLOCK(httpsession->lock);
      return OK;
    }
    httpsession->destroyed = YES;
    MUTEX_UNLOCK(httpsession->lock);
    if (httpsession->is_client) {
      curl_multi_remove_handle(curl_multi,
			       httpsession->cs.client.get);
      curl_easy_cleanup(httpsession->cs.client.get);
      FREE(httpsession->cs.client.url);
    } else {
      MHD_destroy_response(httpsession->cs.server.get);
    }
    GROW(httpsession->rbuff2,
	 httpsession->rsize2,
	 0);
    GROW(httpsession->wbuff,
	 httpsession->wsize,
	 0);
    MUTEX_DESTROY(httpsession->lock);
    FREE(httpsession);
  }
  FREE(tsession);
  return OK;
}

/**
 * Get the GNUnet HTTP port from the configuration, or from
 * /etc/services if it is not specified in the config file.
 */
static unsigned short getGNUnetHTTPPort() {
  unsigned long long port;

  if (-1 == GC_get_configuration_value_number(coreAPI->cfg,
					      "HTTP",
					      "PORT",
					      0,
					      65535,
					      1080,
					      &port)) 
    port = 1080;
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
static int httpAssociate(TSession * tsession) {
  HTTPSession * httpSession;

  if (tsession == NULL) {
    GE_BREAK(NULL, 0);
    return SYSERR;
  }
  httpSession = (HTTPSession*) tsession->internal;
  MUTEX_LOCK(httpSession->lock);
  if (httpSession->destroyed == YES) {
    MUTEX_UNLOCK(httpSession->lock);
    return SYSERR;
  }
  httpSession->users++;
  MUTEX_UNLOCK(httpSession->lock);
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
static int verifyHelo(const P2P_hello_MESSAGE * helo) {
  const HostAddress * haddr;

  haddr = (const HostAddress*) &helo[1];
  if ( (ntohs(helo->senderAddressSize) != sizeof(HostAddress)) ||
       (ntohs(helo->header.size) != P2P_hello_MESSAGE_size(helo)) ||
       (ntohs(helo->header.type) != p2p_PROTO_hello) ||
       (ntohs(helo->protocol) != HTTP_PROTOCOL_NUMBER) ||
       (MHD_NO == acceptPolicyCallback(NULL,
				       (const struct sockaddr*) haddr,
				       sizeof(IPaddr))) )
    return SYSERR; /* obviously invalid */
  return OK;
}

/**
 * Create a hello-Message for the current node. The hello is
 * created without signature and without a timestamp. The
 * GNUnet core will sign the message and add an expiration time.
 *
 * @return hello on success, NULL on error
 */
static P2P_hello_MESSAGE * createhello() {
  P2P_hello_MESSAGE * msg;
  HostAddress * haddr;
  unsigned short port;

  port = getGNUnetHTTPPort();
  if (0 == port) {
    GE_LOG(NULL,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "HTTP port is 0, will only send using HTTP.\n");
    return NULL; /* HTTP transport is configured SEND-only! */
  }
  msg = (P2P_hello_MESSAGE *) MALLOC(sizeof(P2P_hello_MESSAGE) + sizeof(HostAddress));
  haddr = (HostAddress*) &msg[1];

  if (! ( ( (upnp != NULL) &&
	    (OK == upnp->get_ip(port,
				"TCP",
				&haddr->ip)) ) ||
	  (SYSERR != getPublicIPAddress(coreAPI->cfg,
					coreAPI->ectx,
					&haddr->ip)) ) ) {
    FREE(msg);
    GE_LOG(coreAPI->ectx,
	   GE_WARNING | GE_ADMIN | GE_USER | GE_BULK,
	   _("HTTP: Could not determine my public IP address.\n"));
    return NULL;  
  }
#if DEBUG_HTTP
  GE_LOG(coreAPI->ectx, 
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "HTTP uses IP address %u.%u.%u.%u.\n",
	 PRIP(ntohl(*(int*)&haddr->ip)));
#endif
  haddr->port = htons(port);
  haddr->reserved = htons(0);
  msg->senderAddressSize = htons(sizeof(HostAddress));
  msg->protocol = htons(HTTP_PROTOCOL_NUMBER);
  msg->MTU = htonl(0);
  return msg;
}

/**
 * Add a new session to the array watched by the select thread.  Grows
 * the array if needed.  If the caller wants to do anything useful
 * with the return value, it must have the lock on httplock before
 * calling.  It is ok to call this function without holding httplock if
 * the return value is ignored.
 */
static unsigned int addTSession(TSession * tsession) {
  unsigned int i;

  MUTEX_LOCK(httplock);
  if (tsessionCount == tsessionArrayLength)
    GROW(tsessions,
	 tsessionArrayLength,
	 tsessionArrayLength * 2);
  i = tsessionCount;
  tsessions[tsessionCount++] = tsession;
  MUTEX_UNLOCK(httplock);
  return i;
}

static int contentReaderCallback(void * cls,
				 size_t pos,
				 char * buf,
				 int max) {
  HTTPSession * session = cls;

  MUTEX_LOCK(session->lock);
  if (session->destroyed) {
    MUTEX_UNLOCK(session->lock);
    return -1;
  }
  if (session->wpos < max)
    max = session->wpos;
  memcpy(buf,
	 &session->wbuff[session->woff],
	 max);
  session->wpos -= max;
  session->woff += max;
  session->lastUse = get_time();
  if (session->wpos == 0) 
    session->woff  = 0;
  MUTEX_UNLOCK(session->lock);
  return max;
}

/**
 * Notification that libmicrohttpd no longer needs the
 * response object.
 */
static void contentReaderFreeCallback(void * cls) {
  HTTPSession * session = cls;

  session->destroyed = YES;
}

/**
 * Create a new session for an inbound connection on the given
 * socket. Adds the session to the array of sessions watched
 * by the select thread.
 */
static int accessHandlerCallback(void * cls,
				 struct MHD_Session * session,
				 const char * url,
				 const char * method) {
  TSession * tsession;
  struct MHD_Response * response;
  HTTPSession * httpSession;
  HashCode512 client;
  int i;

  if ( (strlen(url) < 2) ||
       (OK != enc2hash(&url[1],
		       &client)) )
    return MHD_NO;

  /* check if we already have a session for this */
  MUTEX_LOCK(httplock);
  for (i=0;i<tsessionCount;i++) {
    tsession = tsessions[i];
    httpSession = tsession->internal;
    if (0 == memcmp(&httpSession->sender,
		    &client,
		    sizeof(HashCode512)))
      break;
    tsession = NULL;
    httpSession = NULL;
  }
  if (tsession != NULL) {
    MUTEX_LOCK(httpSession->lock);
    httpSession->users++;
    MUTEX_UNLOCK(httpSession->lock);
  }
  MUTEX_UNLOCK(httplock);

  if (httpSession == NULL) {
    httpSession = MALLOC(sizeof(HTTPSession));
    httpSession->destroyed = NO;
    httpSession->rpos1 = 0;
    httpSession->rpos2 = 0;
    httpSession->rsize2 = 0;
    httpSession->rbuff2 = NULL;
    httpSession->wsize = 0;
    httpSession->woff = 0;
    httpSession->wpos = 0;
    httpSession->wbuff = NULL;
    httpSession->sender = *(coreAPI->myIdentity);
    httpSession->lock = MUTEX_CREATE(YES);
    httpSession->users = 1; /* us only, core has not seen this tsession! */
    httpSession->lastUse = get_time();
    httpSession->is_client = NO;
    httpSession->cs.client.get = NULL;
    httpSession->cs.client.put = NULL;
    tsession = MALLOC(sizeof(TSession));
    tsession->ttype = HTTP_PROTOCOL_NUMBER;
    tsession->internal = httpSession;
    httpSession->tsession = tsession;
    addTSession(tsession);
  }
  if (0 == strcmp("get", method)) {
    response = MHD_create_response_from_callback(-1,
						 contentReaderCallback,
						 httpSession,
						 contentReaderFreeCallback);
    httpSession->cs.client.get = response;
    MHD_queue_response(session,
		       MHD_HTTP_OK,
		       response);
  } else {
    /* FIXME: handle put! */
  }
  return MHD_YES;
}

/**
 * Process downloaded bits 
 */
static size_t
receiveContentCallback(void * ptr,
		       size_t size,
		       size_t nmemb,
		       void * ctx) {
  HTTPSession * httpSession = ctx;
  const char * inbuf = ptr;
  size_t have = size * nmemb;
  size_t poff = 0;
  size_t cpy;
  MESSAGE_HEADER * hdr;
  P2P_PACKET * mp;
  
  while (have > 0) {
    if (httpSession->rpos1 < sizeof(MESSAGE_HEADER)) {
      cpy = sizeof(MESSAGE_HEADER) - httpSession->rpos1;
      if (cpy > have)
	cpy = have;
      memcpy(&httpSession->rbuff1[httpSession->rpos1],
	     &inbuf[poff],
	     cpy);
      httpSession->rpos1 += cpy;
      have -= cpy;
      poff += cpy;
    }
    if (httpSession->rpos1 < sizeof(MESSAGE_HEADER))
      return size * nmemb;
    hdr = (MESSAGE_HEADER *) httpSession->rbuff1;
    GROW(httpSession->rbuff2,
	 httpSession->rsize2,
	 ntohs(hdr->size));
    if (httpSession->rpos2 < ntohs(hdr->size)) {
      cpy = ntohs(hdr->size) - httpSession->rpos2;
      if (cpy > have)
	cpy = have;
      memcpy(&httpSession->rbuff2[httpSession->rpos2],
	     &inbuf[poff],
	     cpy);
      have -= cpy;
      poff += cpy;
    }
    if (httpSession->rpos2 < ntohs(hdr->size)) 
      return size * nmemb;
    mp = MALLOC(sizeof(P2P_PACKET));
    mp->msg = httpSession->rbuff2;
    mp->sender = httpSession->sender;
    mp->tsession = httpSession->tsession;
    coreAPI->receive(mp);
    httpSession->rbuff2 = NULL;
    httpSession->rpos2 = 0;
    httpSession->rsize2 = 0;
    httpSession->rpos1 = 0;
  }
  return size * nmemb;
}

/**
 * Provide bits for upload
 */
static size_t
sendContentCallback(void * ptr,
		    size_t size,
		    size_t nmemb,
		    void * ctx) {
  HTTPSession * httpSession = ctx;

  /* FIXME: find data to send, if none left, add
     dummy response AND unqueue! */
  return 0;
}

#define CURL_EASY_SETOPT(c, a, b) do { ret = curl_easy_setopt(c, a, b); if (ret != CURLE_OK) GE_LOG(coreAPI->ectx, GE_WARNING | GE_USER | GE_BULK, _("%s failed at %s:%d: `%s'\n"), "curl_easy_setopt", __FILE__, __LINE__, curl_easy_strerror(ret)); } while (0);

/**
 * Establish a connection to a remote node.
 *
 * @param helo the hello-Message for the target node
 * @param tsessionPtr the session handle that is set
 * @return OK on success, SYSERR if the operation failed
 */
static int httpConnect(const P2P_hello_MESSAGE * helo,
		       TSession ** tsessionPtr) {
  const HostAddress * haddr = (const HostAddress*) &helo[1];
  TSession * tsession;
  HTTPSession * httpSession;
  CURL * curl_get;
  CURL * curl_put;
  CURLcode ret;
  CURLMcode mret;
  char * url;
  EncName enc;

  curl_get = curl_easy_init();
  if (curl_get == NULL)
    return SYSERR;
  curl_put = curl_easy_init();
  if (curl_put == NULL) {
    curl_easy_cleanup(curl_get);
    return SYSERR;
  }
  hash2enc(&helo->senderIdentity.hashPubKey,
	   &enc);
  url = MALLOC(64 + sizeof(EncName));
  SNPRINTF(url,
	   64 + sizeof(EncName),
	   "http://%u.%u.%u.%u/%s",
	   PRIP(ntohl(*(int*)&haddr->ip.addr)),
	   &enc);

  /* create GET */
  CURL_EASY_SETOPT(curl_get,
		   CURLOPT_FAILONERROR,
		   1);
  CURL_EASY_SETOPT(curl_get,
		   CURLOPT_URL,
		   url);
  if (strlen(proxy) > 0)
    CURL_EASY_SETOPT(curl_get,
		     CURLOPT_PROXY,
		     proxy);
  CURL_EASY_SETOPT(curl_get,
		   CURLOPT_BUFFERSIZE,
		   32 * 1024); 
  if (0 == strncmp(url,
		   "http", 
		   4))
    CURL_EASY_SETOPT(curl_get,
		     CURLOPT_USERAGENT,
		     "GNUnet-http");
  CURL_EASY_SETOPT(curl_get,
		   CURLOPT_CONNECTTIMEOUT,
		   150L);
  CURL_EASY_SETOPT(curl_get,
		   CURLOPT_WRITEFUNCTION,
		   &receiveContentCallback);

  httpSession = MALLOC(sizeof(HTTPSession));
  httpSession->cs.client.url = url;
  CURL_EASY_SETOPT(curl_get,
		   CURLOPT_WRITEDATA,
		   httpSession);
  if (ret != CURLE_OK) 
    goto cleanup;

  /* FIXME: should we queue here or wait until we have data!? */
  mret = curl_multi_add_handle(curl_multi, curl_get);
  if (mret != CURLM_OK) {
    GE_LOG(coreAPI->ectx,
	   GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
	   _("%s failed at %s:%d: `%s'\n"),
	   "curl_multi_add_handle",
	   __FILE__,
	   __LINE__,
	   curl_multi_strerror(mret));
    goto cleanup;
  }

  /* create PUT */
  CURL_EASY_SETOPT(curl_put,
		   CURLOPT_FAILONERROR,
		   1);
  CURL_EASY_SETOPT(curl_put,
		   CURLOPT_URL,
		   url);
  if (strlen(proxy) > 0)
    CURL_EASY_SETOPT(curl_put,
		     CURLOPT_PROXY,
		     proxy);
  CURL_EASY_SETOPT(curl_put,
		   CURLOPT_BUFFERSIZE,
		   32 * 1024);
  if (0 == strncmp(url,
		   "http", 
		   4))
    CURL_EASY_SETOPT(curl_put,
		     CURLOPT_USERAGENT,
		     "GNUnet-http");
  CURL_EASY_SETOPT(curl_put,
		   CURLOPT_UPLOAD,
		   1);
  CURL_EASY_SETOPT(curl_put,
		   CURLOPT_CONNECTTIMEOUT,
		   150L);
  CURL_EASY_SETOPT(curl_put,
		   CURLOPT_INFILESIZE_LARGE, 
		   0);
  CURL_EASY_SETOPT(curl_put,
		   CURLOPT_READFUNCTION,
		   &sendContentCallback);
  CURL_EASY_SETOPT(curl_put,
		   CURLOPT_READDATA,
		   httpSession);
  if (ret != CURLE_OK) 
    goto cleanup;
  mret = curl_multi_add_handle(curl_multi, curl_put);
  if (mret != CURLM_OK) {
    GE_LOG(coreAPI->ectx,
	   GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
	   _("%s failed at %s:%d: `%s'\n"),
	   "curl_multi_add_handle",
	   __FILE__,
	   __LINE__,
	   curl_multi_strerror(mret));
    goto cleanup;
  }

  /* create SESSION */
  httpSession->destroyed = NO;
  httpSession->rpos1 = 0;
  httpSession->rpos2 = 0;
  httpSession->rsize2 = 0;
  httpSession->rbuff2 = NULL;
  httpSession->wsize = 0;
  httpSession->woff = 0;
  httpSession->wpos = 0;
  httpSession->wbuff = NULL;
  httpSession->sender = helo->senderIdentity;
  httpSession->lock = MUTEX_CREATE(YES);
  httpSession->users = 1; /* us only, core has not seen this tsession! */
  httpSession->lastUse = get_time();
  httpSession->is_client = YES;
  httpSession->cs.client.get = curl_get;
  httpSession->cs.client.put = curl_put;
  tsession = MALLOC(sizeof(TSession));
  httpSession->tsession = tsession;
  tsession->ttype = HTTP_PROTOCOL_NUMBER;
  tsession->internal = httpSession;
  addTSession(tsession);
  *tsessionPtr = tsession;
  return OK;
 cleanup:
  curl_easy_cleanup(curl_get);
  curl_easy_cleanup(curl_put);
  FREE(url);
  FREE(proxy);
  FREE(httpSession);
  return SYSERR;
}

/**
 * Send a message to the specified remote node.
 *
 * @param tsession the P2P_hello_MESSAGE identifying the remote node
 * @param msg the message
 * @param size the size of the message
 * @return SYSERR on error, OK on success, NO if queue is full
 */
static int httpSend(TSession * tsession,
		    const void * msg,
		    const unsigned int size,
		    int important) {
  HTTPSession * httpSession = tsession->internal;

  if (size >= MAX_BUFFER_SIZE)
    return SYSERR;
  if (size == 0) {
    GE_BREAK(NULL, 0);
    return SYSERR;
  }
  /* FIXME: if first data to send, add PUT to multi set! */
  MUTEX_LOCK(httpSession->lock);
  if ( (httpSession->wsize > HTTP_BUF_SIZE) &&
       (important == NO) ) {
    if (stats != NULL)
      stats->change(stat_bytesDropped,
		    size);
    MUTEX_UNLOCK(httpSession->lock); 
    return NO;
  }
  if (httpSession->wsize >= httpSession->wpos + size) {
    if (httpSession->woff + size <= httpSession->wsize) {
      memcpy(&httpSession->wbuff[httpSession->woff],
	     msg,
	     size);
      httpSession->woff += size;
      httpSession->wpos += size;
    } else {
      memmove(httpSession->wbuff,
	      &httpSession->wbuff[httpSession->woff - httpSession->wpos],
	      httpSession->wpos);
      memcpy(&httpSession->wbuff[httpSession->wpos],
	     msg,
	     size);
      httpSession->woff = httpSession->wpos + size;
      httpSession->wpos += size;
    }
  } else {
    if ( (httpSession->wpos + size > HTTP_BUF_SIZE) &&
	 (important == NO) ) {
      if (stats != NULL)
	stats->change(stat_bytesDropped,
		      size);
      MUTEX_UNLOCK(httpSession->lock);
      return NO;
    }
    GROW(httpSession->wbuff,
	 httpSession->wsize,
	 httpSession->wpos + size);
    memmove(httpSession->wbuff,
	    &httpSession->wbuff[httpSession->woff - httpSession->wpos],
	    httpSession->wpos);
    memcpy(&httpSession->wbuff[httpSession->wpos],
	   msg,
	   size);
    httpSession->woff = httpSession->wpos + size;
    httpSession->wpos += size;
  }
  MUTEX_UNLOCK(httpSession->lock);
  return OK;
}

static void *
curl_runner(void * unused) {
  CURLM * multi;
  CURLMcode mret;
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  struct timeval tv;
  int running;

  while (YES == http_running) {
    max = 0;
    FD_ZERO(&rs);
    FD_ZERO(&ws);
    FD_ZERO(&es);
    mret = curl_multi_fdset(multi,
			    &rs,
			    &ws,
			    &es,
			    &max);
    if (mret != CURLM_OK) {
      GE_LOG(coreAPI->ectx,
	     GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
	     _("%s failed at %s:%d: `%s'\n"),
	     "curl_multi_fdset",
	     __FILE__,
	     __LINE__,
	     curl_multi_strerror(mret));
      break;
    }
    /* use timeout of 1s in case that SELECT is not interrupted by
       signal (just to increase portability a bit) -- better a 1s
       delay in the reaction than hanging... */
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    SELECT(max + 1,
	   &rs,
	   &ws,
	   &es,
	   &tv);
    if (YES != http_running)
      break;
    running = 0;
    curl_multi_perform(multi, &running);
  }  
  return NULL;
}

/**
 * Start the server process to receive inbound traffic.
 * @return OK on success, SYSERR if the operation failed
 */
static int startTransportServer() {
  unsigned short port;

  if ( (curl_multi != NULL) ||
       (http_running == YES) )
    return SYSERR;
  curl_multi = curl_multi_init();
  if (curl_multi == NULL) 
    return SYSERR;
  port = getGNUnetHTTPPort();
  if ( (mhd_daemon == NULL) &&
       (port != 0) ) {
    mhd_daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_IPv4,
				  port,
				  &acceptPolicyCallback,
				  NULL,
				  &accessHandlerCallback,
				  NULL);
  }
  http_running = YES;
  curl_thread = PTHREAD_CREATE(&curl_runner,
			       NULL,
			       32 * 1024);
  if (curl_thread == NULL)
    GE_DIE_STRERROR(coreAPI->ectx,
		    GE_FATAL | GE_ADMIN | GE_IMMEDIATE,
		    "pthread_create");
  return OK;
}

/**
 * Shutdown the server process (stop receiving inbound
 * traffic). May be restarted later!
 */
static int stopTransportServer() {
  void * unused;

  if ( (http_running == NO) ||
       (curl_multi == NULL) )
    return SYSERR;
  http_running = NO;
  PTHREAD_STOP_SLEEP(curl_thread);
  PTHREAD_JOIN(curl_thread, &unused);
  if (mhd_daemon != NULL) {
    MHD_stop_daemon(mhd_daemon);
    mhd_daemon = NULL;
  }
  curl_multi_cleanup(curl_multi);
  curl_multi = NULL;
  return OK;
}

/**
 * Reload the configuration. Should never fail (keep old
 * configuration on error, syslog errors!)
 */
static int reloadConfiguration(void * ctx,
			       struct GC_Configuration * cfg,
			       struct GE_Context * ectx,
			       const char * section,
			       const char * option) {
  char * ch;

  if (0 != strcmp(section, "HTTP"))
    return 0; /* fast path */
  MUTEX_LOCK(httplock);
  FREENONNULL(filteredNetworks_);
  ch = NULL;
  GC_get_configuration_value_string(cfg,
				    "HTTP",
				    "BLACKLIST",
				    "",
				    &ch);
  filteredNetworks_ = parse_ipv4_network_specification(ectx,
						       ch);
  FREE(ch);
  MUTEX_UNLOCK(httplock);
  return 0;
}

/**
 * Convert HTTP address to a string.
 */
static char * 
addressToString(const P2P_hello_MESSAGE * hello,
		int do_resolve) {
  char * ret;
  const HostAddress * haddr = (const HostAddress*) &hello[1];
  size_t n;
  const char * hn = "";
  struct hostent * ent;

#if HAVE_GETHOSTBYADDR
  if (do_resolve) {
    ent = gethostbyaddr(haddr,
			sizeof(IPaddr),
			AF_INET);
    if (ent != NULL)
      hn = ent->h_name;
  }    
#endif
  n = 4*4+7+6 + strlen(hn) + 10;
  ret = MALLOC(n);
  if (strlen(hn) > 0) {
    SNPRINTF(ret,
	     n,
	     "%s (%u.%u.%u.%u) HTTP (%u)",
	     hn,
	     PRIP(ntohl(*(int*)&haddr->ip.addr)),
	     ntohs(haddr->port));
  } else {
    SNPRINTF(ret,
	     n,
	     "%u.%u.%u.%u HTTP (%u)",
	     PRIP(ntohl(*(int*)&haddr->ip.addr)),
	     ntohs(haddr->port));
  }
  return ret;
}


/* ******************** public API ******************** */

/**
 * The exported method. Makes the core api available
 * via a global and returns the udp transport API.
 */
TransportAPI * 
inittransport_http(CoreAPIForTransport * core) {
  static TransportAPI httpAPI;

  coreAPI = core;
  httplock = MUTEX_CREATE(YES);
  if (0 != GC_attach_change_listener(coreAPI->cfg,
				     &reloadConfiguration,
				     NULL)) {
    MUTEX_DESTROY(httplock);
    return NULL;
  }
  if (0 != curl_global_init(CURL_GLOBAL_WIN32)) {
    GE_BREAK(NULL, 0);
    GC_detach_change_listener(coreAPI->cfg,
			      &reloadConfiguration,
			      NULL);
    MUTEX_DESTROY(httplock);
    return NULL;
  }
  tsessionCount = 0;
  tsessionArrayLength = 0;
  GROW(tsessions,
       tsessionArrayLength,
       32);
  if (GC_get_configuration_value_yesno(coreAPI->cfg,
				       "HTTP",
				       "UPNP",
				       YES) == YES) {
    upnp = coreAPI->requestService("upnp");
    
    if (upnp == NULL) {
      GE_LOG(coreAPI->ectx,
	     GE_ERROR | GE_USER | GE_IMMEDIATE,
	     _("The UPnP service could not be loaded. To disable UPnP, set the " \
	       "configuration option \"UPNP\" in section \"HTTP\" to \"NO\"\n"));	      
    }
  }

  stats = coreAPI->requestService("stats");
  if (stats != NULL) {
    stat_bytesReceived
      = stats->create(gettext_noop("# bytes received via HTTP"));
    stat_bytesSent
      = stats->create(gettext_noop("# bytes sent via HTTP"));
    stat_bytesDropped
      = stats->create(gettext_noop("# bytes dropped by HTTP (outgoing)"));
  }
  GC_get_configuration_value_string(coreAPI->cfg,
				    "GNUNETD",
				    "HTTP-PROXY",
				    "",
				    &proxy);

  httpAPI.protocolNumber       = HTTP_PROTOCOL_NUMBER;
  httpAPI.mtu                  = 0;
  httpAPI.cost                 = 20000; /* about equal to udp */
  httpAPI.verifyHelo           = &verifyHelo;
  httpAPI.createhello          = &createhello;
  httpAPI.connect              = &httpConnect;
  httpAPI.associate            = &httpAssociate;
  httpAPI.send                 = &httpSend;
  httpAPI.disconnect           = &httpDisconnect;
  httpAPI.startTransportServer = &startTransportServer;
  httpAPI.stopTransportServer  = &stopTransportServer;
  httpAPI.addressToString      = &addressToString;

  return &httpAPI;
}

void donetransport_http() {
  GC_detach_change_listener(coreAPI->cfg,
			    &reloadConfiguration,
			    NULL);
  coreAPI->releaseService(stats);
  stats = NULL;
  FREENONNULL(filteredNetworks_);
  MUTEX_DESTROY(httplock);
  curl_global_cleanup();
  FREENONNULL(proxy);
  proxy = NULL;
}

/* end of http.c */
