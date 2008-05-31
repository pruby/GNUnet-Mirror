/*
     This file is part of GNUnet
     (C) 2001, 2002, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/transport/transport.c
 * @brief Methods to access the transport layer.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_core.h"
#include "gnunet_identity_service.h"
#include "gnunet_transport_service.h"


#define DEBUG_TRANSPORT GNUNET_NO

static GNUNET_CoreAPIForTransport ctapi;

static GNUNET_CoreAPIForPlugins *coreAPI;

static GNUNET_Identity_ServiceAPI *identity;

/**
 * Note that this array MUST not be modified
 * (in size/NULLs) after gnunetd has started
 * to go multi-threaded!
 */
static GNUNET_TransportAPI **tapis = NULL;

static unsigned int tapis_count = 0;

static unsigned long long hello_live;

static struct GNUNET_Mutex *tapis_lock;

static struct GNUNET_Mutex *lock;

static struct GNUNET_GE_Context *ectx;

#define HELLO_RECREATE_FREQ (5 * GNUNET_CRON_MINUTES)

#define CHECK_IT GNUNET_NO
#if CHECK_IT
#include "check.c"
#else
#define CHECK(s) do {} while(0)
#endif


/**
 * Close the session with the remote node.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
assertAssociated (GNUNET_TSession * tsession, const char *token)
{
  int i;

  if (tsession == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  GNUNET_mutex_lock (lock);
  for (i = 0; i < tsession->token_count; i++)
    {
      if (0 == strcmp (tsession->tokens[i], token))
        {
          i = -1;
          break;
        }
    }
  if (i != -1)
    {
      GNUNET_GE_BREAK (NULL, 0);
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

/**
 * Create signed hello for this transport and put it into
 * the cache tapi->hello.
 */
static void
createSignedhello (void *cls)
{
  GNUNET_TransportAPI *tapi = cls;
  GNUNET_mutex_lock (tapis_lock);
  GNUNET_free_non_null (tapi->hello);
  tapi->hello = tapi->hello_create ();
  if (NULL == tapi->hello)
    {
      GNUNET_mutex_unlock (tapis_lock);
      return;
    }
  memcpy (&tapi->hello->publicKey,
          identity->getPublicPrivateKey (), sizeof (GNUNET_RSA_PublicKey));
  memcpy (&tapi->hello->senderIdentity,
          coreAPI->my_identity, sizeof (GNUNET_PeerIdentity));
  tapi->hello->expiration_time =
    htonl (GNUNET_get_time_int32 (NULL) + hello_live);
  tapi->hello->header.type = htons (GNUNET_P2P_PROTO_HELLO);
  tapi->hello->header.size = htons (GNUNET_sizeof_hello (tapi->hello));
  if (GNUNET_SYSERR == identity->signData (&(tapi->hello)->senderIdentity,
                                           GNUNET_sizeof_hello (tapi->hello) -
                                           sizeof (GNUNET_RSA_Signature) -
                                           sizeof (GNUNET_RSA_PublicKey) -
                                           sizeof (GNUNET_MessageHeader),
                                           &tapi->hello->signature))
    {
      GNUNET_free (tapi->hello);
      tapi->hello = NULL;
      GNUNET_GE_BREAK (ectx, 0);
    }
  GNUNET_mutex_unlock (tapis_lock);
}

/**
 * Is this transport mechanism available (for sending)?
 * @return GNUNET_YES or GNUNET_NO
 */
static int
isTransportAvailable (unsigned short ttype)
{
  if (ttype >= tapis_count)
    return GNUNET_NO;
  if (NULL == tapis[ttype])
    return GNUNET_NO;
  return GNUNET_YES;
}

/**
 * Add an implementation of a transport protocol.
 */
static int
addTransport (GNUNET_TransportAPI * tapi)
{
  if (tapi->protocol_number >= tapis_count)
    GNUNET_array_grow (tapis, tapis_count, tapi->protocol_number + 1);
  if (tapis[tapi->protocol_number] != NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  tapis[tapi->protocol_number] = tapi;
  tapi->hello = NULL;
  GNUNET_cron_add_job (coreAPI->cron,
                       &createSignedhello,
                       HELLO_RECREATE_FREQ, HELLO_RECREATE_FREQ, tapi);
  return GNUNET_OK;
}

/**
 * Convert hello to string.
 */
static int
helloToAddress (const GNUNET_MessageHello * hello,
                void **sa, unsigned int *sa_len)
{
  unsigned short prot;

  prot = ntohs (hello->protocol);
  if ((prot >= tapis_count) || (tapis[prot] == NULL))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     _
                     ("Converting peer address to string failed, transport type %d not supported\n"),
                     ntohs (hello->protocol));
      return GNUNET_SYSERR;
    }
  return tapis[prot]->hello_to_address (hello, sa, sa_len);
}

/**
 * Iterate over all available transport mechanisms.
 * @param callback the method to call on each transport API implementation
 * @param data second argument to callback
 */
static int
forEachTransport (GNUNET_TransportCallback callback, void *data)
{
  int i;
  int ret;

  ret = 0;
  for (i = 0; i < tapis_count; i++)
    {
      if (tapis[i] != NULL)
        {
          ret++;
          if (callback != NULL)
            callback (tapis[i], data);
        }
    }
  return ret;
}

/**
 * Connect to a remote host using the advertised
 * transport layer. This may fail if the appropriate
 * transport mechanism is not available.
 *
 * @param hello the hello of the target node
 * @param may_reuse can an existing connection be
 *        re-used?
 * @return session on success, NULL on error
 */
static GNUNET_TSession *
transportConnect (const GNUNET_MessageHello * hello,
                  const char *token, int may_reuse)
{
  unsigned short prot;
  GNUNET_TSession *tsession;

  prot = ntohs (hello->protocol);
  if ((prot >= tapis_count) || (tapis[prot] == NULL))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER |
                     GNUNET_GE_ADMIN,
                     _
                     ("Transport connection attempt failed, transport type %d not supported\n"),
                     prot);
      return NULL;
    }
  tsession = NULL;
  if (GNUNET_OK != tapis[prot]->connect (hello, &tsession, may_reuse))
    return NULL;
  tsession->ttype = prot;
  GNUNET_mutex_lock (lock);
  GNUNET_array_append (tsession->tokens, tsession->token_count, token);
  CHECK (tsession);
  GNUNET_mutex_unlock (lock);
  GNUNET_GE_BREAK (NULL, GNUNET_OK == assertAssociated (tsession, token));
  return tsession;
}

static GNUNET_TSession *
transportConnectFreely (const GNUNET_PeerIdentity * peer, int useTempList,
                        const char *token)
{
  int i;
  GNUNET_MessageHello *hello;
  unsigned int *perm;
  GNUNET_TSession *ret;
  unsigned int hc;
#if DEBUG_TRANSPORT
  GNUNET_EncName enc;
#endif

  hc = 0;
  ret = NULL;
  perm = GNUNET_permute (GNUNET_RANDOM_QUALITY_WEAK, tapis_count);
  for (i = 0; i < tapis_count; i++)
    {
      if (tapis[perm[i]] == NULL)
        continue;
      hello = identity->identity2Hello (peer, perm[i], useTempList);
      if (hello == NULL)
        continue;
      hc++;
      ret = transportConnect (hello, token, GNUNET_YES);
      GNUNET_free (hello);
      if (ret != NULL)
        break;
    }
  GNUNET_free (perm);
  if (ret == NULL)
    {
#if DEBUG_TRANSPORT
      GNUNET_hash_to_enc (&peer->hashPubKey, &enc);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_ADMIN,
                     _
                     ("Transport failed to connect to peer `%s' (%u HELLOs known, none worked)\n"),
                     &enc, hc);
#endif
    }
  return ret;
}

/**
 * A (core) Session is to be associated with a transport session. The
 * transport service may want to know in order to call back on the
 * core if the connection is being closed.
 *
 * @param tsession the session handle passed along
 *   from the call to receive that was made by the transport
 *   layer
 * @return GNUNET_OK if the session could be associated,
 *         GNUNET_SYSERR if not.
 */
static int
transportAssociate (GNUNET_TSession * tsession, const char *token)
{
  int ret;

  if ((tsession == NULL) ||
      (tsession->ttype >= tapis_count) || (tapis[tsession->ttype] == NULL))
    return GNUNET_SYSERR;
  ret = tapis[tsession->ttype]->associate (tsession);
  GNUNET_mutex_lock (lock);
  if (ret == GNUNET_OK)
    GNUNET_array_append (tsession->tokens, tsession->token_count, token);
  CHECK (tsession);
  GNUNET_mutex_unlock (lock);
  if (ret == GNUNET_OK)
    GNUNET_GE_BREAK (NULL, GNUNET_OK == assertAssociated (tsession, token));
  return ret;
}

/**
 * Get the cost of a message in for the given transport mechanism.
 */
static unsigned int
transportGetCost (int ttype)
{
  if ((ttype >= tapis_count) || (tapis[ttype] == NULL))
    return GNUNET_SYSERR;       /* -1 = INFTY */
  return tapis[ttype]->cost;
}

/**
 * Send a message.
 * @param tsession the transport session identifying the connection
 * @param msg the message to send
 * @param size the size of the message
 * @param important
 * @return GNUNET_OK on success, GNUNET_SYSERR on persistent error, GNUNET_NO on
 *         temporary error
 */
static int
transportSend (GNUNET_TSession * tsession,
               const void *msg, unsigned int size, int important)
{
  if (tsession == NULL)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                     "Transmission attempted on uni-directional pipe, failing.\n");
      return GNUNET_SYSERR;     /* can't do that, can happen for unidirectional pipes
                                   that call core with GNUNET_TSession being NULL. */
    }
  GNUNET_mutex_lock (lock);
  CHECK (tsession);
  GNUNET_mutex_unlock (lock);
  if ((tsession->ttype >= tapis_count) || (tapis[tsession->ttype] == NULL))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("Transmission attempt failed, transport type %d unknown.\n"),
                     tsession->ttype);
      return GNUNET_SYSERR;
    }
  return tapis[tsession->ttype]->send (tsession, msg, size, important);
}

/**
 * Close the session with the remote node.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
transportDisconnect (GNUNET_TSession * tsession, const char *token)
{
  int i;

  if (tsession == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  if ((tsession->ttype >= tapis_count) || (tapis[tsession->ttype] == NULL))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  GNUNET_mutex_lock (lock);
  CHECK (tsession);
  for (i = 0; i < tsession->token_count; i++)
    {
      if (0 == strcmp (tsession->tokens[i], token))
        {
          tsession->tokens[i] = tsession->tokens[tsession->token_count - 1];
          GNUNET_array_grow (tsession->tokens,
                             tsession->token_count,
                             tsession->token_count - 1);
          i = -1;
          break;
        }
    }
  if (i != -1)
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_DEVELOPER | GNUNET_GE_USER |
                     GNUNET_GE_IMMEDIATE,
                     "Illegal call to `%s', do not have token `%s'\n",
                     __FUNCTION__, token);
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  GNUNET_mutex_unlock (lock);
  i = tapis[tsession->ttype]->disconnect (tsession);
  GNUNET_GE_BREAK (NULL, i == GNUNET_OK);       /* should never fail */
  return i;
}

/**
 * Verify that a hello is ok. Call a method
 * if the verification was successful.
 * @return GNUNET_OK if the attempt to verify is on the way,
 *        GNUNET_SYSERR if the transport mechanism is not supported
 */
static int
transportVerifyHello (const GNUNET_MessageHello * hello)
{
  unsigned short prot;

  if ((ntohs (hello->header.size) != GNUNET_sizeof_hello (hello)) ||
      (ntohs (hello->header.type) != GNUNET_P2P_PROTO_HELLO))
    return GNUNET_SYSERR;       /* invalid */
  prot = ntohs (hello->protocol);
  if ((prot >= tapis_count) || (tapis[prot] == NULL))
    return GNUNET_SYSERR;       /* not supported */
  return tapis[prot]->hello_verify (hello);
}

/**
 * Get the MTU for a given transport type.
 */
static int
transportGetMTU (unsigned short ttype)
{
  if ((ttype >= tapis_count) || (tapis[ttype] == NULL))
    return GNUNET_SYSERR;
  return tapis[ttype]->mtu;
}

/**
 * Create a hello advertisement for the given
 * transport type for this node.
 */
static GNUNET_MessageHello *
transportCreatehello (unsigned short ttype)
{
  GNUNET_TransportAPI *tapi;
  GNUNET_MessageHello *hello;

  GNUNET_mutex_lock (tapis_lock);
  if (ttype == GNUNET_TRANSPORT_PROTOCOL_NUMBER_ANY)
    {
      unsigned int *perm;

      perm = GNUNET_permute (GNUNET_RANDOM_QUALITY_WEAK, tapis_count);
      ttype = tapis_count - 1;
      while ((ttype < tapis_count) &&
             ((tapis[perm[ttype]] == NULL) ||
              (tapis[perm[ttype]]->hello == NULL)))
        ttype--;                /* unsigned, will wrap around! */
      if (ttype >= tapis_count)
        {
          GNUNET_free (perm);
          GNUNET_mutex_unlock (tapis_lock);
          return NULL;
        }
      ttype = perm[ttype];
      GNUNET_free (perm);
    }
  else
    {
      if ((ttype >= tapis_count) || (tapis[ttype] == NULL))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("No transport of type %d known.\n"), ttype);
          GNUNET_mutex_unlock (tapis_lock);
          return NULL;
        }
    }
  tapi = tapis[ttype];
  if (tapi->hello == NULL)
    {
      GNUNET_mutex_unlock (tapis_lock);
      return NULL;              /* send-only transport */
    }
  hello = GNUNET_malloc (GNUNET_sizeof_hello (tapi->hello));
  memcpy (hello, tapi->hello, GNUNET_sizeof_hello (tapi->hello));
  GNUNET_mutex_unlock (tapis_lock);
  return hello;
}

/**
 * Get a message consisting of (if possible) all addresses that this
 * node is currently advertising.  This method is used to send out
 * possible ways to contact this node when sending a (plaintext) PING
 * during node discovery. Note that if we have many transport
 * implementations, it may not be possible to advertise all of our
 * addresses in one message, thus the caller can bound the size of the
 * advertisements.
 *
 * @param maxLen the maximum size of the hello message collection in bytes
 * @param buff where to write the hello messages
 * @return the number of bytes written to buff, -1 on error
 */
static int
getAdvertisedhellos (unsigned int maxLen, char *buff)
{
  int i;
  int tcount;
  GNUNET_MessageHello **hellos;
  int used;

  GNUNET_mutex_lock (tapis_lock);
  tcount = 0;
  for (i = 0; i < tapis_count; i++)
    if (tapis[i] != NULL)
      tcount++;

  hellos = GNUNET_malloc (tcount * sizeof (GNUNET_MessageHello *));
  tcount = 0;
  for (i = 0; i < tapis_count; i++)
    {
      if (tapis[i] != NULL)
        {
          hellos[tcount] = transportCreatehello (i);
          if (NULL != hellos[tcount])
            tcount++;
        }
    }
  GNUNET_mutex_unlock (tapis_lock);
  if (tcount == 0)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                     _("No transport succeeded in creating a hello!\n"));
      GNUNET_free (hellos);
      return GNUNET_SYSERR;
    }
  used = 0;
  while (tcount > 0)
    {
      i = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, tcount);       /* select a hello at random */
      if ((unsigned int) GNUNET_sizeof_hello (hellos[i]) <= maxLen - used)
        {
          memcpy (&buff[used], hellos[i], GNUNET_sizeof_hello (hellos[i]));
          used += GNUNET_sizeof_hello (hellos[i]);
        }
      GNUNET_free (hellos[i]);
      hellos[i] = hellos[--tcount];
    }
  for (i = 0; i < tcount; i++)
    GNUNET_free (hellos[i]);
  GNUNET_free (hellos);
  if (used == 0)
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_REQUEST,
                   "No HELLOs fit in %u bytes.\n", maxLen);
  return used;
}

static void
initHello (void *cls)
{
  GNUNET_TransportAPI *tapi = cls;
  GNUNET_MessageHello *hello;

  createSignedhello (tapi);
  hello = transportCreatehello (tapi->protocol_number);
  if (NULL != hello)
    {
      identity->addHost (hello);
      GNUNET_free (hello);
    }
}


static void
doneHelper (GNUNET_TransportAPI * tapi, void *unused)
{
  /* In the (rare) case that we shutdown transports
     before the cron-jobs had a chance to run, stop
     the cron-jobs */
  GNUNET_cron_del_job (coreAPI->cron, &initHello, 0, tapi);
}

static void
unloadTransport (int i)
{
  void (*ptr) ();

  doneHelper (tapis[i], NULL);
  GNUNET_cron_del_job (coreAPI->cron,
                       &createSignedhello, HELLO_RECREATE_FREQ, tapis[i]);
  ptr = GNUNET_plugin_resolve_function (tapis[i]->library_handle,
                                        "donetransport_", GNUNET_NO);
  if (ptr != NULL)
    ptr ();
  GNUNET_free (tapis[i]->transport_name);
  GNUNET_free_non_null (tapis[i]->hello);
  tapis[i]->hello = NULL;
  GNUNET_plugin_unload (tapis[i]->library_handle);
  tapis[i] = NULL;
}


/**
 * Actually start the transport services and begin
 * receiving messages.
 */
static void
startTransports (GNUNET_TransportPacketProcessor mpp)
{
  int i;

  ctapi.receive = mpp;
  for (i = 0; i < tapis_count; i++)
    if (tapis[i] != NULL)
      {
        if (GNUNET_OK != tapis[i]->server_start ())
          unloadTransport (i);
      }
}

/**
 * Stop the transport services, stop receiving messages.
 */
static void
stopTransports ()
{
  int i;

  for (i = 0; i < tapis_count; i++)
    if (tapis[i] != NULL)
      tapis[i]->server_stop ();
  ctapi.receive = NULL;
}

static void
initHelper (GNUNET_TransportAPI * tapi, void *unused)
{
  /* Creation of HELLOs takes longer if a locally
     unresolvable hostname ((Dyn)DNS) was specified
     as this host's address and we have no network
     connection at the moment.  Use of gethostbyname()
     blocks the startup process in this case.
     This is why we create the HELLOs in another
     thread. */
  GNUNET_cron_add_job (coreAPI->cron, &initHello, 0, 0, tapi);
}

/**
 * Test if the transport would even try to send
 * a message of the given size and importance
 * for the given session.<br>
 * This function is used to check if the core should
 * even bother to construct (and encrypt) this kind
 * of message.
 *
 * @return GNUNET_YES if the transport would try (i.e. queue
 *         the message or call the OS to send),
 *         GNUNET_NO if the transport would just drop the message,
 *         GNUNET_SYSERR if the size/session is invalid
 */
static int
testWouldTry (GNUNET_TSession * tsession, unsigned int size, int important)
{
  if (tsession == NULL)
    return GNUNET_SYSERR;
  if ((tsession->ttype >= tapis_count) || (tapis[tsession->ttype] == NULL))
    return GNUNET_SYSERR;
  return tapis[tsession->ttype]->send_now_test (tsession, size, important);
}

/**
 * Initialize the transport layer.
 */
GNUNET_Transport_ServiceAPI *
provide_module_transport (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_Transport_ServiceAPI ret;
  GNUNET_TransportAPI *tapi;
  GNUNET_TransportMainMethod tptr;
  char *dso;
  char *next;
  char *pos;
  struct GNUNET_PluginHandle *lib;
  GNUNET_EncName myself;

  ectx = capi->ectx;
  if (-1 == GNUNET_GC_get_configuration_value_number (capi->cfg,
                                                      "GNUNETD",
                                                      "HELLOEXPIRES",
                                                      1,
                                                      GNUNET_MAX_HELLO_EXPIRES
                                                      / 60, 60, &hello_live))
    return NULL;
  hello_live *= 60;

  GNUNET_GE_ASSERT (ectx, sizeof (GNUNET_MessageHello) == 600);
  identity = capi->service_request ("identity");
  if (identity == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return NULL;
    }
  coreAPI = capi;
  ctapi.version = 1;
  ctapi.my_identity = coreAPI->my_identity;
  ctapi.ectx = coreAPI->ectx;
  ctapi.cfg = coreAPI->cfg;
  ctapi.load_monitor = coreAPI->load_monitor;
  ctapi.cron = coreAPI->cron;
  ctapi.receive = NULL;         /* initialized LATER! */
  ctapi.service_request = coreAPI->service_request;
  ctapi.service_release = coreAPI->service_release;
  ctapi.tsession_assert_unused = coreAPI->tsession_assert_unused;

  GNUNET_array_grow (tapis, tapis_count,
                     GNUNET_TRANSPORT_PROTOCOL_NUMBER_UDP + 1);

  tapis_lock = GNUNET_mutex_create (GNUNET_YES);
  lock = GNUNET_mutex_create (GNUNET_NO);

  /* now load transports */
  dso = NULL;
  GNUNET_GE_ASSERT (ectx,
                    -1 != GNUNET_GC_get_configuration_value_string (capi->cfg,
                                                                    "GNUNETD",
                                                                    "TRANSPORTS",
                                                                    "udp tcp nat",
                                                                    &dso));
  if (strlen (dso) != 0)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_BULK,
                     _("Loading transports `%s'\n"), dso);
      next = dso;
      do
        {
          pos = next;
          while ((*next != '\0') && (*next != ' '))
            next++;
          if (*next == '\0')
            next = NULL;        /* terminate! */
          else
            {
              *next = '\0';     /* add 0-termination for pos */
              next++;
            }
          lib = GNUNET_plugin_load (ectx, "libgnunettransport_", pos);
          if (lib == NULL)
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_ERROR | GNUNET_GE_USER |
                             GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE,
                             _("Could not load transport plugin `%s'\n"),
                             pos);
              continue;
            }
          tptr =
            GNUNET_plugin_resolve_function (lib, "inittransport_",
                                            GNUNET_YES);
          if (tptr == NULL)
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                             GNUNET_GE_USER | GNUNET_GE_DEVELOPER |
                             GNUNET_GE_IMMEDIATE,
                             _
                             ("Transport library `%s' did not provide required function '%s%s'.\n"),
                             pos, "inittransport_", pos);
              GNUNET_plugin_unload (lib);
              continue;
            }
          tapi = tptr (&ctapi);
          if (tapi == NULL)
            {
              GNUNET_plugin_unload (lib);
              continue;
            }
          tapi->library_handle = lib;
          tapi->transport_name = GNUNET_strdup (pos);
          if (GNUNET_OK != addTransport (tapi))
            {
              void (*ptr) ();

              GNUNET_free (tapi->transport_name);
              ptr =
                GNUNET_plugin_resolve_function (lib, "donetransport_",
                                                GNUNET_NO);
              if (ptr != NULL)
                ptr ();
              GNUNET_plugin_unload (lib);
            }
          else
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_BULK,
                             _("Loaded transport `%s'\n"), pos);
            }
        }
      while (next != NULL);
    }
  GNUNET_free (dso);

  IF_GELOG (ectx,
            GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&coreAPI->my_identity->hashPubKey, &myself));
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _("I am peer `%s'.\n"), &myself);
  forEachTransport (&initHelper, NULL);

  ret.start = &startTransports;
  ret.stop = &stopTransports;
  ret.test_available = &isTransportAvailable;
  ret.add = &addTransport;
  ret.iterate_available = &forEachTransport;
  ret.connect = &transportConnect;
  ret.connect_freely = &transportConnectFreely;
  ret.associate = &transportAssociate;
  ret.cost_get = &transportGetCost;
  ret.send = &transportSend;
  ret.disconnect = &transportDisconnect;
  ret.hello_verify = &transportVerifyHello;
  ret.hello_to_address = &helloToAddress;
  ret.mtu_get = &transportGetMTU;
  ret.hello_create = &transportCreatehello;
  ret.hello_advertisements_get = &getAdvertisedhellos;
  ret.send_now_test = &testWouldTry;
  ret.assert_associated = &assertAssociated;

  return &ret;
}


/**
 * Shutdown the transport layer.
 */
int
release_module_transport ()
{
  int i;

  forEachTransport (&doneHelper, NULL);
  for (i = 0; i < tapis_count; i++)
    if (tapis[i] != NULL)
      unloadTransport (i);
  GNUNET_mutex_destroy (tapis_lock);
  GNUNET_mutex_destroy (lock);
  tapis_lock = NULL;
  GNUNET_array_grow (tapis, tapis_count, 0);

  coreAPI->service_release (identity);
  identity = NULL;
  coreAPI = NULL;
  return GNUNET_OK;
}


/* end of transport.c */
