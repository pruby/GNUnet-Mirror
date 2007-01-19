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


#define DEBUG_TRANSPORT NO

static CoreAPIForTransport ctapi;

static CoreAPIForApplication * coreAPI;

static Identity_ServiceAPI * identity;

static TransportAPI ** tapis = NULL;

static unsigned int tapis_count = 0;

static unsigned long long helo_live;

static struct MUTEX * tapis_lock;

static struct GE_Context * ectx;

#define HELLO_RECREATE_FREQ (5 * cronMINUTES)



/**
 * Create signed hello for this transport and put it into
 * the cache tapi->helo.
 */
static void createSignedhello(void * cls) {
  TransportAPI * tapi = cls;
  MUTEX_LOCK(tapis_lock);
  FREENONNULL(tapi->hello);
  tapi->hello = tapi->createhello();
  if (NULL == tapi->hello) {
    MUTEX_UNLOCK(tapis_lock);
    return;
  }
  memcpy(&tapi->hello->publicKey,
	 identity->getPublicPrivateKey(),
	 sizeof(PublicKey));
  memcpy(&tapi->hello->senderIdentity,
	 coreAPI->myIdentity,
	 sizeof(PeerIdentity));
  tapi->hello->expirationTime
    = htonl(TIME(NULL) + helo_live);
  tapi->hello->header.type
    = htons(p2p_PROTO_hello);
  tapi->hello->header.size
    = htons(P2P_hello_MESSAGE_size(tapi->hello));
  if (SYSERR == identity->signData(&(tapi->hello)->senderIdentity,
				   P2P_hello_MESSAGE_size(tapi->hello)
				   - sizeof(Signature)
				   - sizeof(PublicKey)
				   - sizeof(MESSAGE_HEADER),
				   &tapi->hello->signature)) {
    FREE(tapi->hello);
    tapi->hello = NULL;
    GE_BREAK(ectx, 0);
  }
  MUTEX_UNLOCK(tapis_lock);
}

/**
 * Is this transport mechanism available (for sending)?
 * @return YES or NO
 */
static int isTransportAvailable(unsigned short ttype) {
  if (ttype >= tapis_count)
    return NO;
  if (NULL == tapis[ttype])
    return NO;
  return YES;
}

/**
 * Add an implementation of a transport protocol.
 */
static int addTransport(TransportAPI * tapi) {
  if (tapi->protocolNumber >= tapis_count)
    GROW(tapis,
	 tapis_count,
	 tapi->protocolNumber+1);
  if (tapis[tapi->protocolNumber] != NULL) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  tapis[tapi->protocolNumber] = tapi;
  tapi->hello = NULL;
  cron_add_job(coreAPI->cron,
	       &createSignedhello,
	       HELLO_RECREATE_FREQ,
	       HELLO_RECREATE_FREQ,
	       tapi);
  return OK;
}

/**
 * Convert hello to string.
 */
static char * 
helloToString(const P2P_hello_MESSAGE * hello,
	      int resolve_ip) {
  unsigned short prot;

  prot = ntohs(hello->protocol);
  if ( (ntohs(hello->protocol) >= tapis_count) ||
       (tapis[prot] == NULL) ) {
    GE_LOG(ectx,
	   GE_INFO | GE_REQUEST | GE_USER,
	   _("Converting peer address to string failed, transport type %d not supported\n"),
	   ntohs(hello->protocol));
    return NULL;
  }
  return tapis[prot]->addressToString(hello, resolve_ip);
}

/**
 * Iterate over all available transport mechanisms.
 * @param callback the method to call on each transport API implementation
 * @param data second argument to callback
 */
static int forEachTransport(TransportCallback callback,
			    void * data) {
  int i;
  int ret;

  ret = 0;
  for (i=0;i<tapis_count;i++) {
    if (tapis[i] != NULL) {
      ret++;
      if (callback != NULL)
	callback(tapis[i], data);
    }
  }
  return ret;
}

/**
 * Connect to a remote host using the advertised
 * transport layer. This may fail if the appropriate
 * transport mechanism is not available.
 *
 * @param helo the hello of the target node. The
 *        callee is responsible for freeing the hello (!), except
 *        if SYSERR is returned!
 * @return OK on success, SYSERR on error
 */
static TSession * transportConnect(const P2P_hello_MESSAGE * helo) {
  unsigned short prot;
  TSession * tsession;

  prot = ntohs(helo->protocol);
  if ( (ntohs(helo->protocol) >= tapis_count)  ||
       (tapis[prot] == NULL) ) {
    GE_LOG(ectx,
	   GE_INFO | GE_REQUEST | GE_USER | GE_ADMIN,
	   _("Transport connection attempt failed, transport type %d not supported\n"),
	   ntohs(helo->protocol));
    return NULL;
  }
  if (OK != tapis[prot]->connect(helo,
				 &tsession))
    return NULL;
  tsession->ttype = prot;
  return tsession;
}

static TSession * transportConnectFreely(const PeerIdentity * peer,
					 int useTempList) {
  int i;
  P2P_hello_MESSAGE * helo;
  int * perm;
  TSession * ret;

  MUTEX_LOCK(tapis_lock);
  ret = NULL;
  perm = permute(WEAK, tapis_count);
  for (i=0;i<tapis_count;i++) {
    if (tapis[perm[i]] == NULL)
      continue;
    helo = identity->identity2Helo(peer,
				   perm[i],
				   useTempList);
    if (helo != NULL) {
      ret = transportConnect(helo);
      FREE(helo);
      if (ret != NULL) {
	FREE(perm);
	MUTEX_UNLOCK(tapis_lock);
	return ret;
      }
    }
  }
  FREE(perm);
  MUTEX_UNLOCK(tapis_lock);
  return NULL;
}

/**
 * A (core) Session is to be associated with a transport session. The
 * transport service may want to know in order to call back on the
 * core if the connection is being closed.
 *
 * @param tsession the session handle passed along
 *   from the call to receive that was made by the transport
 *   layer
 * @return OK if the session could be associated,
 *         SYSERR if not.
 */
static int transportAssociate(TSession * tsession) {
  if ( (tsession == NULL) ||
       (tsession->ttype >= tapis_count) ||
       (tapis[tsession->ttype] == NULL) )
    return SYSERR;
  return tapis[tsession->ttype]->associate(tsession);
}

/**
 * Get the cost of a message in for the given transport mechanism.
 */
static unsigned int transportGetCost(int ttype) {
  if ( (ttype >= tapis_count) ||
       (tapis[ttype] == NULL) )
    return SYSERR; /* -1 = INFTY */
  return tapis[ttype]->cost;
}

/**
 * Send a message.
 * @param tsession the transport session identifying the connection
 * @param msg the message to send
 * @param size the size of the message
 * @param important
 * @return OK on success, SYSERR on persistent error, NO on
 *         temporary error
 */
static int transportSend(TSession * tsession,
			 const void * msg,
			 unsigned int size,
			 int important) {
  if (tsession == NULL) {
    GE_LOG(ectx,
	   GE_DEBUG | GE_DEVELOPER | GE_BULK,
	   "Transmission attempted on uni-directional pipe, failing.\n");
    return SYSERR; /* can't do that, can happen for unidirectional pipes
		      that call core with TSession being NULL. */
  }
  if ( (tsession->ttype >= tapis_count) ||
       (tapis[tsession->ttype] == NULL) ) {
    GE_LOG(ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("Transmission attempt failed, transport type %d unknown.\n"),
	   tsession->ttype);
    return SYSERR;
  }
  return tapis[tsession->ttype]->send(tsession,
				      msg,
				      size,
				      important);
}

/**
 * Close the session with the remote node.
 * @return OK on success, SYSERR on error
 */
static int transportDisconnect(TSession * tsession) {
  if (tsession == NULL) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  if ( (tsession->ttype >= tapis_count) ||
       (tapis[tsession->ttype] == NULL) ) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  return tapis[tsession->ttype]->disconnect(tsession);
}

/**
 * Verify that a hello is ok. Call a method
 * if the verification was successful.
 * @return OK if the attempt to verify is on the way,
 *        SYSERR if the transport mechanism is not supported
 */
static int transportVerifyHelo(const P2P_hello_MESSAGE * helo) {
  unsigned short prot;

  prot = ntohs(helo->protocol);
  if ( (prot == NAT_PROTOCOL_NUMBER) &&
       ( (ntohs(helo->header.size) != P2P_hello_MESSAGE_size(helo)) ||
	 (ntohs(helo->header.type) != p2p_PROTO_hello) ) )
    return SYSERR; /* invalid */
  if ( (ntohs(helo->protocol) >= tapis_count) ||
       (tapis[prot] == NULL) )
    return SYSERR; /* not supported */
  return tapis[prot]->verifyHelo(helo);
}

/**
 * Get the MTU for a given transport type.
 */
static int transportGetMTU(unsigned short ttype) {
  if ( (ttype >= tapis_count) ||
       (tapis[ttype] == NULL) )
    return SYSERR;
  return tapis[ttype]->mtu;
}

/**
 * Create a hello advertisement for the given
 * transport type for this node.
 */
static P2P_hello_MESSAGE *
transportCreatehello(unsigned short ttype) {
  TransportAPI * tapi;
  P2P_hello_MESSAGE * helo;

  MUTEX_LOCK(tapis_lock);
  if (ttype == ANY_PROTOCOL_NUMBER) {
    int * perm;

    perm = permute(WEAK, tapis_count);
    ttype = tapis_count-1;
    while ( (ttype < tapis_count) &&
	    ( (tapis[perm[ttype]] == NULL) ||
	      (tapis[perm[ttype]] != NULL &&
	       tapis[perm[ttype]]->hello == NULL) ) )
      ttype--; /* unsigned, will wrap around! */
    if (ttype >= tapis_count) {
      FREE(perm);
      MUTEX_UNLOCK(tapis_lock);
      return NULL;
    }
    ttype = perm[ttype];
    FREE(perm);
  }
  if ( (ttype >= tapis_count) ||
       (tapis[ttype] == NULL) ) {
    GE_LOG(ectx,
	   GE_WARNING | GE_BULK | GE_USER,
	   _("No transport of type %d known.\n"),
	   ttype);
    MUTEX_UNLOCK(tapis_lock);
    return NULL;
  }
  tapi = tapis[ttype];
  if (tapi->hello == NULL) {
    MUTEX_UNLOCK(tapis_lock);
    return NULL; /* send-only transport */
  }
  helo = MALLOC(P2P_hello_MESSAGE_size(tapi->hello));
  memcpy(helo,
	 tapi->hello,
	 P2P_hello_MESSAGE_size(tapi->hello));
  MUTEX_UNLOCK(tapis_lock);
  return helo;
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
static int getAdvertisedhellos(unsigned int maxLen,
			       char * buff) {
  int i;
  int tcount;
  P2P_hello_MESSAGE ** helos;
  int used;

  MUTEX_LOCK(tapis_lock);
  tcount = 0;
  for (i=0;i<tapis_count;i++)
    if (tapis[i] != NULL)
      tcount++;

  helos = MALLOC(tcount * sizeof(P2P_hello_MESSAGE*));
  tcount = 0;
  for (i=0;i<tapis_count;i++) {
    if (tapis[i] != NULL) {
      helos[tcount] = transportCreatehello(i);
      if (NULL != helos[tcount])
	tcount++;
    }
  }
  MUTEX_UNLOCK(tapis_lock);
  if (tcount == 0) {
    GE_LOG(ectx,
	   GE_INFO | GE_USER | GE_REQUEST,
	   _("No transport succeeded in creating a hello!\n"));
    FREE(helos);
    return SYSERR;
  }
  used = 0;
  while (tcount > 0) {
    i = weak_randomi(tcount); /* select a hello at random */
    if ((unsigned int)P2P_hello_MESSAGE_size(helos[i]) <= maxLen - used) {
      memcpy(&buff[used],
	     helos[i],
	     P2P_hello_MESSAGE_size(helos[i]));
      used += P2P_hello_MESSAGE_size(helos[i]);
    }
    FREE(helos[i]);
    helos[i] = helos[--tcount];
  }
  for (i=0;i<tcount;i++)
    FREE(helos[i]);
  FREE(helos);
  if (used == 0)
    GE_LOG(ectx,
	   GE_DEBUG | GE_DEVELOPER | GE_REQUEST,
	   "No hellos fit in %u bytes.\n",
	   maxLen);
  return used;
}

static void initHello(void * cls) {
  TransportAPI * tapi = cls;
  P2P_hello_MESSAGE * helo;

  createSignedhello(tapi);
  helo = transportCreatehello(tapi->protocolNumber);
  if (NULL != helo) {
    identity->addHost(helo);
    FREE(helo);
  }
}


static void doneHelper(TransportAPI * tapi,
		       void * unused) {
  /* In the (rare) case that we shutdown transports
     before the cron-jobs had a chance to run, stop
     the cron-jobs */
  cron_del_job(coreAPI->cron,
	       &initHello,
	       0,
	       tapi);
}

static void unloadTransport(int i) {
  void (*ptr)();

  doneHelper(tapis[i], NULL);
  cron_del_job(coreAPI->cron,
	       &createSignedhello,
	       HELLO_RECREATE_FREQ,
	       tapis[i]);
  ptr = os_plugin_resolve_function(tapis[i]->libHandle,
				   "donetransport_",
				   NO);
  if (ptr != NULL)
    ptr();
  FREE(tapis[i]->transName);
  FREENONNULL(tapis[i]->hello);
  tapis[i]->hello = NULL;
  os_plugin_unload(tapis[i]->libHandle);
  tapis[i] = NULL;
}


/**
 * Actually start the transport services and begin
 * receiving messages.
 */
static void startTransports(P2P_PACKETProcessor mpp) {
  int i;

  ctapi.receive = mpp;
  for (i=0;i<tapis_count;i++)
    if (tapis[i] != NULL) {
      if (OK != tapis[i]->startTransportServer())
	unloadTransport(i);
    }
}

/**
 * Stop the transport services, stop receiving messages.
 */
static void stopTransports() {
  int i;

  for (i=0;i<tapis_count;i++)
    if (tapis[i] != NULL)
      tapis[i]->stopTransportServer();
  ctapi.receive = NULL;
}

static void initHelper(TransportAPI * tapi,
		       void * unused) {
  /* Creation of HELLOs takes longer if a locally
     unresolvable hostname ((Dyn)DNS) was specified
     as this host's address and we have no network
     connection at the moment. gethostbyname()
     blocks the startup process in this case.
     This is why we create the HELLOs in another
     thread. */
  cron_add_job(coreAPI->cron,
	       &initHello,
	       0,
	       0,
	       tapi);
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
static int testWouldTry(TSession * tsession,
			unsigned int size,
			int important) {
  if (tsession == NULL) 
    return SYSERR; 
  if ( (tsession->ttype >= tapis_count) ||
       (tapis[tsession->ttype] == NULL) ) 
    return SYSERR;  
  return tapis[tsession->ttype]->testWouldTry(tsession,
					      size,
					      important);
}

/**
 * Initialize the transport layer.
 */
Transport_ServiceAPI *
provide_module_transport(CoreAPIForApplication * capi) {
  static Transport_ServiceAPI ret;
  TransportAPI * tapi;
  TransportMainMethod tptr;
  char * dso;
  char * next;
  char * pos;
  struct PluginHandle * lib;
  EncName myself;

  ectx = capi->ectx;
  if (-1 == GC_get_configuration_value_number(capi->cfg,
					      "GNUNETD",
					      "HELLOEXPIRES",
					      1,
					      MAX_HELLO_EXPIRES / 60,
					      60,
					      &helo_live))
    return NULL;
  helo_live *= 60;

  GE_ASSERT(ectx,
	    sizeof(P2P_hello_MESSAGE) == 600);
  identity = capi->requestService("identity");
  if (identity == NULL) {
    GE_BREAK(ectx, 0);
    return NULL;
  }
  coreAPI = capi;
  ctapi.version = 1;
  ctapi.myIdentity = coreAPI->myIdentity;
  ctapi.ectx = coreAPI->ectx;
  ctapi.cfg = coreAPI->cfg;
  ctapi.load_monitor = coreAPI->load_monitor;
  ctapi.cron = coreAPI->cron;
  ctapi.receive = NULL; /* initialized LATER! */
  ctapi.requestService = coreAPI->requestService;
  ctapi.releaseService = coreAPI->releaseService;

  GROW(tapis,
       tapis_count,
       UDP_PROTOCOL_NUMBER+1);

  tapis_lock = MUTEX_CREATE(YES);

  /* now load transports */
  dso = NULL;
  GE_ASSERT(ectx,
	    -1 != GC_get_configuration_value_string(capi->cfg,
						    "GNUNETD",
						    "TRANSPORTS",
						    "udp tcp nat",
						    &dso));
  if (strlen(dso) != 0) {
    GE_LOG(ectx,
	   GE_INFO | GE_USER | GE_BULK,
	   _("Loading transports `%s'\n"),
	   dso);
    next = dso;
    do {
      pos = next;
      while ( (*next != '\0') &&
	      (*next != ' ') )
	next++;
      if (*next == '\0')
	next = NULL; /* terminate! */
      else {
	*next = '\0'; /* add 0-termination for pos */
	next++;
      }
      lib = os_plugin_load(ectx,
			   "libgnunettransport_",
			   pos);
      if (lib == NULL) {
	GE_LOG(ectx,
	       GE_ERROR | GE_USER | GE_ADMIN | GE_IMMEDIATE,
	       _("Could not load transport plugin `%s'\n"),
	       pos);
	continue;
      }
      tptr = os_plugin_resolve_function(lib,
					"inittransport_",
					YES);
      if (tptr == NULL) {
	GE_LOG(ectx,
	       GE_ERROR | GE_ADMIN | GE_USER | GE_DEVELOPER | GE_IMMEDIATE,
	       _("Transport library `%s' did not provide required function '%s%s'.\n"),
	       pos,
	       "inittransport_",
	       pos);
	os_plugin_unload(lib);
	continue;
      }
      tapi = tptr(&ctapi);
      if (tapi == NULL) {
	os_plugin_unload(lib);
	continue;
      }
      tapi->libHandle = lib;
      tapi->transName = STRDUP(pos);
      if (OK != addTransport(tapi)) {
	void (*ptr)();

	FREE(tapi->transName);
	ptr = os_plugin_resolve_function(lib,
					 "donetransport_",
					 NO);
	if (ptr != NULL)
	  ptr();
	os_plugin_unload(lib);	
      } else {
	GE_LOG(ectx,
	       GE_INFO | GE_USER | GE_BULK,
	       _("Loaded transport `%s'\n"),
	       pos);
      }
    } while (next != NULL);
  }
  FREE(dso);

  IF_GELOG(ectx,
	   GE_INFO | GE_REQUEST | GE_USER,
	   hash2enc(&coreAPI->myIdentity->hashPubKey,
		    &myself));
  GE_LOG(ectx,
	 GE_INFO | GE_REQUEST | GE_USER,
	 _("I am peer `%s'.\n"),
	 &myself);
  forEachTransport(&initHelper, NULL);

  ret.start = &startTransports;
  ret.stop = &stopTransports;
  ret.isAvailable = &isTransportAvailable;
  ret.add = &addTransport;
  ret.forEach = &forEachTransport;
  ret.connect = &transportConnect;
  ret.connectFreely = &transportConnectFreely;
  ret.associate = &transportAssociate;
  ret.getCost = &transportGetCost;
  ret.send = &transportSend;
  ret.disconnect = &transportDisconnect;
  ret.verifyhello = &transportVerifyHelo;
  ret.helloToString = &helloToString;
  ret.getMTU = &transportGetMTU;
  ret.createhello = &transportCreatehello;
  ret.getAdvertisedhellos = &getAdvertisedhellos;
  ret.testWouldTry = &testWouldTry;

  return &ret;
}


/**
 * Shutdown the transport layer.
 */
int release_module_transport() {
  int i;

  forEachTransport(&doneHelper, NULL);
  for (i=0;i<tapis_count;i++)
    if (tapis[i] != NULL)
      unloadTransport(i);
  MUTEX_DESTROY(tapis_lock);
  tapis_lock = NULL;
  GROW(tapis,
       tapis_count,
       0);

  coreAPI->releaseService(identity);
  identity = NULL;
  coreAPI = NULL;
  return OK;
}


/* end of transport.c */			
