/*
     This file is part of GNUnet
     (C) 2001, 2002, 2004, 2005 Christian Grothoff (and other contributing authors)

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
static unsigned int helo_live;
static Mutex tapis_lock;

#define HELLO_RECREATE_FREQ (5 * cronMINUTES)



/**
 * Create signed hello for this transport and put it into
 * the cache tapi->helo.
 */
static void createSignedhello(TransportAPI * tapi) {
  MUTEX_LOCK(&tapis_lock);
  FREENONNULL(tapi->helo);
  tapi->helo = tapi->createhello();
  if (NULL == tapi->helo) {
#if DEBUG_TRANSPORT
    LOG(LOG_INFO,
	"Transport `%s' failed to create hello\n",
	tapi->transName);
#endif
    MUTEX_UNLOCK(&tapis_lock);
    return;
  }
  memcpy(&tapi->helo->publicKey,
	 identity->getPublicPrivateKey(),
	 sizeof(PublicKey));
  memcpy(&tapi->helo->senderIdentity,
	 coreAPI->myIdentity,
	 sizeof(PeerIdentity));
  tapi->helo->expirationTime
    = htonl(TIME(NULL) + helo_live);
  tapi->helo->header.type
    = htons(p2p_PROTO_hello);
  tapi->helo->header.size
    = htons(P2P_hello_MESSAGE_size(tapi->helo));
  if (SYSERR == identity->signData(&(tapi->helo)->senderIdentity,
				   P2P_hello_MESSAGE_size(tapi->helo)
				   - sizeof(Signature)
				   - sizeof(PublicKey)
				   - sizeof(P2P_MESSAGE_HEADER),
				   &tapi->helo->signature)) {
    FREE(tapi->helo);
    tapi->helo = NULL;
    BREAK();
  }
  MUTEX_UNLOCK(&tapis_lock);
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
  tapis[tapi->protocolNumber] = tapi;
  tapi->helo = NULL;
  addCronJob((CronJob)&createSignedhello,
	     HELLO_RECREATE_FREQ,
	     HELLO_RECREATE_FREQ,
	     tapi);
  return OK;
}

/**
 * Convert hello to string.
 */
static char * heloToString(const P2P_hello_MESSAGE * helo) {
  TransportAPI * tapi;
  unsigned short prot;

  if (ntohs(helo->protocol) >= tapis_count) {
    LOG(LOG_INFO,
	"%s failed, transport type %d not supported\n",
	__FUNCTION__,
	ntohs(helo->protocol));
    return NULL;
  }
  prot = ntohs(helo->protocol);
  tapi = tapis[prot];
  if (tapi == NULL) {
    LOG(LOG_INFO,
	"%s failed, transport type %d not supported\n",
	__FUNCTION__,
	ntohs(helo->protocol));
     return NULL;
  } else
    return tapi->addressToString(helo);
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
  TransportAPI * tapi;
  unsigned short prot;
  TSession * tsession;

  if (ntohs(helo->protocol) >= tapis_count) {
    LOG(LOG_INFO,
	"%s failed, transport type %d not supported\n",
	__FUNCTION__,
	ntohs(helo->protocol));
    return NULL;
  }
  prot = ntohs(helo->protocol);
  tapi = tapis[prot];
  if (tapi == NULL) {
    LOG(LOG_INFO,
	"%s failed, transport type %d not supported\n",
	__FUNCTION__,
	ntohs(helo->protocol));
     return NULL;
  } else {
    if (OK == tapi->connect(helo,
			    &tsession)) {
      tsession->ttype = prot;
#if DEBUG_TRANSPORT
      LOG(LOG_DEBUG,
	  "Core connected to tsession %p.\n",
	  *tsession);
#endif
      return tsession;
    } else
      return NULL;
  }
}

static TSession * transportConnectFreely(const PeerIdentity * peer,
					 int useTempList) {
  int i;
  P2P_hello_MESSAGE * helo;
  int * perm;
  TSession * ret;

  MUTEX_LOCK(&tapis_lock);
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
	MUTEX_UNLOCK(&tapis_lock);
	return ret;
      }
    }
  }
  FREE(perm);
  MUTEX_UNLOCK(&tapis_lock);
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
  TransportAPI * tapi;

  if (tsession == NULL)
    return SYSERR;
  if (tsession->ttype >= tapis_count)
    return SYSERR;
  tapi = tapis[tsession->ttype];
  if (tapi == NULL)
    return SYSERR;
  else {
#if DEBUG_TRANSPORT
    LOG(LOG_DEBUG,
	"Core associates with tsession %p.\n",
	tsession);
#endif
    return tapi->associate(tsession);
  }
}


/**
 * Get the cost of a message in for the given transport mechanism.
 */
static unsigned int transportGetCost(int ttype) {
  TransportAPI * tapi;

  if (ttype >= tapis_count)
    return SYSERR; /* -1 = INFTY */
  tapi = tapis[ttype];
  if (tapi == NULL)
    return SYSERR; /* -1 = INFTY */
  return tapi->cost;
}

/**
 * Send a message.
 * @param tsession the transport session identifying the connection
 * @param msg the message to send
 * @param size the size of the message
 * @param isEncrypted YES if the message is encrypted
 * @param crc the CRC of the (plaintext) message
 * @return OK on success, SYSERR on persistent error, NO on
 *         temporary error
 */
static int transportSend(TSession * tsession,
			 const void * msg,
			 const unsigned int size) {
  TransportAPI * tapi;

  if (tsession == NULL) {
    LOG(LOG_DEBUG,
        "transportSend attempted on uni-directional pipe, failing.\n");		
    return SYSERR; /* can't do that, can happen for unidirectional pipes
		      that call core with TSession being NULL. */
  }
  if (tsession->ttype >= tapis_count) {
    LOG(LOG_FAILURE,
	"%s failed, transport type %d unknown.\n",
	__FUNCTION__,
	tsession->ttype);
    return SYSERR;
  }
  tapi = tapis[tsession->ttype];
  if (tapi == NULL) {
    LOG(LOG_FAILURE,
	"%s failed, transport type %d unknown.\n",
	__FUNCTION__,
	tsession->ttype);
    return SYSERR;
  } else
    return tapi->send(tsession,
		      msg,
		      size);
}

/**
 * Send a message.  Try to be more reliable than usual.
 *
 * @param tsession the transport session identifying the connection
 * @param msg the message to send
 * @param size the size of the message
 * @return OK on success, SYSERR on error
 */
static int transportSendReliable(TSession * tsession,
				 const void * msg,
				 const unsigned int size) {
  TransportAPI * tapi;

  if (tsession == NULL) {
    LOG(LOG_DEBUG,
	"Cannot send reliable on this connection (not bi-directional!)\n");
    return SYSERR; /* can't do that, can happen for unidirectional pipes
		      that call core with TSession being NULL. */
  }
  if (tsession->ttype >= tapis_count) {
    LOG(LOG_FAILURE,
	"%s failed, transport type %d unknown.\n",
	__FUNCTION__,
	tsession->ttype);
    return SYSERR;
  }
  tapi = tapis[tsession->ttype];
  if (tapi == NULL) {
    LOG(LOG_FAILURE,
	"%s failed, transport type %d unknown.\n",
	__FUNCTION__,
	tsession->ttype);
    return SYSERR;
  }
  else
    return tapi->sendReliable(tsession,
			      msg,
			      size);
}

/**
 * Close the session with the remote node.
 * @return OK on success, SYSERR on error
 */
static int transportDisconnect(TSession * tsession) {
  TransportAPI * tapi;

  if (tsession == NULL) {
    BREAK();
    return SYSERR;
  }
  if (tsession->ttype >= tapis_count) {
    BREAK();
    return SYSERR;
  }
  tapi = tapis[tsession->ttype];
  if (tapi == NULL) {
    BREAK();
    return SYSERR;
  } else {
#if DEBUG_TRANSPORT
    LOG(LOG_DEBUG,
	"Core calls disconnect on tsession %p.\n",
	tsession);
#endif
    return tapi->disconnect(tsession);
  }
}

/**
 * Verify that a hello is ok. Call a method
 * if the verification was successful.
 * @return OK if the attempt to verify is on the way,
 *        SYSERR if the transport mechanism is not supported
 */
static int transportVerifyHelo(const P2P_hello_MESSAGE * helo) {
  TransportAPI * tapi;

  if (ntohs(helo->protocol) >= tapis_count) {
    LOG(LOG_EVERYTHING,
	"Advertised transport type %d"
	" does not match any known transport.\n",
	ntohs(helo->protocol));
    return SYSERR;
  }
  tapi = tapis[ntohs(helo->protocol)];
  if (tapi == NULL) {
    if (ntohs(helo->protocol) != NAT_PROTOCOL_NUMBER) {
      LOG(LOG_EVERYTHING,
	"Advertised transport type %d"
	" does not match any known transport.\n",
	ntohs(helo->protocol));
      return SYSERR;
    } else {
      LOG(LOG_EVERYTHING,
	"Advertised transport type is NAT,"
	" but nat module is not loaded."
	" Rudimentary sanity check enforced.\n");
      if ((ntohs(helo->header.size) != P2P_hello_MESSAGE_size(helo)) ||
	(ntohs(helo->header.type) != p2p_PROTO_hello) )
	return SYSERR; /* obviously invalid */
      return OK;
    }
  } else
    return tapi->verifyHelo(helo);
}

/**
 * Get the MTU for a given transport type.
 */
static int transportGetMTU(unsigned short ttype) {
  TransportAPI * tapi;

  if (ttype >= tapis_count)
    return SYSERR;
  tapi = tapis[ttype];
  if (tapi == NULL)
    return SYSERR;
  else
    return tapi->mtu;
}

/**
 * Create a hello advertisement for the given
 * transport type for this node.
 */
static P2P_hello_MESSAGE * transportCreatehello(unsigned short ttype) {
  TransportAPI * tapi;
  P2P_hello_MESSAGE * helo;

  MUTEX_LOCK(&tapis_lock);
  if (ttype == ANY_PROTOCOL_NUMBER) {
    int * perm;

    perm = permute(WEAK, tapis_count);
    ttype = tapis_count-1;
    while ( (ttype < tapis_count) &&
	    ( (tapis[perm[ttype]] == NULL) ||
	      (tapis[perm[ttype]] != NULL &&
	       tapis[perm[ttype]]->helo == NULL) ) )
      ttype--; /* unsigned, will wrap around! */
    if (ttype >= tapis_count) {
      FREE(perm);
      MUTEX_UNLOCK(&tapis_lock);
      return NULL;
    }
    ttype = perm[ttype];
    FREE(perm);
  }
  if (ttype >= tapis_count) {
    LOG(LOG_WARNING,
	_("No transport of type %d known.\n"),
	ttype);
    MUTEX_UNLOCK(&tapis_lock);
    return NULL;
  }
  tapi = tapis[ttype];
  if (tapi == NULL) {
    LOG(LOG_WARNING,
	_("No transport of type %d known.\n"),
	ttype);
    MUTEX_UNLOCK(&tapis_lock);
    return NULL;
  }
  if (tapi->helo == NULL) {
#if DEBUG_TRANSPORT
    LOG(LOG_DEBUG,
	"Transport of type %d configured for sending only (no hello).\n",
	ttype);
#endif
    MUTEX_UNLOCK(&tapis_lock);
    return NULL;
  }

  helo = MALLOC(P2P_hello_MESSAGE_size(tapi->helo));
  memcpy(helo,
	 tapi->helo,
	 P2P_hello_MESSAGE_size(tapi->helo));
  MUTEX_UNLOCK(&tapis_lock);
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

  MUTEX_LOCK(&tapis_lock);
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
  MUTEX_UNLOCK(&tapis_lock);
  if (tcount == 0) {
    LOG(LOG_DEBUG,
	"no transport succeeded in creating a hello\n");
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
    LOG(LOG_DEBUG,
	"%s failed: no hellos fit in %u bytes\n",
	maxLen);
  return used;
}


/**
 * Actually start the transport services and begin
 * receiving messages.
 */
static void startTransports(P2P_PACKETProcessor mpp) {
  int i;
  ctapi.receive = mpp;
  for (i=0;i<tapis_count;i++)
    if (tapis[i] != NULL)
      tapis[i]->startTransportServer();
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

static void initHelper(TransportAPI * tapi,
		       void * unused) {
  /* Creation of HELLOs takes longer if a locally
     unresolvable hostname ((Dyn)DNS) was specified
     as this host's address and we have no network
     connection at the moment. gethostbyname()
     blocks the startup process in this case.
     This is why we create the HELLOs in another
     thread. */
  addCronJob(&initHello,
       0,
       0,
       tapi);
}

static void doneHelper(TransportAPI * tapi,
		       void * unused) {
  /* In the (rare) case that we shutdown transports
     before the cron-jobs had a chance to run, stop
     the cron-jobs */
  delCronJob(&initHello,
       0,
       tapi);
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
  void * lib;
  EncName myself;

  GNUNET_ASSERT(sizeof(P2P_hello_MESSAGE) == 600);
  identity = capi->requestService("identity");
  if (identity == NULL) {
    BREAK();
    return NULL;
  }
  coreAPI = capi;
  ctapi.version = 0;
  ctapi.myIdentity = coreAPI->myIdentity;
  ctapi.receive = NULL; /* initialized LATER! */
  ctapi.requestService = coreAPI->requestService;
  ctapi.releaseService = coreAPI->releaseService;

  helo_live = getConfigurationInt("GNUNETD",
				  "HELLOEXPIRES") * 60; /* minutes to seconds */
  if (helo_live > MAX_HELLO_EXPIRES)
    helo_live = MAX_HELLO_EXPIRES;

  if (helo_live <= 0) {
    helo_live = 60 * 60;
    LOG(LOG_WARNING,
	_("Option `%s' not set in configuration in section `%s',"
	  " setting to %dm.\n"),
	"HELLOEXPIRES", "GNUNETD", helo_live / 60);
  }
  GROW(tapis,
       tapis_count,
       UDP_PROTOCOL_NUMBER+1);

  MUTEX_CREATE_RECURSIVE(&tapis_lock);

  /* now load transports */
  dso = getConfigurationString("GNUNETD",
			       "TRANSPORTS");
  if (dso == NULL) {
    LOG(LOG_WARNING,
	_("You should specify at least one transport service"
	  " under option `%s' in section `%s'.\n"),
	"TRANSPORTS", "GNUNETD");
  } else {
    LOG(LOG_DEBUG,
	"Loading transports `%s'\n",
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
      lib = loadDynamicLibrary("libgnunettransport_",
			       pos);
      tptr = bindDynamicMethod(lib,
			       "inittransport_",
			       pos);
      if (tptr == NULL)
	errexit(_("Transport library `%s' did not provide "
		  "required function '%s%s'.\n"),
		pos,
		"inittransport_",
		pos);
      tapi = tptr(&ctapi);
      tapi->libHandle = lib;
      tapi->transName = STRDUP(pos);
      addTransport(tapi);
      LOG(LOG_DEBUG,
	  "Loaded transport `%s'\n",
	  pos);
    } while (next != NULL);
    FREE(dso);
  }


  IFLOG(LOG_DEBUG,
	hash2enc(&coreAPI->myIdentity->hashPubKey,
		 &myself));
  LOG(LOG_DEBUG,
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
  ret.sendReliable = &transportSendReliable;
  ret.disconnect = &transportDisconnect;
  ret.verifyhello = &transportVerifyHelo;
  ret.heloToString = &heloToString;
  ret.getMTU = &transportGetMTU;
  ret.createhello = &transportCreatehello;
  ret.getAdvertisedhellos = &getAdvertisedhellos;

  return &ret;
}


/**
 * Shutdown the transport layer.
 */
int release_module_transport() {
  int i;
  void (*ptr)();

  forEachTransport(&doneHelper, NULL);
  for (i=0;i<tapis_count;i++) {
    if (tapis[i] != NULL) {
      delCronJob((CronJob)&createSignedhello,
		 HELLO_RECREATE_FREQ,
		 tapis[i]);
      ptr = bindDynamicMethod(tapis[i]->libHandle,
			      "donetransport_",
			      tapis[i]->transName);
      if (ptr != NULL)
	ptr();
      FREE(tapis[i]->transName);
      FREENONNULL(tapis[i]->helo);
      tapis[i]->helo = NULL;
      if (0 == getConfigurationInt("GNUNETD",
				   "VALGRIND"))
	/* do not unload plugins if we're using
	   valgrind */
	unloadDynamicLibrary(tapis[i]->libHandle);
    }
  }

  MUTEX_DESTROY(&tapis_lock);
  GROW(tapis,
       tapis_count,
       0);

  coreAPI->releaseService(identity);
  identity = NULL;
  coreAPI = NULL;
  return OK;
}


/* end of transport.c */			
