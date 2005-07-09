/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file advertising/advertising.c
 * @brief Cron-jobs that exchange HELOs to ensure that the network is
 * connected (nodes know of each other).  This is implemented as
 * an application and not a service (since no API is provided for
 * clients to call on -- this just happens in the background).
 *
 * Nevertheless, every GNUnet peer should probably run advertising
 * at the moment.
 *
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_identity_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_pingpong_service.h"
#include "gnunet_stats_service.h"
#include "gnunet_topology_service.h"

#include "bootstrap.h"

/**
 * Send our HELO to a random connected host on a regular basis.
 */
#define HELO_BROADCAST_FREQUENCY (2 * cronMINUTES)

/**
 * From time to time, forward one HELO from one peer to
 * a random other peer.
 */
#define HELO_FORWARD_FREQUENCY (4 * cronMINUTES)

/**
 * Meanings of the bits in activeCronJobs (ACJ).
 */
#define ACJ_NONE 0
#define ACJ_ANNOUNCE 1
#define ACJ_FORWARD 2
#define ACJ_ALL (ACJ_ANNOUNCE | ACJ_FORWARD)

#define DEBUG_HELOEXCHANGE NO

static CoreAPIForApplication * coreAPI;

static Transport_ServiceAPI * transport;

static Identity_ServiceAPI * identity;

static Pingpong_ServiceAPI * pingpong;

static Topology_ServiceAPI * topology;

static Stats_ServiceAPI * stats;

static int stat_HELO_in;

static int stat_HELO_out;

static int stat_HELO_fwd;

/**
 * Which types of cron-jobs are currently scheduled
 * with cron?
 */
static int activeCronJobs = ACJ_NONE;

static cron_t lastHELOMsg = 0;

static double getConnectPriority() {
  double preference;

  /* we should'nt give lots of bandwidth for HELOs if we're close to
     the connection goal */
  preference = topology->getSaturation();
  if (preference <= 0.0001)
    preference = 0xFFFF;
  else
    preference = 1/preference;
  /* always give some decent, but compared to (migrated) content
     competitive amount of bandwidth to peers sending (valid)
     HELOs */
  if (preference < 0.2)
    preference = 0.2;
  return preference;
}

static void callAddHost(HELO_Message * helo) {
  identity->addHost(helo);
  FREE(helo);
}

/**
 * We have received a HELO.  Verify (signature, integrity,
 * ping-pong) and store identity if ok.
 *
 * @param message the HELO message
 * @return SYSERR on error, OK on success
 */
static int
receivedHELO(const p2p_HEADER * message) {
  TSession * tsession;
  HELO_Message * copy;
  PeerIdentity foreignId;
  HELO_Message * msg;
  p2p_HEADER * ping;
  char * buffer;
  int heloEnd;
  int mtu;
  int res;
  cron_t now;

  /* first verify that it is actually a valid HELO */
  msg = (HELO_Message* ) message;
  if (ntohs(msg->header.size) != HELO_Message_size(msg))
    return SYSERR;
  identity->getPeerIdentity(&msg->publicKey,
			    &foreignId);
  if (!equalsHashCode512(&msg->senderIdentity.hashPubKey,
			 &foreignId.hashPubKey))
    return SYSERR; /* public key and host hash do not match */
  if (SYSERR == verifySig(&msg->senderIdentity,
			  HELO_Message_size(msg)
			  - sizeof(Signature)
			  - sizeof(PublicKey)
			  - sizeof(p2p_HEADER),
			  &msg->signature,
			  &msg->publicKey)) {
    EncName enc;
    IFLOG(LOG_WARNING,
	  hash2enc(&msg->senderIdentity.hashPubKey,
		   &enc));
    LOG(LOG_WARNING,
	_("HELO message from '%s' invalid (signature invalid). Dropping.\n"),
	(char*)&enc);
    return SYSERR; /* message invalid */
  }
  if ((TIME_T)ntohl(msg->expirationTime) > TIME(NULL) + MAX_HELO_EXPIRES) {
     LOG(LOG_WARNING,
	 _("HELO message received invalid (expiration time over limit). Dropping.\n"));
    return SYSERR;
  }
  if (SYSERR == transport->verifyHELO(msg))
    return OK; /* not good, but do process rest of message */
  if (stats != NULL)
    stats->change(stat_HELO_in, 1);
#if DEBUG_HELOEXCHANGE
  LOG(LOG_INFO,
      _("HELO advertisement for protocol %d received.\n"),
      ntohs(msg->protocol));
#endif
  if (ntohs(msg->protocol) == NAT_PROTOCOL_NUMBER) {
    /* We *can* not verify NAT.  Ever.  So all we
       can do is just accept it.  The best thing
       that we may do is check that it was not
       forwarded by another peer (forwarding NAT
       advertisements is invalid), but even that
       check can not be done securely (since we
       have to accept HELOs in plaintext).  Thus
       we take NAT advertisements at face value
       (which is OK since we never attempt to
       connect to a NAT). */
    identity->addHost(msg);
    return OK;
  }

  /* Then check if we have seen this HELO before, if it is identical
     except for the TTL, we trust it and do not play PING-PONG */
  copy = identity->identity2Helo(&foreignId,
				 ntohs(msg->protocol),
				 NO);
  if (NULL != copy) {
    if ( (ntohs(copy->senderAddressSize) ==
	  ntohs(msg->senderAddressSize)) &&
	 (0 == memcmp(&msg->MTU,
		      &copy->MTU,
		      sizeof(unsigned short)*2+
		      sizeof(unsigned int) +
		      ntohs(copy->senderAddressSize)) ) ) {
      /* ok, we've seen this one exactly like this before (at most the
	 TTL has changed); thus we can 'trust' it without playing
	 ping-pong */
      identity->addHost(msg);
      FREE(copy);
      return OK;
    } else {
#if DEBUG_HELOEXCHANGE
      LOG(LOG_DEBUG,
	  "advertised HELO differs from prior knowledge,"
	  " requireing ping-pong confirmation.\n");
#endif
    }
    FREE(copy);
  }

  if (testConfigurationString("GNUNETD",
			      "PRIVATE-NETWORK",
			      "YES")) {
    /* the option 'PRIVATE-NETWORK' can be used
       to limit the connections of this peer to
       peers of which the hostkey has been copied
       by hand to data/hosts;  if this option is
       given, GNUnet will not accept advertisements
       of peers that the local node does not already
       know about.  Note that in order for this
       option to work, HOSTLISTURL should either
       not be set at all or be set to a trusted
       peer that only advertises the private network.
       Also, the option does NOT work at the moment
       if the NAT transport is loaded; for that,
       a couple of lines above would need some minor
       editing :-). */
    return SYSERR;
  }

  cronTime(&now);
  if ( (now - lastHELOMsg) *
       getConfigurationInt("LOAD",
			   "MAXNETDOWNBPSTOTAL") /
       cronSECONDS / 100
       < HELO_Message_size(msg) ) {
    /* do not use more than about 1% of the
       available bandwidth to VERIFY HELOs (by sending
       our own with a PING).  This does not affect
       the HELO advertising.  Sure, we should not
       advertise much more than what other peers
       can verify, but the problem is that buggy/
       malicious peers can spam us with HELOs, and
       we don't want to follow that up with massive
       HELO-ing by ourselves. */
    return SYSERR;
  }
  lastHELOMsg = now;

  /* Ok, must play PING-PONG. Add the HELO to the temporary
     (in-memory only) buffer to make it available for a short
     time in order to play PING-PONG */
  identity->addHostTemporarily(msg);


  /* Establish session as advertised in the HELO */
  tsession = transport->connect(msg);
  if (tsession == NULL) 
    return SYSERR; /* could not connect */  

  /* build message to send, ping must contain return-information,
     such as a selection of our HELOs... */
  mtu = transport->getMTU(tsession->ttype);
  if (mtu == 0)
    mtu = 2048; /* bound size */
  buffer = MALLOC(mtu);
  copy = MALLOC(HELO_Message_size(msg));
  memcpy(copy,
	 msg,
	 HELO_Message_size(msg));
  ping = pingpong->pingUser(&msg->senderIdentity,
			    (CronJob)&callAddHost,
			    copy,
			    YES);
  if (ping == NULL) {
    res = SYSERR;
    FREE(buffer);
    LOG(LOG_INFO,
	_("Could not send HELOs+PING, ping buffer full.\n"));
    transport->disconnect(tsession);
    return SYSERR;
  }
  if (mtu > ntohs(ping->size)) {
    heloEnd = transport->getAdvertisedHELOs(mtu - ntohs(ping->size),
					    buffer);
    GNUNET_ASSERT(mtu - ntohs(ping->size) >= heloEnd);
  } else {
    heloEnd = -2;
  }
  if (heloEnd <= 0) {
    LOG(LOG_WARNING,
	_("'%s' failed (%d, %u). Will not send PING.\n"),
	"getAdvertisedHELOs",
	heloEnd,
	mtu - ntohs(ping->size));
    FREE(buffer);
    transport->disconnect(tsession);
    return SYSERR;
  }
  res = OK;
  memcpy(&buffer[heloEnd],
	 ping,
	 ntohs(ping->size));
  heloEnd += ntohs(ping->size);
  FREE(ping);

  /* ok, finally we can send! */
  if ( (res == OK) &&
       (SYSERR == coreAPI->sendPlaintext(tsession,
					 buffer,
					 heloEnd)) )
    res = SYSERR;
  FREE(buffer);
  if (SYSERR == transport->disconnect(tsession))
    res = SYSERR;
  return res;
}

typedef struct {
  /* the HELO message */
  HELO_Message * m;
  /* send the HELO in 1 out of n cases */
  int n;
} SendData;

static void
broadcastHelper(const PeerIdentity * hi,
		const unsigned short proto,
		int confirmed,
		SendData * sd) {
  HELO_Message * helo;
  TSession * tsession;
  EncName other;
  int prio;

  if (confirmed == NO)
    return;
  if (proto == NAT_PROTOCOL_NUMBER)
    return; /* don't advertise NAT addresses via broadcast */
  if (randomi(sd->n) != 0)
    return;
  hash2enc(&hi->hashPubKey,
	   &other);
#if DEBUG_HELOEXCHANGE
  LOG(LOG_DEBUG,
      "Entering '%s' with target '%s'.\n",
      __FUNCTION__,
      &other);
#endif
  if (hostIdentityEquals(hi,
			 coreAPI->myIdentity))
    return; /* never advertise to myself... */
  prio = (int) getConnectPriority();
  if (prio >= EXTREME_PRIORITY)
    prio = EXTREME_PRIORITY / 4;
  if (0 != coreAPI->queryBPMfromPeer(hi)) {
    coreAPI->unicast(hi,
		     &sd->m->header,
		     prio,
		     HELO_BROADCAST_FREQUENCY);
    if (stats != NULL)
      stats->change(stat_HELO_out,
		    1);
    return;
  }
  /* with even lower probability (with n peers
     trying to contact with a probability of 1/n^2,
     we get a probability of 1/n for this, which
     is what we want: fewer attempts to contact fresh
     peers as the network grows): */
  if (randomi(sd->n) != 0)
    return;

  /* establish short-lived connection, send, tear down */
  helo = identity->identity2Helo(hi,
				 proto,
				 NO);
  if (NULL == helo) {
#if DEBUG_HELOEXCHANGE
    LOG(LOG_DEBUG,
	"Exit from '%s' (error: '%s' failed).\n",
	__FUNCTION__,
	"identity2Helo");
#endif
    return;
  }
  tsession = transport->connect(helo);
  FREE(helo);
  if (tsession == NULL) {
#if DEBUG_HELOEXCHANGE
    LOG(LOG_DEBUG,
	"Exit from '%s' (%s error).\n",
	__FUNCTION__,
	"transportConnect");
#endif
    return; /* could not connect */
  }
  if (stats != NULL)
    stats->change(stat_HELO_out,
		  1);
  coreAPI->sendPlaintext(tsession,
			 (char*)&sd->m->header,
			 HELO_Message_size(sd->m));
  transport->disconnect(tsession);
#if DEBUG_HELOEXCHANGE
  LOG(LOG_DEBUG,
      "Exit from %s.\n",
      __FUNCTION__);
#endif
 }

/**
 * Tell a couple of random hosts on the currentKnownHost list
 * that we exist (called for each transport)...
 */
static void
broadcastHELOTransport(TransportAPI * tapi,
		       const int * prob) {
  SendData sd;
  cron_t now;

  if (getNetworkLoadUp() > 100)
    return; /* network load too high... */
  if (0 != randomi(*prob))
    return; /* ignore */
#if DEBUG_HELOEXCHANGE
  LOG(LOG_CRON,
      "Enter '%s'.\n",
      __FUNCTION__);
#endif
  cronTime(&now);
  sd.n = identity->forEachHost(now,
			       NULL,
			       NULL); /* just count */
  sd.m = transport->createHELO(tapi->protocolNumber);
  if (sd.m == NULL)
    return;
#if DEBUG_HELOEXCHANGE
  LOG(LOG_INFO,
      _("Advertising my transport %d to selected peers.\n"),
      tapi->protocolNumber);
#endif
  identity->addHost(sd.m);
  if (sd.n < 1) {
    if (identity->forEachHost(0, NULL, NULL) == 0)
      LOG(LOG_WARNING,
	  _("Announcing ourselves pointless: "
	    "no other peers are known to us so far.\n"));
    FREE(sd.m);
    return; /* no point in trying... */
  }
  identity->forEachHost(now,
		       (HostIterator)&broadcastHelper,
		       &sd);
  FREE(sd.m);
#if DEBUG_HELOEXCHANGE
  LOG(LOG_CRON,
      "Exit '%s'.\n",
      __FUNCTION__);
#endif
}

/**
 * Tell a couple of random hosts on the currentKnownHost list
 * that we exist...
 */
static void broadcastHELO(void * unused) {
  unsigned int i;

  if (getNetworkLoadUp() > 100)
    return; /* network load too high... */
  if (getCPULoad() > 100)
    return; /* CPU load too high... */
  i = transport->forEach(NULL,
			 NULL);
  transport->forEach((TransportCallback)&broadcastHELOTransport,
		     &i);
}

typedef struct {
  unsigned int delay;
  HELO_Message * msg;
  int prob;
} FCC;

static void forwardCallback(const PeerIdentity * peer,
			    FCC * fcc) {
  if (getNetworkLoadUp() > 100)
    return; /* network load too high... */
  if (randomi(fcc->prob) != 0)
    return; /* only forward with a certain chance */
  if (equalsHashCode512(&peer->hashPubKey,
			&fcc->msg->senderIdentity.hashPubKey))
    return; /* do not bounce the HELO of a peer back
	       to the same peer! */
  if (stats != NULL)
    stats->change(stat_HELO_fwd, 1);
  coreAPI->unicast(peer,
		   &fcc->msg->header,
		   0, /* priority */
		   fcc->delay);
}

/**
 * Forward HELOs from all known hosts to all connected hosts.
 */
static void
forwardHELOHelper(const PeerIdentity * peer,
		  unsigned short protocol,
		  int confirmed,
		  void * data) {
  int * probability = data;
  HELO_Message * helo;
  TIME_T now;
  int count;
  FCC fcc;

  if (getNetworkLoadUp() > 100)
    return; /* network load too high... */
  if (confirmed == NO)
    return;
  if (protocol == NAT_PROTOCOL_NUMBER)
    return; /* don't forward NAT addresses */
  if (randomi((*probability)+1) != 0)
    return; /* only forward with a certain chance,
	       (on average: 1 peer per run!) */
#if DEBUG_HELOEXCHANGE
  LOG(LOG_CRON,
      "forwarding HELOs\n");
#endif
  helo = identity->identity2Helo(peer,
				 protocol,
				 NO);
  if (NULL == helo)
    return; /* this should not happen */
  helo->header.type
    = htons(p2p_PROTO_HELO);
  helo->header.size
    = htons(HELO_Message_size(helo));
  /* do not forward expired HELOs */
  TIME(&now);
  if ((TIME_T)ntohl(helo->expirationTime) < now) {
    EncName enc;
    /* remove HELOs that expired */
    IFLOG(LOG_INFO,
	  hash2enc(&peer->hashPubKey,
		   &enc));
    LOG(LOG_INFO,
	_("Removing HELO from peer '%s' (expired %ds ago).\n"),
	&enc,
	now - ntohl(helo->expirationTime));
    identity->delHostFromKnown(peer, protocol);
    FREE(helo);
    return;
  }
  count = coreAPI->forAllConnectedNodes(NULL,
					NULL);
  if (count > 0) {
    fcc.delay = (*probability) * HELO_BROADCAST_FREQUENCY;  /* send before the next round */
    fcc.msg  = helo;
    fcc.prob = count;
    coreAPI->forAllConnectedNodes((PerNodeCallback) &forwardCallback,
				  &fcc);
  }
  FREE(helo);
}

/**
 * Forward HELOs from all known hosts to all connected hosts.
 * We do on average 1 forwarding (by random selection of
 * source and target).
 */
static void
forwardHELO(void * unused) {
  int count;

  if (getCPULoad() > 100)
    return; /* CPU load too high... */
#if DEBUG_HELOEXCHANGE
  LOG(LOG_CRON,
      "Enter '%s'.\n",
      __FUNCTION__);
#endif
  count = identity->forEachHost(0,
				NULL,
				NULL);
  identity->forEachHost(0, /* ignore blacklisting */
			&forwardHELOHelper,
			&count);
#if DEBUG_HELOEXCHANGE
  LOG(LOG_CRON,
      "Exit '%s'.\n",
      __FUNCTION__);
#endif
}

/**
 * Type for a HELO send via an encrypted channel.
 */
static int
eHELOHandler(const PeerIdentity * sender,
	     const p2p_HEADER * message) {
  if (OK == receivedHELO(message)) {
    /* if the HELO was ok, update traffic preference
       for the peer (depending on how much we like
       to learn about other peers) */
    coreAPI->preferTrafficFrom(sender,
			       getConnectPriority());
  }
  return OK; /* even if we had errors processing the HELO, keep going */
}

/**
 * Type for a HELO send in plaintext.
 */
static int
pHELOHandler(const PeerIdentity * sender,
	     const p2p_HEADER * message,
	     TSession * session) {
  receivedHELO(message);
  return OK;
}

/**
 * The configuration has changed, update set of running cron jobs.
 * Does not have to suspend cron since this guaranteed to be a cron
 * job!
 */
static void
configurationUpdateCallback() {
  if (ACJ_ANNOUNCE == (activeCronJobs & ACJ_ANNOUNCE)) {
    if (testConfigurationString("NETWORK",
				"DISABLE-ADVERTISEMENTS",
				"YES"))
      delCronJob(&broadcastHELO,
		 HELO_BROADCAST_FREQUENCY,
		 NULL);
    activeCronJobs -= ACJ_ANNOUNCE;
  } else {
    if (testConfigurationString("NETWORK",
				"HELOEXCHANGE",
				"YES"))
      addCronJob(&broadcastHELO,
		 15 * cronSECONDS,
		 HELO_BROADCAST_FREQUENCY,
		 NULL);
    activeCronJobs += ACJ_ANNOUNCE;
  }
  if (ACJ_FORWARD == (activeCronJobs & ACJ_FORWARD)) {
    if (! testConfigurationString("NETWORK",
				  "HELOEXCHANGE",
				  "YES"))
      delCronJob(&forwardHELO,
		 HELO_FORWARD_FREQUENCY,
		 NULL); /* seven minutes: exchange */
    activeCronJobs -= ACJ_FORWARD;
  } else {
    if (! testConfigurationString("NETWORK",
				  "DISABLE-ADVERTISEMENTS",
				  "YES"))
      addCronJob(&broadcastHELO,
		 15 * cronSECONDS,
		 HELO_BROADCAST_FREQUENCY,
		 NULL);
    activeCronJobs += ACJ_FORWARD;
  }
}

/**
 * Start advertising.
 */
int
initialize_module_advertising(CoreAPIForApplication * capi) {
  coreAPI = capi;
  identity = capi->requestService("identity");
  if (identity == NULL) {
    BREAK();
    return SYSERR;
  }
  transport = capi->requestService("transport");
  if (transport == NULL) {
    BREAK();
    capi->releaseService(identity);
    identity = NULL;
    return SYSERR;
  }
  pingpong = capi->requestService("pingpong");
  if (pingpong == NULL) {
    BREAK();
    capi->releaseService(identity);
    identity = NULL;
    capi->releaseService(transport);
    transport = NULL;
    return SYSERR;
  }
  topology = capi->requestService("topology");
  if (topology == NULL) {
    BREAK();
    capi->releaseService(identity);
    identity = NULL;
    capi->releaseService(transport);
    transport = NULL;
    capi->releaseService(pingpong);
    pingpong = NULL;
    return SYSERR;
  }
  stats = capi->requestService("stats");
  if (stats != NULL) {
    stat_HELO_in = stats->create(_("# Peer advertisements received"));
    stat_HELO_out = stats->create(_("# Self advertisments transmitted"));
    stat_HELO_fwd = stats->create(_("# Foreign advertisements forwarded"));
  }

  LOG(LOG_DEBUG,
      _("'%s' registering handler %d (plaintext and ciphertext)\n"),
      "advertising",
      p2p_PROTO_HELO);

  capi->registerHandler(p2p_PROTO_HELO,
			&eHELOHandler);
  capi->registerPlaintextHandler(p2p_PROTO_HELO,
				 &pHELOHandler);
  registerConfigurationUpdateCallback(&configurationUpdateCallback);
  if (! testConfigurationString("NETWORK",
				"DISABLE-ADVERTISEMENTS",
				"YES")) {
    addCronJob(&broadcastHELO,
	       15 * cronSECONDS,
	       HELO_BROADCAST_FREQUENCY,
	       NULL);
    activeCronJobs += ACJ_ANNOUNCE;
  } else {
    LOG(LOG_WARNING,
	_("Network advertisements disabled by configuration!\n"));
  }
  if (testConfigurationString("NETWORK",
			      "HELOEXCHANGE",
			      "YES") == YES) {
    addCronJob(&forwardHELO,
	       4 * cronMINUTES,
	       HELO_FORWARD_FREQUENCY,
	       NULL);
    activeCronJobs += ACJ_FORWARD;
  }
#if DEBUG_HELOEXCHANGE
  else
    LOG(LOG_DEBUG,
	"HELO forwarding disabled!\n");
#endif

  startBootstrap(capi);
  setConfigurationString("ABOUT",
			 "advertising",
			 _("ensures that this peer is known by other"
			   " peers and discovers other peers"));
  return OK;
}

/**
 * Stop advertising.
 */
void done_module_advertising() {
  stopBootstrap();
  if (ACJ_ANNOUNCE == (activeCronJobs & ACJ_ANNOUNCE)) {
    delCronJob(&broadcastHELO,
	       HELO_BROADCAST_FREQUENCY,
	       NULL);
    activeCronJobs -= ACJ_ANNOUNCE;
  }
  if (ACJ_FORWARD == (activeCronJobs & ACJ_FORWARD)) {
    delCronJob(&forwardHELO,
	       HELO_FORWARD_FREQUENCY,
	       NULL); /* seven minutes: exchange */
    activeCronJobs -= ACJ_FORWARD;
  }
  unregisterConfigurationUpdateCallback(&configurationUpdateCallback);
  coreAPI->unregisterHandler(p2p_PROTO_HELO,
			     &eHELOHandler);
  coreAPI->unregisterPlaintextHandler(p2p_PROTO_HELO,
				      &pHELOHandler);
  coreAPI->releaseService(transport);
  transport = NULL;
  coreAPI->releaseService(identity);
  identity = NULL;
  coreAPI->releaseService(pingpong);
  pingpong = NULL;
  coreAPI->releaseService(topology);
  topology = NULL;
  if (stats != NULL) {
    coreAPI->releaseService(stats);
    stats = NULL;
  }
  coreAPI = NULL;
}




/* end of advertising.c */
