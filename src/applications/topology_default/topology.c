/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file topology_default/topology.c
 * @brief create the GNUnet mesh topology (essentially,
 *   try to connect to a large diverse, random set of peers)
 * @author Christian Grothoff
 *
 * Topology is implemented as both a service and an
 * application to allow users to force loading it
 * (which is probably a very good idea -- otherwise
 * the peer will end up rather disconnected :-)
 */

#include "platform.h"
#include "gnunet_core.h"
#include "gnunet_protocols.h"
#include "gnunet_identity_service.h"
#include "gnunet_topology_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_pingpong_service.h"

#define DEBUG_TOPOLOGY NO

/**
 * After 2 minutes on an inactive connection, probe the other
 * node with a ping if we have achieved less than 50% of our
 * connectivity goal.
 */
#define SECONDS_PINGATTEMPT 120

/**
 * How often should the cron-job scan for free slots (to establish
 * new connections)?
 */
#define LIVE_SCAN_FREQUENCY 500 * cronMILLIS

/**
 * Value > 1 that determines the chance (1:LSE) that the cron job
 * actually tries to do something for a given slot.
 */
#define LIVE_SCAN_EFFECTIVENESS 10

/**
 * Value < 1 that determines the chance (1:LPE) that the cron job
 * actually tries to ping a peer that is about to time-out.
 */
#define LIVE_PING_EFFECTIVENESS 20

static CoreAPIForApplication * coreAPI;

static Identity_ServiceAPI * identity;

static Transport_ServiceAPI * transport;

static Pingpong_ServiceAPI * pingpong;

/**
 * How many peers are we connected to in relation
 * to our ideal number?  (ideal = 1.0, too few: < 1,
 * too many: > 1). Maybe 0!
 */
static double saturation = 0.0;

/**
 * Record for state maintanance between scanHelperCount,
 * scanHelperSelect and scanForHosts.
 */
typedef struct {
  unsigned int index;
  unsigned int matchCount;
  long long costSelector;
  PeerIdentity match;
} IndexMatch;

/**
 * Here in this scanning for applicable hosts, we also want to take
 * the protocols into account and prefer "cheap" protocols,
 * i.e. protocols with a low overhead.
 *
 * @param id which peer are we currently looking at
 * @param proto what transport protocol are we looking at
 * @param im updated structure used to select the peer
 */
static void scanHelperCount(const PeerIdentity * id,
			    unsigned short proto,	
			    int confirmed,
			    void * data) {
  IndexMatch * im = data;

  if (hostIdentityEquals(coreAPI->myIdentity,
			 id))
    return;
  if (coreAPI->computeIndex(id) != im->index)
    return;
  if (0 != coreAPI->queryBPMfromPeer(id))
    return;
  if (YES == transport->isAvailable(proto)) {
    im->matchCount++;
    im->costSelector += transport->getCost(proto);
  }
}

/**
 * Select the peer and transport that was selected based on transport
 * cost.
 *
 * @param id the current peer
 * @param proto the protocol of the current peer
 * @param im structure responsible for the selection process
 */
static void scanHelperSelect(const PeerIdentity * id,
			     unsigned short proto,
			     int confirmed,
			     void * data) {
  IndexMatch * im = data;

  if (hostIdentityEquals(coreAPI->myIdentity, id))
    return;
  if (coreAPI->computeIndex(id) != im->index)
    return;
  if (0 != coreAPI->queryBPMfromPeer(id))
    return;
  if (YES == transport->isAvailable(proto)) {
    im->costSelector -= transport->getCost(proto);
    if ( (im->matchCount == 0) ||
	 (im->costSelector < 0) )
      im->match = *id;
    im->matchCount--;
  }
}

/**
 * Look in the list for known hosts; pick a random host of minimal
 * transport cost for the hosttable at index index. When called, the
 * mutex of at the given index must not be hold.
 *
 * @param index for which entry in the connection table
 *   are we looking for peers?
 */
static void scanForHosts(unsigned int index) {
  IndexMatch indexMatch;
  cron_t now;
#if DEBUG_TOPOLOGY
  EncName enc;
#endif

  if (getNetworkLoadUp() > 100)
    return; /* bandwidth saturated, do not
	       push it higher! */
  cronTime(&now);
  indexMatch.index = index;
  indexMatch.matchCount = 0;
  indexMatch.costSelector = 0;
  identity->forEachHost(now,
			&scanHelperCount,
			&indexMatch);
  if (indexMatch.matchCount == 0) {
    LOG(LOG_EVERYTHING,
	"No peers found for slot %u\n",
	index);
    return; /* no matching peers found! */
  }
  if (indexMatch.costSelector > 0)
    indexMatch.costSelector
      = randomi(indexMatch.costSelector/4)*4;
  indexMatch.match = *(coreAPI->myIdentity);
  identity->forEachHost(now,
			&scanHelperSelect,
			&indexMatch);
  if (hostIdentityEquals(coreAPI->myIdentity,
			 &indexMatch.match))
    return; /* should happen really rarely */
  if (coreAPI->computeIndex(&indexMatch.match) != index) {
    BREAK(); /* should REALLY not happen */
    return;
  }
#if DEBUG_TOPOLOGY
  hash2enc(&indexMatch.match.hashPubKey,
	   &enc);
  LOG(LOG_DEBUG,
      "Topology: trying to connect to `%s' in slot '%u'.\n",
      &enc,
      index);
#endif
  coreAPI->unicast(&indexMatch.match,
		   NULL,
		   0,
		   0);
  identity->blacklistHost(&indexMatch.match,
			  300 + (int) saturation * 600,
			  NO);
}

/**
 * We received a sign of life from this host.
 *
 * @param hostId the peer that gave a sign of live
 */
static void notifyPONG(PeerIdentity * hostId) {
#if DEBUG_TOPOLOGY
  EncName enc;

  hash2enc(&hostId->hashPubKey,
	   &enc);
  LOG(LOG_DEBUG,
      "Received pong from `%s', telling core that peer is still alive.\n",
      (char*)&enc);
#endif
  coreAPI->confirmSessionUp(hostId);
  FREE(hostId);
}

/**
 * Check the liveness of the ping and possibly ping it.
 */
static void checkNeedForPing(const PeerIdentity * peer,
			     void * unused) {
  cron_t now;
  cron_t act;
  PeerIdentity * hi;
#if DEBUG_TOPOLOGY
  EncName enc;
#endif

  if (weak_randomi(LIVE_PING_EFFECTIVENESS) != 0)
    return;
  cronTime(&now);
  if (SYSERR == coreAPI->getLastActivityOf(peer, &act)) {
    BREAK();
    return; /* this should not happen... */
  }

  if (now - act > SECONDS_PINGATTEMPT * cronSECONDS) {
    /* if we have less than 75% of the number of connections
       that we would like to have, try ping-ing the other side
       to keep the connection open instead of hanging up */
    hi = MALLOC(sizeof(PeerIdentity));
    *hi = *peer;
#if DEBUG_TOPOLOGY
    hash2enc(&hi->hashPubKey,
	     &enc);
    LOG(LOG_DEBUG,
	"Sending ping to `%s' to prevent connection timeout.\n",
	(char*)&enc);
#endif
    if (OK != pingpong->ping(peer,
			     NO,
			     (CronJob)&notifyPONG,
			     hi))
      FREE(hi);
  }
}

/**
 * Call this method periodically to decrease liveness of hosts.
 *
 * @param unused not used, just to make signature type nicely
 */
static void cronCheckLiveness(void * unused) {
  int i;
  int slotCount;
  int active;
  unsigned int minint;
  int autoconnect;

  autoconnect = testConfigurationString("GNUNETD",
					"DISABLE-AUTOCONNECT",
					"YES");
  slotCount = coreAPI->getSlotCount();
  if (saturation > 0.001)
    minint = (int) 1 / saturation;
  else
    minint = 10;
  if (minint == 0)
    minint = 1;
  for (i=slotCount-1;i>=0;i--) {
    if (weak_randomi(LIVE_SCAN_EFFECTIVENESS) != 0)
      continue;
    if ( (minint > coreAPI->isSlotUsed(i)) &&
	 (! autoconnect) )
      scanForHosts(i);
  }
  active = coreAPI->forAllConnectedNodes
    (&checkNeedForPing,
     NULL);
  saturation = 1.0 * active / slotCount;
}

static int estimateNetworkSize() {
  unsigned int active;
  unsigned int known;

  active = coreAPI->forAllConnectedNodes(NULL, NULL);
  if (active == 0)
    return 0;
  known = identity->forEachHost(0,
				NULL,
				NULL);
  if (active > known)
    return active; /* should not be possible */
  /* Assumption:
     if we only connect to X% of all machines
     that we know, we probably also only know X%
     of all peers that exist;

     Then the total number of machines is
     1/X * known, or known * known / active.

     Of course, we may know more than X% of the
     machines, in which case this estimate is too
     high.  Well, that is why it is an estimate :-).

     Example:
     - we connect to all machines we have ever heard
       of => network size == # active
     - we connect to only 1% of the machines we have
       heard of => network size = 100 * # active
  */
  if (known * known / active < known)
    return 0x7FFFFFFF; /* integer overflow, return max int */
  return known * known / active;
}

static double estimateSaturation() {
  return saturation;
}

static int allowConnection(const PeerIdentity * peer) {
  return OK; /* allow everything */
}

#define TOPOLOGY_TAG_FILE "topology-070"

Topology_ServiceAPI *
provide_module_topology_default(CoreAPIForApplication * capi) {
  static Topology_ServiceAPI api;
  char * data;
  unsigned int len;

  coreAPI = capi;
  identity = capi->requestService("identity");
  if (identity == NULL) {
    BREAK();
    return NULL;
  }
  transport = capi->requestService("transport");
  if (transport == NULL) {
    BREAK();
    capi->releaseService(identity);
    identity = NULL;
    return NULL;
  }
  pingpong = capi->requestService("pingpong");
  if (pingpong == NULL) {
    BREAK();
    capi->releaseService(identity);
    identity = NULL;
    capi->releaseService(transport);
    transport = NULL;
    return NULL;
  }

  addCronJob(&cronCheckLiveness,
	     LIVE_SCAN_FREQUENCY,
	     LIVE_SCAN_FREQUENCY,
	     NULL);

  if (-1 == (len = stateReadContent(TOPOLOGY_TAG_FILE,
				    (void**) &data))) {
    stateWriteContent(TOPOLOGY_TAG_FILE,
		      strlen(PACKAGE_VERSION),
		      PACKAGE_VERSION);
  } else {
    if (0 != strncmp(PACKAGE_VERSION,
		     data,
		     len)) {
      LOG(LOG_FAILURE,
	  _("Version mismatch (`%s' vs. '%*.s'), run gnunet-update!\n"),
	  PACKAGE_VERSION,
	  len,
	  data);
      FREE(data);
      delCronJob(&cronCheckLiveness,
		 LIVE_SCAN_FREQUENCY,
		 NULL);
      capi->releaseService(identity);
      identity = NULL;
      capi->releaseService(transport);
      transport = NULL;
      capi->releaseService(pingpong);
      pingpong = NULL;
      return NULL;
    }
    FREE(data);
  }

  api.estimateNetworkSize = &estimateNetworkSize;
  api.getSaturation = &estimateSaturation;
  api.allowConnectionFrom = &allowConnection;
  return &api;
}

int release_module_topology_default() {
  delCronJob(&cronCheckLiveness,
	     LIVE_SCAN_FREQUENCY,
	     NULL);
  coreAPI->releaseService(identity);
  identity = NULL;
  coreAPI->releaseService(transport);
  transport = NULL;
  coreAPI->releaseService(pingpong);
  pingpong = NULL;
  coreAPI = NULL;
  return OK;
}

/**
 * Update topology module.
 */
void update_module_topology_default(UpdateAPI * uapi) {
  stateUnlinkFromDB(TOPOLOGY_TAG_FILE);
  uapi->updateModule("identity");
  uapi->updateModule("transport");
  uapi->updateModule("pingpong");
}



static CoreAPIForApplication * myCapi;
static Topology_ServiceAPI * myTopology;

int initialize_module_topology_default(CoreAPIForApplication * capi) {
  myCapi = capi;
  myTopology = capi->requestService("topology");
  GNUNET_ASSERT(myTopology != NULL);
  return OK;
}

void done_module_topology_default() {
  myCapi->releaseService(myTopology);
  myCapi = NULL;
  myTopology = NULL;
}

/* end of topology.c */
