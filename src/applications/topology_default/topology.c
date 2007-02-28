/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
#include "gnunet_state_service.h"
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
static int scanHelperCount(const PeerIdentity * id,
			   unsigned short proto,	
			   int confirmed,
			   void * data) {
  IndexMatch * im = data;

  if (0 == memcmp(coreAPI->myIdentity,
		  id,
		  sizeof(PeerIdentity)))
    return OK;
  if (coreAPI->computeIndex(id) != im->index)
    return OK;
  if (0 != coreAPI->queryBPMfromPeer(id))
    return OK;
  if (YES == transport->isAvailable(proto)) {
    im->matchCount++;
    im->costSelector += transport->getCost(proto);
  }
  return OK;
}

/**
 * Select the peer and transport that was selected based on transport
 * cost.
 *
 * @param id the current peer
 * @param proto the protocol of the current peer
 * @param im structure responsible for the selection process
 */
static int scanHelperSelect(const PeerIdentity * id,
			    unsigned short proto,
			    int confirmed,
			    void * data) {
  IndexMatch * im = data;

  if (0 == memcmp(coreAPI->myIdentity,
		  id,
		  sizeof(PeerIdentity)))
    return OK;
  if (coreAPI->computeIndex(id) != im->index)
    return OK;
  if (0 != coreAPI->queryBPMfromPeer(id))
    return OK;
  if (YES == transport->isAvailable(proto)) {
    im->costSelector -= transport->getCost(proto);
    if ( (im->matchCount == 0) ||
	 (im->costSelector < 0) ) {
      im->match = *id;
      return SYSERR;
    }
    im->matchCount--;
  }
  return OK;
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

  if (os_network_monitor_get_load(coreAPI->load_monitor,
				  Upload) > 100)
    return; /* bandwidth saturated, do not
	       push it higher! */
  now = get_time();
  indexMatch.index = index;
  indexMatch.matchCount = 0;
  indexMatch.costSelector = 0;
  identity->forEachHost(now,
			&scanHelperCount,
			&indexMatch);
  if (indexMatch.matchCount == 0) {
#if DEBUG_TOPOLOGY
    GE_LOG(coreAPI->ectx,
	   GE_DEBUG | GE_REQUEST | GE_DEVELOPER,
	   "No peers found for slot %u\n",
	   index);
#endif
    return; /* no matching peers found! */
  }
  if (indexMatch.costSelector > 0)
    indexMatch.costSelector
      = weak_randomi(indexMatch.costSelector/4)*4;
  indexMatch.match = *(coreAPI->myIdentity);
  identity->forEachHost(now,
			&scanHelperSelect,
			&indexMatch);
  if (0 == memcmp(coreAPI->myIdentity,
		  &indexMatch.match,
		  sizeof(PeerIdentity)))
    return; /* should happen really rarely */
  if (coreAPI->computeIndex(&indexMatch.match) != index) {
    GE_BREAK(NULL, 0); /* should REALLY not happen */
    return;
  }
#if DEBUG_TOPOLOGY
  IF_GELOG(coreAPI->ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER | GE_DEVELOPER,
	   hash2enc(&indexMatch.match.hashPubKey,
		    &enc));
  GE_LOG(coreAPI->ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER | GE_DEVELOPER,
	 "Trying to connect to peer `%s'\n",
	 &enc);
#endif
  coreAPI->unicast(&indexMatch.match,
		   NULL,
		   0,
		   0);
  identity->blacklistHost(&indexMatch.match,
			  600 + (int) (saturation * 600),
			  NO);
}

/**
 * We received a sign of life from this host.
 *
 * @param hostId the peer that gave a sign of live
 */
static void notifyPONG(void * cls) {
  PeerIdentity * hostId = cls;
  coreAPI->confirmSessionUp(hostId);
  FREE(hostId);
}

/**
 * Check the liveness of the peer and possibly ping it.
 */
static void checkNeedForPing(const PeerIdentity * peer,
			     void * unused) {
  cron_t now;
  cron_t act;
  PeerIdentity * hi;

  if (weak_randomi(LIVE_PING_EFFECTIVENESS) != 0)
    return;
  now = get_time();
  if (SYSERR == coreAPI->getLastActivityOf(peer, &act)) {
    GE_BREAK(coreAPI->ectx, 0);
    return; /* this should not happen... */
  }

  if (now - act > SECONDS_PINGATTEMPT * cronSECONDS) {
    /* if we have less than 75% of the number of connections
       that we would like to have, try ping-ing the other side
       to keep the connection open instead of hanging up */
    hi = MALLOC(sizeof(PeerIdentity));
    *hi = *peer;
    if (OK != pingpong->ping(peer,
			     &notifyPONG,
			     hi,
			     NO,
			     rand()))
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

  autoconnect = GC_get_configuration_value_yesno(coreAPI->cfg,
						 "GNUNETD",
						 "DISABLE-AUTOCONNECT",
						 NO);
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
	 (NO == autoconnect) )
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
  if ( (coreAPI->myIdentity != NULL) &&
       (0 == memcmp(coreAPI->myIdentity,
		    peer,
		    sizeof(PeerIdentity))) )
    return SYSERR; /* disallow connections to self */
  return OK; /* allow everything else */
}

Topology_ServiceAPI *
provide_module_topology_default(CoreAPIForApplication * capi) {
  static Topology_ServiceAPI api;

  coreAPI = capi;
  identity = capi->requestService("identity");
  if (identity == NULL) {
    GE_BREAK(capi->ectx, 0);
    return NULL;
  }
  transport = capi->requestService("transport");
  if (transport == NULL) {
    GE_BREAK(capi->ectx, 0);
    capi->releaseService(identity);
    identity = NULL;
    return NULL;
  }
  pingpong = capi->requestService("pingpong");
  if (pingpong == NULL) {
    GE_BREAK(capi->ectx, 0);
    capi->releaseService(identity);
    identity = NULL;
    capi->releaseService(transport);
    transport = NULL;
    return NULL;
  }
  cron_add_job(capi->cron,
	       &cronCheckLiveness,
	       LIVE_SCAN_FREQUENCY,
	       LIVE_SCAN_FREQUENCY,
	       NULL);
  api.estimateNetworkSize = &estimateNetworkSize;
  api.getSaturation = &estimateSaturation;
  api.allowConnectionFrom = &allowConnection;
  return &api;
}

int release_module_topology_default() {
  cron_del_job(coreAPI->cron,
	       &cronCheckLiveness,
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

#define TOPOLOGY_TAG_FILE "topology-070"

/**
 * Update topology module.
 */
void update_module_topology_default(UpdateAPI * uapi) {
  State_ServiceAPI * state;

  uapi->updateModule("state");
  uapi->updateModule("identity");
  uapi->updateModule("transport");
  uapi->updateModule("pingpong");

  /* remove version stamp file from 0.7.0x,
     we have a global check for version, so
     we do not need this one anymore;
     this code can be removed in a few
     versions (since it is just minor cleanup
     anyway) */
  state = uapi->requestService("state");
  state->unlink(NULL,
		TOPOLOGY_TAG_FILE);
  uapi->releaseService(state);
  state = NULL;
}

static CoreAPIForApplication * myCapi;

static Topology_ServiceAPI * myTopology;

int initialize_module_topology_default(CoreAPIForApplication * capi) {
  myCapi = capi;
  myTopology = capi->requestService("topology");
  GE_ASSERT(capi->ectx,
	    myTopology != NULL);
  GE_ASSERT(capi->ectx,
	    0 == GC_set_configuration_value_string(capi->cfg,
						   capi->ectx,
						   "ABOUT",
						   "topology",
						   gettext_noop("maintains GNUnet default mesh topology")));
  return OK;
}

void done_module_topology_default() {
  myCapi->releaseService(myTopology);
  myCapi = NULL;
  myTopology = NULL;
}

/* end of topology.c */
