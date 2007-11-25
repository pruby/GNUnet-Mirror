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
 * @file topology_f2f/topology.c
 * @brief create the GNUnet F2F topology (essentially,
 *   try to connect to friends only)
 * @author Christian Grothoff
 *
 * Topology is implemented as both a service and an
 * application to allow users to force loading it
 * (which is probably a very good idea -- otherwise
 * the peer will end up rather disconnected :-)
 */

#include "platform.h"
#include "gnunet_core.h"
#include "gnunet_directories.h"
#include "gnunet_protocols.h"
#include "gnunet_topology_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_pingpong_service.h"

#define DEBUG_TOPOLOGY GNUNET_NO

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
#define LIVE_SCAN_FREQUENCY 500 * GNUNET_CRON_MILLISECONDS

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

static GNUNET_CoreAPIForPlugins *coreAPI;

static GNUNET_Identity_ServiceAPI *identity;

static GNUNET_Transport_ServiceAPI *transport;

static GNUNET_Pingpong_ServiceAPI *pingpong;

static struct GNUNET_GE_Context *ectx;

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
typedef struct
{
  unsigned int index;
  unsigned int matchCount;
  long long costSelector;
  GNUNET_PeerIdentity match;
} IndexMatch;

static GNUNET_PeerIdentity *friends;
static unsigned int friendCount;

static int
allowConnection (const GNUNET_PeerIdentity * peer)
{
  int i;

  if ((coreAPI->myIdentity != NULL) &&
      (0 == memcmp (coreAPI->myIdentity, peer, sizeof (GNUNET_PeerIdentity))))
    return GNUNET_SYSERR;       /* disallow connections to self */
  for (i = friendCount - 1; i >= 0; i--)
    if (0 == memcmp (&friends[i], peer, sizeof (GNUNET_PeerIdentity)))
      return GNUNET_OK;
  return GNUNET_SYSERR;
}

/**
 * Here in this scanning for applicable hosts, we also want to take
 * the protocols into account and prefer "cheap" protocols,
 * i.e. protocols with a low overhead.
 *
 * @param id which peer are we currently looking at
 * @param proto what transport protocol are we looking at
 * @param im updated structure used to select the peer
 */
static int
scanHelperCount (const GNUNET_PeerIdentity * id,
                 unsigned short proto, int confirmed, void *cls)
{
  IndexMatch *im = cls;

  if (0 == memcmp (coreAPI->myIdentity, id, sizeof (GNUNET_PeerIdentity)))
    return GNUNET_OK;
  if (coreAPI->computeIndex (id) != im->index)
    return GNUNET_OK;
  if (GNUNET_OK == coreAPI->queryPeerStatus (id, NULL, NULL))
    return GNUNET_OK;
  if ((GNUNET_YES == transport->isAvailable (proto))
      && (GNUNET_OK == allowConnection (id)))
    {
      im->matchCount++;
      im->costSelector += transport->getCost (proto);
    }
  return GNUNET_OK;
}

/**
 * Select the peer and transport that was selected based on transport
 * cost.
 *
 * @param id the current peer
 * @param proto the protocol of the current peer
 * @param im structure responsible for the selection process
 */
static int
scanHelperSelect (const GNUNET_PeerIdentity * id,
                  const unsigned short proto, int confirmed, void *cls)
{
  IndexMatch *im = cls;
  if (0 == memcmp (coreAPI->myIdentity, id, sizeof (GNUNET_PeerIdentity)))
    return GNUNET_OK;
  if (coreAPI->computeIndex (id) != im->index)
    return GNUNET_OK;
  if (GNUNET_OK == coreAPI->queryPeerStatus (id, NULL, NULL))
    return GNUNET_OK;
  if ((GNUNET_OK == allowConnection (id))
      && (GNUNET_YES == transport->isAvailable (proto)))
    {
      im->costSelector -= transport->getCost (proto);
      if ((im->matchCount == 0) || (im->costSelector < 0))
        {
          im->match = *id;
          return GNUNET_SYSERR; /* abort iteration */
        }
      im->matchCount--;
    }
  return GNUNET_OK;
}

/**
 * Look in the list for known hosts; pick a random host of minimal
 * transport cost for the hosttable at index index. When called, the
 * mutex of at the given index must not be hold.
 *
 * @param index for which entry in the connection table are we looking for peers?
 */
static void
scanForHosts (unsigned int index)
{
  IndexMatch indexMatch;
  GNUNET_CronTime now;
#if DEBUG_TOPOLOGY
  GNUNET_EncName enc;
#endif

  now = GNUNET_get_time ();
  indexMatch.index = index;
  indexMatch.matchCount = 0;
  indexMatch.costSelector = 0;
  identity->forEachHost (now, &scanHelperCount, &indexMatch);
  if (indexMatch.matchCount == 0)
    return;                     /* no matching peers found! */
  if (indexMatch.costSelector > 0)
    indexMatch.costSelector =
      GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                         indexMatch.costSelector / 4) * 4;
  indexMatch.match = *(coreAPI->myIdentity);
  identity->forEachHost (now, &scanHelperSelect, &indexMatch);
  if (0 == memcmp (coreAPI->myIdentity,
                   &indexMatch.match, sizeof (GNUNET_PeerIdentity)))
    {
      GNUNET_GE_BREAK (ectx, 0);        /* should not happen, at least not often... */
      return;
    }
  if (coreAPI->computeIndex (&indexMatch.match) != index)
    {
      GNUNET_GE_BREAK (ectx, 0);        /* should REALLY not happen */
      return;
    }
#if DEBUG_TOPOLOGY
  IF_GELOG (ectx,
            GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&indexMatch.match.hashPubKey, &enc));
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Topology: trying to connect to `%s'.\n", &enc);
#endif
  if (GNUNET_NO == identity->isBlacklisted (&indexMatch.match, GNUNET_YES))
    {
      coreAPI->unicast (&indexMatch.match, NULL, 0, 0);
      identity->blacklistHost (&indexMatch.match, (unsigned int) 5 * 60 * 60 * saturation,      /* 5h at full saturation */
                               GNUNET_NO);
    }
}

/**
 * We received a GNUNET_RSA_sign of life from this host.
 *
 * @param hostId the peer that gave a GNUNET_RSA_sign of live
 */
static void
notifyPONG (void *cls)
{
  GNUNET_PeerIdentity *hostId = cls;
#if DEBUG_TOPOLOGY
  GNUNET_EncName enc;

  GNUNET_hash_to_enc (&hostId->hashPubKey, &enc);
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Received pong from `%s', telling core that peer is still alive.\n",
                 (char *) &enc);
#endif
  coreAPI->confirmSessionUp (hostId);
  GNUNET_free (hostId);
}

/**
 * Check the liveness of the ping and possibly ping it.
 */
static void
checkNeedForPing (const GNUNET_PeerIdentity * peer, void *unused)
{
  GNUNET_CronTime now;
  GNUNET_CronTime act;
#if DEBUG_TOPOLOGY
  GNUNET_EncName enc;
#endif

  if (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, LIVE_PING_EFFECTIVENESS)
      != 0)
    return;
  now = GNUNET_get_time ();
  if (GNUNET_SYSERR == coreAPI->getLastActivityOf (peer, &act))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return;                   /* this should not happen... */
    }

  if (now - act > SECONDS_PINGATTEMPT * GNUNET_CRON_SECONDS)
    {
      /* if we have less than 75% of the number of connections
         that we would like to have, try ping-ing the other side
         to keep the connection open instead of hanging up */
      GNUNET_PeerIdentity *hi = GNUNET_malloc (sizeof (GNUNET_PeerIdentity));
      *hi = *peer;
#if DEBUG_TOPOLOGY
      GNUNET_hash_to_enc (&hi->hashPubKey, &enc);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Sending ping to `%s' to prevent connection timeout.\n",
                     (char *) &enc);
#endif
      if (GNUNET_OK !=
          pingpong->ping (peer, &notifyPONG, hi, GNUNET_NO, rand ()))
        GNUNET_free (hi);
    }
}

/**
 * Call this method periodically to decrease liveness of hosts.
 *
 * @param unused not used, just to make signature type nicely
 */
static void
cronCheckLiveness (void *unused)
{
  int i;
  int slotCount;
  int active;
  int autoconnect;

  autoconnect = GNUNET_GC_get_configuration_value_yesno (coreAPI->cfg,
                                                         "GNUNETD",
                                                         "DISABLE-AUTOCONNECT",
                                                         GNUNET_NO);
  slotCount = coreAPI->getSlotCount ();
  if ((GNUNET_NO == autoconnect) && (saturation < 1))
    {
      for (i = slotCount - 1; i >= 0; i--)
        {
          if (GNUNET_random_u32
              (GNUNET_RANDOM_QUALITY_WEAK, LIVE_SCAN_EFFECTIVENESS) != 0)
            continue;
          if (0 == coreAPI->isSlotUsed (i))
            scanForHosts (i);
        }
    }
  active = coreAPI->forAllConnectedNodes (&checkNeedForPing, NULL);
  saturation = 1.0 * active / slotCount;
}

static int
estimateNetworkSize ()
{
  return friendCount;
}

static double
estimateSaturation ()
{
  return saturation;
}

/**
 * @return 0 on success.
 */
static int
rereadConfiguration (void *ctx,
                     struct GNUNET_GC_Configuration *cfg,
                     struct GNUNET_GE_Context *ectx,
                     const char *section, const char *option)
{
  char *fn;
  char *data;
  unsigned long long size;
  size_t pos;
  GNUNET_EncName enc;
  GNUNET_HashCode hc;

  if (0 != strcmp (section, "F2F"))
    return 0;
  GNUNET_array_grow (friends, friendCount, 0);
  fn = NULL;
  GNUNET_GC_get_configuration_value_filename (cfg,
                                              "F2F",
                                              "FRIENDS",
                                              GNUNET_DEFAULT_DAEMON_VAR_DIRECTORY
                                              "/friends", &fn);
  if ((0 == GNUNET_disk_file_test (ectx, fn))
      || (GNUNET_OK != GNUNET_disk_file_size (ectx, fn, &size, GNUNET_YES)))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_USER | GNUNET_GE_ADMIN | GNUNET_GE_ERROR |
                     GNUNET_GE_IMMEDIATE,
                     "Could not read friends list `%s'\n", fn);
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  data = GNUNET_malloc (size);
  if (size != GNUNET_disk_file_read (ectx, fn, size, data))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Failed to read friends list from `%s'\n"), fn);
      GNUNET_free (fn);
      GNUNET_free (data);
      return GNUNET_SYSERR;
    }
  GNUNET_free (fn);
  pos = 0;
  while ((pos < size) && isspace (data[pos]))
    pos++;
  while (pos <= size - sizeof (GNUNET_EncName))
    {
      memcpy (&enc, &data[pos], sizeof (GNUNET_EncName));
      if (!isspace (enc.encoding[sizeof (GNUNET_EncName) - 1]))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _
                         ("Syntax error in topology specification, skipping bytes.\n"));
          continue;
        }
      enc.encoding[sizeof (GNUNET_EncName) - 1] = '\0';
      if (GNUNET_OK == GNUNET_enc_to_hash ((char *) &enc, &hc))
        {
          GNUNET_array_grow (friends, friendCount, friendCount + 1);
          friends[friendCount - 1].hashPubKey = hc;
        }
      else
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _
                         ("Syntax error in topology specification, skipping bytes `%s'.\n"),
                         &enc);
        }
      pos = pos + sizeof (GNUNET_EncName);
      while ((pos < size) && isspace (data[pos]))
        pos++;
    }
  return 0;
}

GNUNET_Topology_ServiceAPI *
provide_module_topology_f2f (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_Topology_ServiceAPI api;

  coreAPI = capi;
  ectx = capi->ectx;
  identity = capi->requestService ("identity");
  if (identity == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return NULL;
    }
  transport = capi->requestService ("transport");
  if (transport == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      capi->releaseService (identity);
      identity = NULL;
      return NULL;
    }
  pingpong = capi->requestService ("pingpong");
  if (pingpong == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      capi->releaseService (identity);
      identity = NULL;
      capi->releaseService (transport);
      transport = NULL;
      return NULL;
    }
  if (0 != GNUNET_GC_attach_change_listener (coreAPI->cfg,
                                             &rereadConfiguration, NULL))
    {
      GNUNET_GE_BREAK (ectx, 0);
      capi->releaseService (identity);
      identity = NULL;
      capi->releaseService (transport);
      transport = NULL;
      capi->releaseService (pingpong);
      pingpong = NULL;
      return NULL;
    }

  GNUNET_cron_add_job (coreAPI->cron,
                       &cronCheckLiveness,
                       LIVE_SCAN_FREQUENCY, LIVE_SCAN_FREQUENCY, NULL);
  api.estimateNetworkSize = &estimateNetworkSize;
  api.getSaturation = &estimateSaturation;
  api.allowConnectionFrom = &allowConnection;
  return &api;
}

int
release_module_topology_f2f ()
{
  GNUNET_cron_del_job (coreAPI->cron, &cronCheckLiveness, LIVE_SCAN_FREQUENCY,
                       NULL);
  GNUNET_GC_detach_change_listener (coreAPI->cfg, &rereadConfiguration, NULL);
  coreAPI->releaseService (identity);
  identity = NULL;
  coreAPI->releaseService (transport);
  transport = NULL;
  coreAPI->releaseService (pingpong);
  pingpong = NULL;
  coreAPI = NULL;
  GNUNET_array_grow (friends, friendCount, 0);
  return GNUNET_OK;
}

/**
 * Update topology module.
 */
void
update_module_topology_default (GNUNET_UpdateAPI * uapi)
{
  uapi->updateModule ("state");
  uapi->updateModule ("identity");
  uapi->updateModule ("transport");
  uapi->updateModule ("pingpong");
}

static GNUNET_CoreAPIForPlugins *myCapi;

static GNUNET_Topology_ServiceAPI *myTopology;

int
initialize_module_topology_f2f (GNUNET_CoreAPIForPlugins * capi)
{
  myCapi = capi;
  myTopology = capi->requestService ("topology");
  GNUNET_GE_ASSERT (ectx, myTopology != NULL);
  GNUNET_GE_ASSERT (capi->ectx,
                    0 == GNUNET_GC_set_configuration_value_string (capi->cfg,
                                                                   capi->ectx,
                                                                   "ABOUT",
                                                                   "topology",
                                                                   gettext_noop
                                                                   ("maintains a friend-to-friend restricted topology")));
  return GNUNET_OK;
}

void
done_module_topology_f2f ()
{
  myCapi->releaseService (myTopology);
  myCapi = NULL;
  myTopology = NULL;
}

/* end of topology.c */
