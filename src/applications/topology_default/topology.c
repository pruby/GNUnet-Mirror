/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006, 2007 Christian Grothoff (and other contributing authors)

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
#include "gnunet_directories.h"
#include "gnunet_protocols.h"
#include "gnunet_identity_service.h"
#include "gnunet_state_service.h"
#include "gnunet_topology_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_pingpong_service.h"

#define DEBUG_TOPOLOGY GNUNET_NO

#define DEBUG_LIVENESS GNUNET_NO

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

/**
 * How many peers are we connected to in relation
 * to our ideal number?  (ideal = 1.0, too few: < 1,
 * too many: > 1). Maybe 0!
 */
static double saturation = 0.0;

/**
 * Array of our friends.
 */
static GNUNET_PeerIdentity *friends;

/**
 * Number of friends that we have.
 */
static unsigned int friendCount;

/**
 * Minimum number of friends to have in the
 * connection set.
 */
static unsigned int minimum_friend_count;

/**
 * Flag to disallow non-friend connections (pure F2F mode).
 */
static int friends_only;



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
                 unsigned short proto, int confirmed, void *data)
{
  IndexMatch *im = data;

  if (0 == memcmp (coreAPI->my_identity, id, sizeof (GNUNET_PeerIdentity)))
    return GNUNET_OK;
  if (coreAPI->core_slot_index_get (id) != im->index)
    return GNUNET_OK;
  if (GNUNET_OK == coreAPI->p2p_connection_status_check (id, NULL, NULL))
    return GNUNET_OK;
  if (GNUNET_YES == transport->test_available (proto))
    {
      im->matchCount++;
      im->costSelector += transport->cost_get (proto);
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
                  unsigned short proto, int confirmed, void *data)
{
  IndexMatch *im = data;

  if (0 == memcmp (coreAPI->my_identity, id, sizeof (GNUNET_PeerIdentity)))
    return GNUNET_OK;
  if (coreAPI->core_slot_index_get (id) != im->index)
    return GNUNET_OK;
  if (GNUNET_OK == coreAPI->p2p_connection_status_check (id, NULL, NULL))
    return GNUNET_OK;
  if (GNUNET_YES == transport->test_available (proto))
    {
      im->costSelector -= transport->cost_get (proto);
      if ((im->matchCount == 0) || (im->costSelector < 0))
        {
          im->match = *id;
          return GNUNET_SYSERR;
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
 * @param index for which entry in the connection table
 *   are we looking for peers?
 */
static void
scanForHosts (unsigned int index)
{
  IndexMatch indexMatch;
  GNUNET_CronTime now;
#if DEBUG_TOPOLOGY
  GNUNET_EncName enc;
#endif

  if (GNUNET_network_monitor_get_load
      (coreAPI->load_monitor, GNUNET_ND_UPLOAD) > 100)
    return;                     /* bandwidth saturated, do not
                                   push it higher! */
  now = GNUNET_get_time ();
  indexMatch.index = index;
  indexMatch.matchCount = 0;
  indexMatch.costSelector = 0;
  identity->forEachHost (now, &scanHelperCount, &indexMatch);
  if (indexMatch.matchCount == 0)
    {
#if DEBUG_TOPOLOGY
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                     GNUNET_GE_DEVELOPER, "No peers found for slot %u\n",
                     index);
#endif
      return;                   /* no matching peers found! */
    }
  if (indexMatch.costSelector > 0)
    indexMatch.costSelector =
      GNUNET_random_u64 (GNUNET_RANDOM_QUALITY_WEAK, indexMatch.costSelector);
  indexMatch.match = *(coreAPI->my_identity);
  identity->forEachHost (now, &scanHelperSelect, &indexMatch);
  if (0 == memcmp (coreAPI->my_identity,
                   &indexMatch.match, sizeof (GNUNET_PeerIdentity)))
    return;                     /* should happen really rarely */
  if (coreAPI->core_slot_index_get (&indexMatch.match) != index)
    {
      GNUNET_GE_BREAK (NULL, 0);        /* should REALLY not happen */
      return;
    }
  if (GNUNET_OK ==
      coreAPI->p2p_connection_status_check (&indexMatch.match, NULL, NULL))
    {
      GNUNET_GE_BREAK (NULL, 0);        /* should REALLY not happen */
      return;
    }

#if DEBUG_TOPOLOGY
  IF_GELOG (coreAPI->ectx,
            GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER |
            GNUNET_GE_DEVELOPER,
            GNUNET_hash_to_enc (&indexMatch.match.hashPubKey, &enc));
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER |
                 GNUNET_GE_DEVELOPER, "Trying to connect to peer `%s'\n",
                 &enc);
#endif
  if (GNUNET_NO == identity->isBlacklisted (&indexMatch.match, GNUNET_YES))
    {
      coreAPI->ciphertext_send (&indexMatch.match, NULL, 0, 0);
      identity->blacklistHost (&indexMatch.match, (unsigned int) (saturation * 5 * 60 * 60),    /* 5 hours at full saturation */
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
#if DEBUG_TOPOLOGY || DEBUG_LIVENESS
  GNUNET_EncName enc;

  IF_GELOG (coreAPI->ectx,
            GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
            GNUNET_hash_to_enc (&hostId->hashPubKey, &enc));
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                 "Received liveness confirmation from `%s'.\n", &enc);
#endif

  coreAPI->p2p_connection_confirm (hostId);
  GNUNET_free (hostId);
}

/**
 * Check the liveness of the peer and possibly ping it.
 */
static void
checkNeedForPing (const GNUNET_PeerIdentity * peer, void *unused)
{
  GNUNET_CronTime now;
  GNUNET_CronTime act;
  GNUNET_PeerIdentity *hi;
  int ran;

  ran =
    GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, LIVE_PING_EFFECTIVENESS);
  if (ran != 0)
    return;
  now = GNUNET_get_time ();
  if (GNUNET_SYSERR == coreAPI->p2p_connection_last_activity_get (peer, &act))
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
      return;                   /* this should not happen... */
    }

  if (now - act > SECONDS_PINGATTEMPT * GNUNET_CRON_SECONDS)
    {
      /* if we have less than 75% of the number of connections
         that we would like to have, try ping-ing the other side
         to keep the connection open instead of hanging up */
#if DEBUG_TOPOLOGY || DEBUG_LIVENESS
      GNUNET_EncName enc;

      IF_GELOG (coreAPI->ectx,
                GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                GNUNET_hash_to_enc (&peer->hashPubKey, &enc));
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                     GNUNET_GE_DEVELOPER,
                     "Peer `%s' was inactive for %llus.  Sending PING.\n",
                     &enc, (now - act) / GNUNET_CRON_SECONDS);
#endif


      hi = GNUNET_malloc (sizeof (GNUNET_PeerIdentity));
      *hi = *peer;
      if (GNUNET_OK !=
          pingpong->ping (peer, &notifyPONG, hi, GNUNET_NO, rand ()))
        GNUNET_free (hi);
    }
}

#define MAX_PEERS_PER_SLOT 10

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
  unsigned int minint;
  int autoconnect;

  autoconnect = GNUNET_GC_get_configuration_value_yesno (coreAPI->cfg,
                                                         "GNUNETD",
                                                         "DISABLE-AUTOCONNECT",
                                                         GNUNET_NO);
  slotCount = coreAPI->core_slots_count ();
  if ((GNUNET_NO == autoconnect) && (saturation < 1))
    {
      if (saturation * MAX_PEERS_PER_SLOT >= 1)
        minint = (unsigned int) (1 / saturation);
      else
        minint = MAX_PEERS_PER_SLOT;    /* never put more than 10 peers into a slot */
      for (i = slotCount - 1; i >= 0; i--)
        {
          if (GNUNET_random_u32
              (GNUNET_RANDOM_QUALITY_WEAK, LIVE_SCAN_EFFECTIVENESS) != 0)
            continue;
          if (minint > coreAPI->core_slot_test_used (i))
            scanForHosts (i);
        }
    }
  active = coreAPI->p2p_connections_iterate (&checkNeedForPing, NULL);
  saturation = 1.0 * active / slotCount;
}

static int
estimateNetworkSize ()
{
  unsigned int active;
  unsigned int known;

  active = coreAPI->p2p_connections_iterate (NULL, NULL);
  if (active == 0)
    return 0;
  known = identity->forEachHost (0, NULL, NULL);
  if (active > known)
    return active;              /* should not be possible */
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
    return 0x7FFFFFFF;          /* integer overflow, return max int */
  return known * known / active;
}

static double
estimateSaturation ()
{
  return saturation;
}

static int
is_friend (const GNUNET_PeerIdentity * peer)
{
  unsigned int i;

  for (i = 0; i < friendCount; i++)
    if (0 == memcmp (&friends[i], peer, sizeof (GNUNET_PeerIdentity)))
      return 1;
  return 0;
}

static void
friend_counter (const GNUNET_PeerIdentity * peer, void *cls)
{
  unsigned int *cnt = cls;

  if (is_friend (peer))
    (*cnt)++;
}

static unsigned int
count_connected_friends (GNUNET_ConnectionIterator connectionIterator,
                         void *cls)
{
  unsigned int i;

  i = 0;
  connectionIterator (&friend_counter, &i, cls);
  return i;
}

static int
core_wrapper (GNUNET_NodeIteratorCallback callback,
              void *cb_arg, void *unused)
{
  return coreAPI->p2p_connections_iterate (callback, cb_arg);
}

static int
allowConnection (const GNUNET_PeerIdentity * peer)
{
  if ((coreAPI->my_identity != NULL) &&
      (0 ==
       memcmp (coreAPI->my_identity, peer, sizeof (GNUNET_PeerIdentity))))
    return GNUNET_SYSERR;       /* disallow connections to self */
  if (is_friend (peer))
    return GNUNET_OK;
  if (friends_only)
    return GNUNET_SYSERR;
  if (count_connected_friends (&core_wrapper, NULL) >= minimum_friend_count)
    return GNUNET_OK;
  return GNUNET_SYSERR;
}

/**
 * Would it be ok to drop the connection to this
 * peer?
 */
static int
isConnectionGuarded (const GNUNET_PeerIdentity * peer,
                     GNUNET_ConnectionIterator connectionIterator, void *cls)
{
  if (!is_friend (peer))
    return GNUNET_NO;
  if (count_connected_friends (connectionIterator, cls) <=
      minimum_friend_count)
    return GNUNET_YES;
  return GNUNET_NO;
}

static unsigned int
countGuardedConnections ()
{
  return minimum_friend_count;
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
  unsigned long long opt;

  if (0 != strcmp (section, "F2F"))
    return 0;
  friends_only = GNUNET_GC_get_configuration_value_yesno (cfg,
                                                          "F2F",
                                                          "FRIENDS-ONLY",
                                                          GNUNET_NO);
  if (friends_only == GNUNET_SYSERR)
    return GNUNET_SYSERR;       /* invalid */
  opt = 0;
  GNUNET_GC_get_configuration_value_number (cfg,
                                            "F2F",
                                            "MINIMUM",
                                            0, 1024 * 1024, 0, &opt);
  minimum_friend_count = (unsigned int) opt;
  GNUNET_array_grow (friends, friendCount, 0);
  fn = NULL;
  GNUNET_GC_get_configuration_value_filename (cfg,
                                              "F2F",
                                              "FRIENDS",
                                              GNUNET_DEFAULT_DAEMON_VAR_DIRECTORY
                                              "/friends", &fn);
        /**Nate change, don't beat me up if it's not pretty!*/
  if (GNUNET_OK != GNUNET_disk_file_test (ectx, fn))
    {
      GNUNET_disk_file_write (ectx, fn, NULL, 0, "600");
    }
  if ((0 == GNUNET_disk_file_test (ectx, fn))
      || (GNUNET_OK != GNUNET_disk_file_size (ectx, fn, &size, GNUNET_YES)))
    {
      GNUNET_free (fn);
      fn = NULL;
      if ((friends_only) || (minimum_friend_count > 0))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_USER | GNUNET_GE_ADMIN | GNUNET_GE_ERROR |
                         GNUNET_GE_IMMEDIATE,
                         _("Could not read friends list `%s'\n"), fn);
          return GNUNET_SYSERR;
        }
    }
  if ((fn != NULL) && (size > 0))
    {
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
      fn = NULL;
      pos = 0;
      while ((pos < size) && isspace (data[pos]))
        pos++;
      while ((size >= sizeof (GNUNET_EncName)) &&
             (pos <= size - sizeof (GNUNET_EncName)))
        {
          memcpy (&enc, &data[pos], sizeof (GNUNET_EncName));
          if (!isspace (enc.encoding[sizeof (GNUNET_EncName) - 1]))
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_WARNING | GNUNET_GE_BULK |
                             GNUNET_GE_USER,
                             _
                             ("Syntax error in topology specification, skipping bytes.\n"));
              pos++;
              while ((pos < size) && (!isspace (data[pos])))
                pos++;
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
                             GNUNET_GE_WARNING | GNUNET_GE_BULK |
                             GNUNET_GE_USER,
                             _
                             ("Syntax error in topology specification, skipping bytes `%s'.\n"),
                             &enc);
            }
          pos = pos + sizeof (GNUNET_EncName);
          while ((pos < size) && isspace (data[pos]))
            pos++;
        }
      if ((minimum_friend_count > friendCount) && (friends_only == GNUNET_NO))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _
                         ("Fewer friends specified than required by minimum friend count. Will only connect to friends.\n"));
        }
      if ((minimum_friend_count >
           coreAPI->core_slots_count ()) && (friends_only == GNUNET_NO))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _
                         ("More friendly connections required than target total number of connections.\n"));
        }
      GNUNET_free (data);
    }
  GNUNET_free_non_null (fn);
  return 0;
}


GNUNET_Topology_ServiceAPI *
provide_module_topology_default (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_Topology_ServiceAPI api;

  coreAPI = capi;
  identity = capi->service_request ("identity");
  if (identity == NULL)
    {
      GNUNET_GE_BREAK (capi->ectx, 0);
      return NULL;
    }
  transport = capi->service_request ("transport");
  if (transport == NULL)
    {
      GNUNET_GE_BREAK (capi->ectx, 0);
      capi->service_release (identity);
      identity = NULL;
      return NULL;
    }
  pingpong = capi->service_request ("pingpong");
  if (pingpong == NULL)
    {
      GNUNET_GE_BREAK (capi->ectx, 0);
      capi->service_release (identity);
      identity = NULL;
      capi->service_release (transport);
      transport = NULL;
      return NULL;
    }
  if (0 != GNUNET_GC_attach_change_listener (coreAPI->cfg,
                                             &rereadConfiguration, NULL))
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
      capi->service_release (identity);
      identity = NULL;
      capi->service_release (transport);
      transport = NULL;
      capi->service_release (pingpong);
      pingpong = NULL;
      return NULL;
    }
  GNUNET_cron_add_job (capi->cron,
                       &cronCheckLiveness,
                       LIVE_SCAN_FREQUENCY, LIVE_SCAN_FREQUENCY, NULL);
  api.estimateNetworkSize = &estimateNetworkSize;
  api.getSaturation = &estimateSaturation;
  api.allowConnectionFrom = &allowConnection;
  api.isConnectionGuarded = &isConnectionGuarded;
  api.countGuardedConnections = &countGuardedConnections;
  return &api;
}

int
release_module_topology_default ()
{
  GNUNET_cron_del_job (coreAPI->cron, &cronCheckLiveness, LIVE_SCAN_FREQUENCY,
                       NULL);
  GNUNET_GC_detach_change_listener (coreAPI->cfg, &rereadConfiguration, NULL);
  coreAPI->service_release (identity);
  identity = NULL;
  coreAPI->service_release (transport);
  transport = NULL;
  coreAPI->service_release (pingpong);
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
  uapi->service_update ("state");
  uapi->service_update ("identity");
  uapi->service_update ("transport");
  uapi->service_update ("pingpong");
}

static GNUNET_CoreAPIForPlugins *myCapi;

static GNUNET_Topology_ServiceAPI *myTopology;

int
initialize_module_topology_default (GNUNET_CoreAPIForPlugins * capi)
{
  myCapi = capi;
  myTopology = capi->service_request ("topology");
  GNUNET_GE_ASSERT (capi->ectx, myTopology != NULL);
  GNUNET_GE_ASSERT (capi->ectx,
                    0 == GNUNET_GC_set_configuration_value_string (capi->cfg,
                                                                   capi->ectx,
                                                                   "ABOUT",
                                                                   "topology",
                                                                   gettext_noop
                                                                   ("maintains GNUnet default mesh topology")));
  return GNUNET_OK;
}

void
done_module_topology_default ()
{
  myCapi->service_release (myTopology);
  myCapi = NULL;
  myTopology = NULL;
}

/* end of topology.c */
