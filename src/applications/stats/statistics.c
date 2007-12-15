/*
  This file is part of GNUnet.
  (C) 2001, 2002, 2004, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/stats/statistics.c
 * @brief keeping statistics of GNUnet activities
 * @author Christian Grothoff
 *
 * This module keeps a mapping of strings to (unsigned long long)
 * values. Every entry in the mapping can be accessed with a handle
 * (int) which can be obtained from the string. The module can be used
 * to keep track of certain statistical information, such as the
 * number of bytes received, messages sent, kilobytes stored, and so
 * on.<p>
 *
 * When loaded by gnunetd, the gnunet-stats tool can be used to
 * print the statistical information stored in this module.
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_core.h"
#include "gnunet_protocols.h"
#include "gnunet_stats_service.h"
#include "statistics.h"

/**
 * Should we generate *very* costly statistics about
 * the SQStore?  Only set to GNUNET_YES for debugging, never
 * in production!
 */
#define HAVE_SQSTATS GNUNET_NO

/* *************** service *************** */

/**
 * When did the module start?
 */
static GNUNET_CronTime startTime;

struct StatEntry
{
  unsigned long long value;
  char *description;
  unsigned int descStrLen;
};

static struct StatEntry *entries;

/**
 * Size of the entries array
 */
static unsigned int statCounters;

/**
 * lock for the stat module
 */
static struct GNUNET_Mutex *statLock;

/**
 * The core API.
 */
static GNUNET_CoreAPIForPlugins *coreAPI;

/**
 * Get a handle to a statistical entity.
 *
 * @param name a description of the entity
 * @return a handle for updating the associated value
 */
static int
statHandle (const char *name)
{
  int i;
  GNUNET_GE_ASSERT (NULL, name != NULL);
  GNUNET_mutex_lock (statLock);
  for (i = 0; i < statCounters; i++)
    if (0 == strcmp (entries[i].description, name))
      {
        GNUNET_mutex_unlock (statLock);
        return i;
      }
  GNUNET_array_grow (entries, statCounters, statCounters + 1);
  entries[statCounters - 1].description = GNUNET_strdup (name);
  entries[statCounters - 1].descStrLen = strlen (name);
  entries[statCounters - 1].value = 0;
  GNUNET_mutex_unlock (statLock);
  return statCounters - 1;
}

/**
 * Manipulate statistics. Sets the statistics associated with the
 * handle to value.
 *
 * @param handle the handle for the value to change
 * @param value to what the value should be set
 */
static void
statSet (const int handle, const unsigned long long value)
{
  GNUNET_mutex_lock (statLock);
  if ((handle < 0) || (handle >= statCounters))
    {
      GNUNET_GE_BREAK (NULL, 0);
      GNUNET_mutex_unlock (statLock);
      return;
    }
  entries[handle].value = value;
  GNUNET_mutex_unlock (statLock);
}

static unsigned long long
statGet (const int handle)
{
  unsigned long long ret;
  GNUNET_mutex_lock (statLock);
  if ((handle < 0) || (handle >= statCounters))
    {
      GNUNET_GE_BREAK (NULL, 0);
      GNUNET_mutex_unlock (statLock);
      return -1;
    }
  ret = entries[handle].value;
  GNUNET_mutex_unlock (statLock);
  return ret;
}

/**
 * Manipulate statistics. Changes the statistics associated with the
 * value by delta.
 *
 * @param handle the handle for the value to change
 * @param delta by how much should the value be changed
 */
static void
statChange (const int handle, const int delta)
{
  GNUNET_mutex_lock (statLock);
  if ((handle < 0) || (handle >= statCounters))
    {
      GNUNET_GE_BREAK (NULL, 0);
      GNUNET_mutex_unlock (statLock);
      return;
    }
  entries[handle].value += delta;
  GNUNET_mutex_unlock (statLock);
}


/**
 * Shutdown the statistics module.
 */
void
release_module_stats ()
{
  int i;

  GNUNET_mutex_destroy (statLock);
  for (i = 0; i < statCounters; i++)
    GNUNET_free (entries[i].description);
  GNUNET_array_grow (entries, statCounters, 0);
}


/**
 * Initialize the statistics module.
 */
GNUNET_Stats_ServiceAPI *
provide_module_stats (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_Stats_ServiceAPI api;

  coreAPI = capi;
  api.create = &statHandle;
  api.set = &statSet;
  api.change = &statChange;
  api.get = &statGet;
  startTime = GNUNET_get_time ();
  statLock = GNUNET_mutex_create (GNUNET_YES);
  return &api;
}


/* *************** protocol *************** */

/* ********* special stats that are updated
   always just before we send the reply ******* */

static int stat_handle_network_load_up;
static int stat_handle_network_load_down;
static int stat_handle_cpu_load;
static int stat_handle_io_load;
static int stat_bytes_noise_received;
static int stat_connected;
#ifdef MINGW
static int stat_handles;
#endif
static GNUNET_Stats_ServiceAPI *stats;
static GNUNET_CoreAPIForPlugins *myCoreAPI;

#if HAVE_SQSTATS
#include "sqstats.c"
#endif

extern unsigned int uiHandleCount;

static void
initializeStats ()
{
  stat_handle_network_load_up
    = statHandle (gettext_noop ("% of allowed network load (up)"));
  stat_handle_network_load_down
    = statHandle (gettext_noop ("% of allowed network load (down)"));
  stat_handle_cpu_load = statHandle (gettext_noop ("% of allowed cpu load"));
  stat_handle_io_load = statHandle (gettext_noop ("% of allowed io load"));
  stat_connected = statHandle (gettext_noop ("# of connected peers"));
  stat_bytes_noise_received
    = statHandle (gettext_noop ("# bytes of noise received"));
#ifdef MINGW
  stat_handles = statHandle (gettext_noop ("# plibc handles"));
#endif
}

static void
immediateUpdates ()
{
  int load;

#if HAVE_SQSTATS
  update_sqstore_stats ();
#endif
  load = GNUNET_cpu_get_load (coreAPI->ectx, coreAPI->cfg);
  if (load == -1)
    load = 0;
  statSet (stat_handle_cpu_load, load);
  load = GNUNET_disk_get_load (coreAPI->ectx, coreAPI->cfg);
  if (load == -1)
    load = 0;
  statSet (stat_handle_io_load, load);
  load =
    GNUNET_network_monitor_get_load (coreAPI->load_monitor, GNUNET_ND_UPLOAD);
  if (load == -1)
    load = 0;
  statSet (stat_handle_network_load_up, load);
  load =
    GNUNET_network_monitor_get_load (coreAPI->load_monitor,
                                     GNUNET_ND_DOWNLOAD);
  if (load == -1)
    load = 0;
  statSet (stat_handle_network_load_down, load);
  statSet (stat_connected, coreAPI->forAllConnectedNodes (NULL, NULL));
#ifdef MINGW
  statSet (stat_handles, plibc_get_handle_count ());
#endif
}


/**
 * Send statistics to a TCP socket.  May send multiple messages if the
 * overall size would be too big otherwise.
 *
 * @param originalRequestMessage ignored at this point.
 */
static int
sendStatistics (struct GNUNET_ClientHandle *sock,
                const GNUNET_MessageHeader * originalRequestMessage)
{
  CS_stats_reply_MESSAGE *statMsg;
  int pos;                      /* position in the values-descriptions */
  int start;
  int end;
  int mpos;                     /* postion in the message */

  immediateUpdates ();
  statMsg = GNUNET_malloc (GNUNET_MAX_BUFFER_SIZE);
  statMsg->header.type = htons (GNUNET_CS_PROTO_STATS_STATISTICS);
  statMsg->totalCounters = htonl (statCounters);
  statMsg->statCounters = htons (0);
  statMsg->startTime = GNUNET_htonll (startTime);

  start = 0;
  while (start < statCounters)
    {
      pos = start;
      /* first pass: gauge how many statistic numbers
         and their descriptions we can send in one message */
      mpos = 0;
      while ((pos < statCounters) &&
             (mpos + sizeof (unsigned long long)
              + entries[pos].descStrLen + 1
              < GNUNET_MAX_BUFFER_SIZE - sizeof (CS_stats_reply_MESSAGE)))
        {
          mpos += sizeof (unsigned long long);  /* value */
          mpos += entries[pos].descStrLen + 1;
          pos++;
        }
      end = pos;
      /* second pass: copy values and messages to message */
      for (pos = start; pos < end; pos++)
        ((CS_stats_reply_MESSAGE_GENERIC *) statMsg)->values[pos -
                                                             start] =
          GNUNET_htonll (entries[pos].value);
      mpos = sizeof (unsigned long long) * (end - start);
      for (pos = start; pos < end; pos++)
        {
          memcpy (&
                  ((char
                    *) (((CS_stats_reply_MESSAGE_GENERIC *) statMsg))->
                   values)[mpos], entries[pos].description,
                  entries[pos].descStrLen + 1);
          mpos += entries[pos].descStrLen + 1;
        }
      statMsg->statCounters = htonl (end - start);
      GNUNET_GE_ASSERT (NULL,
                        mpos + sizeof (CS_stats_reply_MESSAGE) <
                        GNUNET_MAX_BUFFER_SIZE);

      statMsg->header.size = htons (mpos + sizeof (CS_stats_reply_MESSAGE));
      /* printf("writing message of size %d with stats %d to %d out of %d to socket\n",
         ntohs(statMsg->header.size),
         start, end, statCounters); */
      if (GNUNET_SYSERR ==
          coreAPI->cs_send_to_client (sock, &statMsg->header, GNUNET_YES))
        break;                  /* abort, socket error! */
      start = end;
    }
  GNUNET_free (statMsg);
  return GNUNET_OK;
}

/**
 * Handle a request to see if a particular p2p message is supported.
 */
static int
handleMessageSupported (struct GNUNET_ClientHandle *sock,
                        const GNUNET_MessageHeader * message)
{
  unsigned short type;
  unsigned short htype;
  int supported;
  CS_stats_get_supported_MESSAGE *cmsg;

  if (ntohs (message->size) != sizeof (CS_stats_get_supported_MESSAGE))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  cmsg = (CS_stats_get_supported_MESSAGE *) message;
  type = ntohs (cmsg->type);
  htype = ntohs (cmsg->handlerType);
  supported = coreAPI->p2p_test_handler_registered (type, htype);
  return coreAPI->sendValueToClient (sock, supported);
}

/**
 * We received a request from a client to provide the number
 * of directly connected peers.  Sends the response.
 *
 * @param client the socket connecting to the client
 * @param msg the request from the client
 * @returns GNUNET_OK if ok, GNUNET_SYSERR if not.
 */
static int
processGetConnectionCountRequest (struct GNUNET_ClientHandle *client,
                                  const GNUNET_MessageHeader * msg)
{
  if (ntohs (msg->size) != sizeof (GNUNET_MessageHeader))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  return coreAPI->sendValueToClient
    (client, coreAPI->forAllConnectedNodes (NULL, NULL));
}

/**
 * Handler for processing noise.
 */
static int
processNoise (const GNUNET_PeerIdentity * sender,
              const GNUNET_MessageHeader * msg)
{
  statChange (stat_bytes_noise_received, ntohs (msg->size));
  return GNUNET_OK;
}


int
initialize_module_stats (GNUNET_CoreAPIForPlugins * capi)
{
  GNUNET_GE_ASSERT (capi->ectx, myCoreAPI == NULL);
  myCoreAPI = capi;
  stats = capi->request_service ("stats");
  if (stats == NULL)
    {
      GNUNET_GE_BREAK (capi->ectx, 0);
      myCoreAPI = NULL;
      return GNUNET_SYSERR;
    }
  initializeStats ();
  GNUNET_GE_LOG (capi->ectx,
                 GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                 _
                 ("`%s' registering client handlers %d %d %d and p2p handler %d\n"),
                 "stats", GNUNET_CS_PROTO_TRAFFIC_COUNT,
                 GNUNET_CS_PROTO_STATS_GET_STATISTICS,
                 GNUNET_CS_PROTO_STATS_GET_P2P_MESSAGE_SUPPORTED,
                 GNUNET_P2P_PROTO_NOISE);
  capi->registerClientHandler (GNUNET_CS_PROTO_STATS_GET_STATISTICS,
                               &sendStatistics);
  capi->
    registerClientHandler
    (GNUNET_CS_PROTO_STATS_GET_P2P_MESSAGE_SUPPORTED,
     &handleMessageSupported);
  capi->
    registerClientHandler
    (GNUNET_CS_PROTO_STATS_GET_CS_MESSAGE_SUPPORTED, &handleMessageSupported);
  capi->registerClientHandler (GNUNET_CS_PROTO_TRAFFIC_COUNT,
                               &processGetConnectionCountRequest);
  capi->registerHandler (GNUNET_P2P_PROTO_NOISE, &processNoise);
  GNUNET_GE_ASSERT (capi->ectx,
                    0 == GNUNET_GC_set_configuration_value_string (capi->cfg,
                                                                   capi->ectx,
                                                                   "ABOUT",
                                                                   "stats",
                                                                   gettext_noop
                                                                   ("keeps statistics about gnunetd's operation")));
#if HAVE_SQSTATS
  init_sqstore_stats ();
#endif
  immediateUpdates ();
  return GNUNET_OK;
}

int
done_module_stats ()
{
#if HAVE_SQSTATS
  done_sqstore_stats ();
#endif
  GNUNET_GE_ASSERT (NULL, myCoreAPI != NULL);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_STATS_GET_STATISTICS,
                                    &sendStatistics);
  coreAPI->
    unregisterClientHandler
    (GNUNET_CS_PROTO_STATS_GET_P2P_MESSAGE_SUPPORTED,
     &handleMessageSupported);
  coreAPI->
    unregisterClientHandler
    (GNUNET_CS_PROTO_STATS_GET_CS_MESSAGE_SUPPORTED, &handleMessageSupported);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_TRAFFIC_COUNT,
                                    &processGetConnectionCountRequest);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_NOISE, &processNoise);
  myCoreAPI->release_service (stats);
  stats = NULL;
  myCoreAPI = NULL;
  return GNUNET_OK;
}


/* end of statistics.c */
