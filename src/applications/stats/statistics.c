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
 * the SQStore?  Only set to YES for debugging, never
 * in production!
 */
#define HAVE_SQSTATS NO

/* *************** service *************** */

/**
 * When did the module start?
 */
static cron_t startTime;

struct StatEntry {
  unsigned long long value;
  char * description;
  unsigned int descStrLen;
};

static struct StatEntry * entries;

/**
 * Size of the entries array
 */
static unsigned int statCounters;

/**
 * lock for the stat module
 */
static struct MUTEX * statLock;

/**
 * The core API.
 */
static CoreAPIForApplication * coreAPI;

/**
 * Get a handle to a statistical entity.
 *
 * @param name a description of the entity
 * @return a handle for updating the associated value
 */
static int statHandle(const char * name) {
  int i;
  GE_ASSERT(NULL, name != NULL);
  MUTEX_LOCK(statLock);
  for (i=0;i<statCounters;i++)
    if (0 == strcmp(entries[i].description, name)) {
      MUTEX_UNLOCK(statLock);
      return i;
    }
  GROW(entries,
       statCounters,
       statCounters+1);
  entries[statCounters-1].description = STRDUP(name);
  entries[statCounters-1].descStrLen = strlen(name);
  entries[statCounters-1].value = 0;
  MUTEX_UNLOCK(statLock);
  return statCounters-1;
}

/**
 * Manipulate statistics. Sets the statistics associated with the
 * handle to value.
 *
 * @param handle the handle for the value to change
 * @param value to what the value should be set
 */
static void statSet(const int handle,
		    const unsigned long long value) {
  MUTEX_LOCK(statLock);
  if ( (handle < 0) ||
       (handle >= statCounters) ) {
    GE_BREAK(NULL, 0);
    MUTEX_UNLOCK(statLock);
    return;
  }
  entries[handle].value = value;
  MUTEX_UNLOCK(statLock);
}

static unsigned long long statGet(const int handle) {
  unsigned long long ret;
  MUTEX_LOCK(statLock);
  if ( (handle < 0) ||
       (handle >= statCounters) ) {
    GE_BREAK(NULL, 0);
    MUTEX_UNLOCK(statLock);
    return -1;
  }
  ret = entries[handle].value;
  MUTEX_UNLOCK(statLock);
  return ret;
}

/**
 * Manipulate statistics. Changes the statistics associated with the
 * value by delta.
 *
 * @param handle the handle for the value to change
 * @param delta by how much should the value be changed
 */
static void statChange(const int handle,
		       const int delta) {
  MUTEX_LOCK(statLock);
  if ( (handle < 0) ||
       (handle >= statCounters) ) {
    GE_BREAK(NULL, 0);
    MUTEX_UNLOCK(statLock);
    return;
  }
  entries[handle].value += delta;
  MUTEX_UNLOCK(statLock);
}


/**
 * Shutdown the statistics module.
 */
void release_module_stats() {
  int i;

  MUTEX_DESTROY(statLock);
  for (i=0;i<statCounters;i++)
    FREE(entries[i].description);
  GROW(entries,
       statCounters,
       0);
}


/**
 * Initialize the statistics module.
 */
Stats_ServiceAPI *
provide_module_stats(CoreAPIForApplication * capi) {
  static Stats_ServiceAPI api;

  coreAPI = capi;
  api.create = &statHandle;
  api.set = &statSet;
  api.change = &statChange;
  api.get = &statGet;
  startTime = get_time();
  statLock = MUTEX_CREATE(YES);
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
static Stats_ServiceAPI * stats;
static CoreAPIForApplication * myCoreAPI;

#if HAVE_SQSTATS
#include "sqstats.c"
#endif

static void initializeStats() {
  stat_handle_network_load_up
    = statHandle(gettext_noop("% of allowed network load (up)"));
  stat_handle_network_load_down
    = statHandle(gettext_noop("% of allowed network load (down)"));
  stat_handle_cpu_load
    = statHandle(gettext_noop("% of allowed cpu load"));
  stat_handle_io_load
    = statHandle(gettext_noop("% of allowed io load"));
  stat_connected
    = statHandle(gettext_noop("# of connected peers"));
  stat_bytes_noise_received
    = statHandle(gettext_noop("# bytes of noise received"));
}

static void immediateUpdates() {
  int load;

#if HAVE_SQSTATS
  update_sqstore_stats();
#endif
  load = os_cpu_get_load(coreAPI->ectx,
			 coreAPI->cfg);
  if (load == -1)
    load = 0;
  statSet(stat_handle_cpu_load,
	  load);
  load = os_disk_get_load(coreAPI->ectx,
			  coreAPI->cfg);
  if (load == -1)
    load = 0;
  statSet(stat_handle_io_load,
	  load);
  load = os_network_monitor_get_load(coreAPI->load_monitor,
				     Upload);
  if (load == -1)
    load = 0;
  statSet(stat_handle_network_load_up,
	  load);
  load = os_network_monitor_get_load(coreAPI->load_monitor,
				     Download);
  if (load == -1)
    load = 0;
  statSet(stat_handle_network_load_down,
	  load);
  statSet(stat_connected,
	  coreAPI->forAllConnectedNodes(NULL, NULL));
}


/**
 * Send statistics to a TCP socket.  May send multiple messages if the
 * overall size would be too big otherwise.
 *
 * @param originalRequestMessage ignored at this point.
 */
static int sendStatistics(struct ClientHandle * sock,
			  const MESSAGE_HEADER * originalRequestMessage) {
  CS_stats_reply_MESSAGE * statMsg;
  int pos; /* position in the values-descriptions */
  int start;
  int end;
  int mpos; /* postion in the message */

  immediateUpdates();
  statMsg = MALLOC(MAX_BUFFER_SIZE);
  statMsg->header.type
    = htons(CS_PROTO_stats_STATISTICS);
  statMsg->totalCounters
    = htonl(statCounters);
  statMsg->statCounters
    = htons(0);
  statMsg->startTime
    = htonll(startTime);

  start = 0;
  while (start < statCounters) {
    pos = start;
    /* first pass: gauge how many statistic numbers
       and their descriptions we can send in one message */
    mpos = 0;
    while ( (pos < statCounters) &&
	    (mpos + sizeof(unsigned long long)
	     + entries[pos].descStrLen + 1
	     < MAX_BUFFER_SIZE - sizeof(CS_stats_reply_MESSAGE)) ) {
      mpos += sizeof(unsigned long long); /* value */
      mpos += entries[pos].descStrLen + 1;
      pos++;
    }
    end = pos;
    /* second pass: copy values and messages to message */
    for (pos=start;pos<end;pos++)
      ((CS_stats_reply_MESSAGE_GENERIC*)statMsg)->values[pos-start] = htonll(entries[pos].value);
    mpos = sizeof(unsigned long long) * (end - start);
    for (pos=start;pos<end;pos++) {
      memcpy(&((char*)(((CS_stats_reply_MESSAGE_GENERIC*)statMsg))->values)[mpos],
	     entries[pos].description,
	     entries[pos].descStrLen+1);
      mpos += entries[pos].descStrLen+1;
    }
    statMsg->statCounters = htonl(end - start);
    GE_ASSERT(NULL, mpos + sizeof(CS_stats_reply_MESSAGE) < MAX_BUFFER_SIZE);

    statMsg->header.size = htons(mpos + sizeof(CS_stats_reply_MESSAGE));
    /* printf("writing message of size %d with stats %d to %d out of %d to socket\n",
       ntohs(statMsg->header.size),
       start, end, statCounters);*/
    if (SYSERR == coreAPI->sendToClient(sock,
					&statMsg->header))
      break; /* abort, socket error! */
    start = end;
  }
  FREE(statMsg);
  return OK;
}

/**
 * Handle a request to see if a particular p2p message is supported.
 */
static int handleMessageSupported(struct ClientHandle * sock,
				  const MESSAGE_HEADER * message) {
  unsigned short type;
  unsigned short htype;
  int supported;
  CS_stats_get_supported_MESSAGE * cmsg;

  if (ntohs(message->size) != sizeof(CS_stats_get_supported_MESSAGE)) {
    GE_BREAK(NULL, 0);
    return SYSERR;
  }
  cmsg = (CS_stats_get_supported_MESSAGE *) message;
  type = ntohs(cmsg->type);
  htype = ntohs(cmsg->handlerType);
  supported = coreAPI->isHandlerRegistered(type, htype);
  return coreAPI->sendValueToClient(sock, supported);
}

/**
 * We received a request from a client to provide the number
 * of directly connected peers.  Sends the response.
 *
 * @param client the socket connecting to the client
 * @param msg the request from the client
 * @returns OK if ok, SYSERR if not.
 */
static int processGetConnectionCountRequest(struct ClientHandle * client,
					    const MESSAGE_HEADER * msg) {
  if (ntohs(msg->size) != sizeof(MESSAGE_HEADER)) {
    GE_BREAK(NULL, 0);
    return SYSERR;
  }
  return coreAPI->sendValueToClient
    (client,
     coreAPI->forAllConnectedNodes(NULL, NULL));
}

/**
 * Handler for processing noise.
 */
static int processNoise(const PeerIdentity * sender,
			const MESSAGE_HEADER * msg) {
  statChange(stat_bytes_noise_received,
	     ntohs(msg->size));
  return OK;
}


int initialize_module_stats(CoreAPIForApplication * capi) {
  GE_ASSERT(capi->ectx,
	    myCoreAPI == NULL);
  myCoreAPI = capi;
  stats = capi->requestService("stats");
  if (stats == NULL) {
    GE_BREAK(capi->ectx, 0);
    myCoreAPI = NULL;
    return SYSERR;
  }
  initializeStats();
  GE_LOG(capi->ectx,
	 GE_INFO | GE_USER | GE_REQUEST,
	 _("`%s' registering client handlers %d %d %d and p2p handler %d\n"),
	 "stats",
	 CS_PROTO_traffic_COUNT,
	 CS_PROTO_stats_GET_STATISTICS,
	 CS_PROTO_stats_GET_P2P_MESSAGE_SUPPORTED,
	 P2P_PROTO_noise);
  capi->registerClientHandler(CS_PROTO_stats_GET_STATISTICS,
			      &sendStatistics);
  capi->registerClientHandler(CS_PROTO_stats_GET_P2P_MESSAGE_SUPPORTED,
			      &handleMessageSupported);
  capi->registerClientHandler(CS_PROTO_stats_GET_CS_MESSAGE_SUPPORTED,
			      &handleMessageSupported);
  capi->registerClientHandler(CS_PROTO_traffic_COUNT,
				&processGetConnectionCountRequest);
  capi->registerHandler(P2P_PROTO_noise,
			&processNoise);
  GE_ASSERT(capi->ectx,
	    0 == GC_set_configuration_value_string(capi->cfg,
						   capi->ectx,
						   "ABOUT",
						   "stats",
						   gettext_noop("keeps statistics about gnunetd's operation")));
#if HAVE_SQSTATS
  init_sqstore_stats();
#endif
  immediateUpdates();
  return OK;
}

int done_module_stats() {
#if HAVE_SQSTATS
  done_sqstore_stats();
#endif
  GE_ASSERT(NULL, myCoreAPI != NULL);
  coreAPI->unregisterClientHandler(CS_PROTO_stats_GET_STATISTICS,
				   &sendStatistics);
  coreAPI->unregisterClientHandler(CS_PROTO_stats_GET_P2P_MESSAGE_SUPPORTED,
				   &handleMessageSupported);
  coreAPI->unregisterClientHandler(CS_PROTO_stats_GET_CS_MESSAGE_SUPPORTED,
				   &handleMessageSupported);
  coreAPI->unregisterClientHandler(CS_PROTO_traffic_COUNT,
				   &processGetConnectionCountRequest);
  coreAPI->unregisterHandler(P2P_PROTO_noise,
			     &processNoise);
  myCoreAPI->releaseService(stats);
  stats = NULL;
  myCoreAPI = NULL;
  return OK;
}


/* end of statistics.c */
