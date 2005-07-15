/*
  This file is part of GNUnet.
  (C) 2001, 2002, 2004 Christian Grothoff (and other contributing authors)

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

/* *************** service *************** */

/**
 * When did the module start?
 */
static cron_t startTime;

/**
 * How many values do we keep statistics for?
 */
static unsigned int statCounters = 0;

/**
 * What are these values (value)
 */
static unsigned long long * values = NULL;

/**
 * A description for each of the values
 */
static char ** descriptions = NULL;

/**
 * lock for the stat module
 */
static Mutex statLock;

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
  GNUNET_ASSERT(name != NULL);
  MUTEX_LOCK(&statLock);
  for (i=0;i<statCounters;i++)
    if (0 == strcmp(descriptions[i], name)) {
      MUTEX_UNLOCK(&statLock);
      return i;
    }

  GROW(values,
       statCounters,
       statCounters+1);
  statCounters--;
  GROW(descriptions,
       statCounters,
       statCounters+1);
  descriptions[statCounters-1] = STRDUP(name);
  MUTEX_UNLOCK(&statLock);
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
  MUTEX_LOCK(&statLock);
  if ( (handle < 0) ||
       (handle >= statCounters) ) {
    BREAK();
    MUTEX_UNLOCK(&statLock);
    return;
  }
  values[handle] = value;
  MUTEX_UNLOCK(&statLock);
}

static unsigned long long statGet(const int handle) {
  unsigned long long ret;
  MUTEX_LOCK(&statLock);
  if ( (handle < 0) ||
       (handle >= statCounters) ) {
    BREAK();
    MUTEX_UNLOCK(&statLock);
    return -1;
  }
  ret = values[handle];
  MUTEX_UNLOCK(&statLock);
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
  MUTEX_LOCK(&statLock);
  if ( (handle < 0) ||
       (handle >= statCounters) ) {
    BREAK();
    MUTEX_UNLOCK(&statLock);
    return;
  }
  values[handle] += delta;
  MUTEX_UNLOCK(&statLock);
}


/**
 * Shutdown the statistics module.
 */
void release_module_stats() {
  int i;

  MUTEX_DESTROY(&statLock);
  for (i=0;i<statCounters;i++)
    FREE(descriptions[i]);
  FREENONNULL(descriptions);
  descriptions = NULL;
  GROW(values,
       statCounters,
       0);
}


/**
 * Initialize the statistics module.
 */
Stats_ServiceAPI * provide_module_stats(CoreAPIForApplication * capi) {
  static Stats_ServiceAPI api;

  coreAPI = capi;
  api.create = &statHandle;
  api.set = &statSet;
  api.change = &statChange;
  api.get = &statGet;
  cronTime(&startTime);
  MUTEX_CREATE_RECURSIVE(&statLock);
  return &api;
}


/* *************** protocol *************** */

/* ********* special stats that are updated
   always just before we send the reply ******* */

static int stat_handle_network_load_up;
static int stat_handle_network_load_down;
static int stat_handle_cpu_load;
static int stat_bytes_noise_received;
static int stat_connected;

static void initializeStats() {
  stat_handle_network_load_up
    = statHandle(gettext_noop("% of allowed network load (up)"));
  stat_handle_network_load_down
    = statHandle(gettext_noop("% of allowed network load (down)"));
  stat_handle_cpu_load
    = statHandle(gettext_noop("% of allowed cpu load"));
  stat_connected
    = statHandle(gettext_noop("# of connected peers"));
  stat_bytes_noise_received
    = statHandle(gettext_noop("# bytes of noise received"));
}

static void immediateUpdates() {
  statSet(stat_handle_cpu_load, getCPULoad());
  statSet(stat_handle_network_load_up, getNetworkLoadUp());
  statSet(stat_handle_network_load_down, getNetworkLoadDown());
  statSet(stat_connected,
	  coreAPI->forAllConnectedNodes(NULL, NULL));
}


/**
 * Send statistics to a TCP socket.  May send multiple messages if the
 * overall size would be too big otherwise.
 *
 * @param originalRequestMessage ignored at this point.
 */
static int sendStatistics(ClientHandle sock,
			  const CS_HEADER * originalRequestMessage) {
  STATS_CS_MESSAGE * statMsg;
  int pos; /* position in the values-descriptions */
  int start;
  int end;
  int mpos; /* postion in the message */

  immediateUpdates();
  statMsg = (STATS_CS_MESSAGE*)MALLOC(MAX_BUFFER_SIZE);
  statMsg->header.type
    = htons(STATS_CS_PROTO_STATISTICS);
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
	     + strlen(descriptions[pos]) + 1
	     < MAX_BUFFER_SIZE - sizeof(STATS_CS_MESSAGE)) ) {
      mpos += sizeof(unsigned long long); /* value */
      mpos += strlen(descriptions[pos])+1;
      pos++;
    }
    end = pos;
    /* second pass: copy values and messages to message */
    for (pos=start;pos<end;pos++)
      ((STATS_CS_MESSAGE_GENERIC*)statMsg)->values[pos-start] = htonll(values[pos]);
    mpos = sizeof(unsigned long long) * (end - start);
    for (pos=start;pos<end;pos++) {
      strcpy(&((char*)(((STATS_CS_MESSAGE_GENERIC*)statMsg))->values)[mpos],
	     descriptions[pos]);
      mpos += strlen(descriptions[pos])+1;
    }
    statMsg->statCounters = htonl(end - start);
    GNUNET_ASSERT(mpos + sizeof(STATS_CS_MESSAGE) < MAX_BUFFER_SIZE);

    statMsg->header.size = htons(mpos + sizeof(STATS_CS_MESSAGE));
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
static int handlep2pMessageSupported(ClientHandle sock,
				     const CS_HEADER * message) {
  unsigned short type;
  unsigned short htype;
  int supported;
  STATS_CS_GET_MESSAGE_SUPPORTED * cmsg;

  if (ntohs(message->size) != sizeof(STATS_CS_GET_MESSAGE_SUPPORTED)) {
    BREAK();
    return SYSERR;
  }
  cmsg = (STATS_CS_GET_MESSAGE_SUPPORTED *) message;
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
static int processGetConnectionCountRequest(ClientHandle client,
					    const CS_HEADER * msg) {
  if (ntohs(msg->size) != sizeof(CS_HEADER)) {
    BREAK();
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
			const p2p_HEADER * msg) {
  statChange(stat_bytes_noise_received,
	     ntohs(msg->size));
  return OK;
}


static Stats_ServiceAPI * myApi;
static CoreAPIForApplication * myCoreAPI;

int initialize_module_stats(CoreAPIForApplication * capi) {
  GNUNET_ASSERT(myCoreAPI == NULL);
  myCoreAPI = capi;
  myApi = capi->requestService("stats");
  if (myApi == NULL) {
    BREAK();
    myCoreAPI = NULL;
    return SYSERR;
  }
  initializeStats();
  LOG(LOG_DEBUG,
      "'%s' registering client handlers %d %d %d and p2p handler %d\n",
      "stats",
      CS_PROTO_CLIENT_COUNT,
      STATS_CS_PROTO_GET_STATISTICS,
      STATS_CS_PROTO_GET_P2P_MESSAGE_SUPPORTED,
      p2p_PROTO_NOISE);
  capi->registerClientHandler(STATS_CS_PROTO_GET_STATISTICS,
			      &sendStatistics);
  capi->registerClientHandler(STATS_CS_PROTO_GET_P2P_MESSAGE_SUPPORTED,
			      &handlep2pMessageSupported);
  capi->registerClientHandler(CS_PROTO_CLIENT_COUNT,
				&processGetConnectionCountRequest);
  capi->registerHandler(p2p_PROTO_NOISE,
			&processNoise);
  setConfigurationString("ABOUT",
			 "stats",
			 gettext_noop("keeps statistics about gnunetd's operation"));
  return OK;
}

int done_module_stats() {
  GNUNET_ASSERT(myCoreAPI != NULL);
  coreAPI->unregisterClientHandler(STATS_CS_PROTO_GET_STATISTICS,
				   &sendStatistics);
  coreAPI->unregisterClientHandler(STATS_CS_PROTO_GET_P2P_MESSAGE_SUPPORTED,
				   &handlep2pMessageSupported);
  coreAPI->unregisterClientHandler(CS_PROTO_CLIENT_COUNT,
				   &processGetConnectionCountRequest);
  coreAPI->unregisterHandler(p2p_PROTO_NOISE,
			     &processNoise);
  myCoreAPI->releaseService(myApi);
  myApi = NULL;
  myCoreAPI = NULL;
  return OK;
}


/* end of statistics.c */
