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
 * @file server/connection.c
 * @brief module responsible for the peer-to-peer connections
 *
 * This file contains the connection table which lists all the current
 * connections of the node with other hosts and buffers outgoing
 * packets to these hosts.  The connection table also contains state
 * information such as sessionkeys, credibility and the last time we
 * had host activity.<p>
 *
 * This code is responsible for exchanging a sessionkey with another
 * peer, grouping several messages into a larger packet, padding with
 * noise, encryption and deferred sending of these messages.<p>
 *
 * The file is organized as follows:
 *
 * a) includes
 * b) defines
 * c) typedefs
 * d) global variables
 * e) code
 * <p>
 *
 * @author Tzvetan Horozov
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_session_service.h"
#include "gnunet_fragmentation_service.h"
#include "gnunet_topology_service.h"
#include "gnunet_stats_service.h"
#include "connection.h"
#include "core.h"
#include "handler.h"


/* **************** defines ************ */

/* tuning parameters */

#define DEBUG_CONNECTION NO

/* output knapsack priorities into a file? */
#define DEBUG_COLLECT_PRIO NO

/**
 * If an attempt to establish a connection is not answered
 * within 150s, drop.
 */
#define SECONDS_NOPINGPONG_DROP 150

/**
 * If an established connection is inactive for 5 minutes,
 * drop.
 */
#define SECONDS_INACTIVE_DROP 300

/**
 * After 2 minutes on an inactive connection, probe the other
 * node with a ping if we have achieved less than 50% of our
 * connectivity goal.
 */
#define SECONDS_PINGATTEMPT 120

/**
 * High priority message that needs to go through fast,
 * but not if policies would be disregarded.
 */
#define ADMIN_PRIORITY 0xFFFF

/**
 * If we under-shoot our bandwidth limitation in one time period, how
 * much of that limit are we allowed to 'roll-over' into the next
 * period?  The number given here is a factor of the total per-minute
 * bandwidth limit.
 */
#define MAX_BUF_FACT 2

/**
 * Expected MTU for a streaming connection.
 */
#define EXPECTED_MTU 32768

/**
 * How many ping/pong messages to we want to transmit
 * per SECONDS_INACTIVE_DROP interval? (must be >=4 to
 * keep connection alive with reasonable probability).
 */
#define TARGET_MSG_SID 8

/**
 * Minimum number of sample messages (per peer) before we recompute
 * traffic assignments?
 */
#define MINIMUM_SAMPLE_COUNT 8

/**
 * What is the minimum number of bytes per minute that
 * we allocate PER peer? (5 minutes inactivity timeout,
 * 32768 MTU, 8 MSGs => 8 * 32768 / 5 = ~50000 bpm [ ~800 bps])
 */
#define MIN_BPM_PER_PEER (TARGET_MSG_SID * EXPECTED_MTU * 60 / SECONDS_INACTIVE_DROP)

/**
 * How often do we expect to re-run the traffic allocation
 * code? (depends on MINIMUM_SAMPLE_COUNT and MIN_BPM_PER_PEER
 * and MTU size).
 */
#define MIN_SAMPLE_TIME (MINIMUM_SAMPLE_COUNT * cronMINUTES * EXPECTED_MTU / MIN_BPM_PER_PEER)

/**
 * Hard limit on the send buffer size (per connection, in bytes),
 * Must be larger than EXPECTED_MTU.
 */
#define MAX_SEND_BUFFER_SIZE (EXPECTED_MTU * 8)

/**
 * Status constants
 *
 * Protocol goes like this:
 *          DOWN
 *   -> hello+SETKEY+PING(1) ->
 *        SETKEY_SENT
 *  <- hello+SETKEY+PONG(1)+PING(2) <-
 *       -> PONG(2) ->
 *           UP
 *
 * Note that the second hello may not be necessary from a protocol
 * point of view, but makes sense for symmetry and to provide the
 * other side with an up-to-date hello.  For the other side, it looks
 * like this:
 *
 *          DOWN
 *      <- hello+SETKEY+PING(1) <-
 *  -> hello+SETKEY+PONG(1)+PING(2) ->
 *        SETKEY_RECEIVED
 *       <- PONG(2) <-
 *           UP
 *
 * PING's and PONG's are repeated later
 * in the protocol as keep-alive messages.
 * If a peer wants to shutdown a connection
 * immediately (be polite, not let it time-out,
 * save bandwidth), he sends:
 *
 *          UP
 *      -> HANGUP ->
 *         DOWN
 *
 * The other side then does:
 *          UP
 *      <- HANGUP -<
 *         DOWN
 *
 * A 3-way handshake does not happen for
 * the shutdown since it is not reliable
 * (timeout is the ultimate measure).
 */

#define STAT_DOWN             0
/* hello and SETKEY sent (PING included) */
#define STAT_SETKEY_SENT        1
/* SETKEY received, hello and SETKEY sent (PING included) */
#define STAT_SETKEY_RECEIVED    2
/* PING confirmed with (encrypted) PONG */
#define STAT_UP               7


#if DEBUG_CONNECTION == 2
#define ENTRY() LOG(LOG_DEBUG, "Method entry: %s defined in %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
#else
#define ENTRY() ;
#endif

#if DEBUG_COLLECT_PRIO == YES
FILE * prioFile;
#endif


/* ******************** typedefs ******************* */

/**
 * Type of the linked list of send callbacks (to
 * implement a round-robbin invocation chain).
 */
typedef struct SendCallbackList__ {
  /**
   * Minimum number of bytes that must be available
   * to call this callback.
   */
  unsigned int minimumPadding;

  /**
   * The callback method.
   */
  BufferFillCallback callback;

  /**
   * Did we say that this is a linked list?
   */
  struct SendCallbackList__ * next;

} SendCallbackList;


typedef struct fENHWrap {
  PerNodeCallback method;
  void * arg;
} fENHWrap;


/**
 * The other side has decided to terminate the connection.  This
 * message MAY be send if the other node decides to be nice.  It is
 * not required.  Mind that the message contains for which host the
 * termination is, such that we don't hang up the wrong connection...
 * A node can also choose to ignore the HANGUP message, though this is
 * probably not going to help that node.  This message is used to
 * prevent sending data to connections that were closed on the other
 * side (can happen anyway, so this is just an optimization between
 * well-behaved, non-malicious nodes that like each other).
 */
typedef struct {
  P2P_MESSAGE_HEADER header;
  PeerIdentity sender;
} P2P_hangup_MESSAGE;


/* *********** flags for SendEntry.flags ********** */

/* no flags */
#define SE_FLAG_NONE 0
/* place entry at the head of the message */
#define SE_FLAG_PLACE_HEAD 1
/* place entry at the tail of the message */
#define SE_FLAG_PLACE_TAIL 2

#define SE_PLACEMENT_FLAG 3

/**
 * Entry in the send buffer.  Contains the size of the message, the
 * priority, when the message was passed to unicast, a callback to
 * fill in the actual message and a closure (argument to the
 * callback).
 */
typedef struct {
  /** how long is this message part expected to be? */
  unsigned short len;
  /** flags */
  unsigned short flags;
  /** how important is this message part? */
  unsigned int pri;
  /** when did we intend to transmit? */
  cron_t transmissionTime;
  /** callback to call to create the message part */
  BuildMessageCallback callback;
  /** argument to callback, call FREENONNULL(closure) if we
      can not transmit this MessagePart. */
  void * closure;
  /** YES if selected by knapsack for sending */
  int knapsackSolution;
} SendEntry;

/**
 * A session is a token provided by the transport
 * API to refer to a connection of the transport
 * layer.
 */
typedef struct {
  /**
   * To whom are we connected with this session?
   */
  PeerIdentity sender;

  /**
   * The MTU for this session, 0 for streaming transports.
   */
  unsigned short mtu;

  /**
   * The session handle specific for the transport service.
   */
  TSession * tsession;

} Session;


/**
 * Type of the connection table.
 */
typedef struct BufferEntry_ {
  /** Session for the connection */
  Session session;
  /** the current session key used for encryption */
  SESSIONKEY skey_local;
  /** at which time was the local sessionkey created */
  TIME_T skey_local_created;
  /** the current session key used for decryption */
  SESSIONKEY skey_remote;
  /** at which time was the remote sessionkey created */
  TIME_T skey_remote_created;
  /** is this host alive? timestamp of the time of the last-active
      point (as witnessed by some higher-level application, typically
      topology+pingpong) */
  cron_t isAlive;
  /**  Status of the connection (STAT_XXX) */
  unsigned int status;

  /** last sequence number received on this connection (highest) */
  unsigned int lastSequenceNumberReceived;
  /** bit map indicating which of the 32 sequence numbers before the last
      were received (good for accepting out-of-order packets and
      estimating reliability of the connection) */
  unsigned int lastPacketsBitmap;
  /** last sequence number transmitted */
  unsigned int lastSequenceNumberSend;

  /** number of entries in the send buffer */
  unsigned int sendBufferSize;

  /** buffer of entries waiting to be transmitted */
  SendEntry ** sendBuffer;

  /** time of the last send-attempt (to avoid
      solving knapsack's too often) */
  cron_t lastSendAttempt;

  /**
   * How frequent (per connection!) may we attempt to solve the knapsack
   * problem and send a message out? Note that setting this value higher
   * reduces the CPU overhead while a lower value can improve thoughput.
   *
   * The value is adjusted according to how fast we perceive the CPU
   * to be (and is also proportional too how much bandwidth we have)...
   */
  cron_t MAX_SEND_FREQUENCY;

  /** a hash collision overflow chain */
  struct BufferEntry_ * overflowChain;


  /* *********** outbound bandwidth limits ********** */

  /** byte-per-minute limit for this connection */
  unsigned int max_bpm;
  /** current bps (actually bytes per minute) for this connection
      (incremented every minute by max_bpm,
       bounded by max_bpm * secondsInactive/2;
       may get negative if we have VERY high priority
       content) */
  long long available_send_window;
  /** time of the last increment of available_send_window */
  cron_t last_bps_update;

  /* *********** inbound bandwidth accounting ******** */

  /* how much traffic (bytes) did we receive on this connection since
     the last update-round? */
  long long recently_received;

  /** How valueable were the messages of this peer recently? */
  double current_connection_value;

  /* the highest bandwidth limit that a well-behaved peer
     must have received by now */
  unsigned int max_transmitted_limit;
  /* what is the limit that we are currently shooting for? (byte per minute) */
  unsigned int idealized_limit;

  unsigned int violations;

  /* are we currently in "sendBuffer" for this
     entry? */
  int inSendBuffer;
  
} BufferEntry;

typedef struct {
  BufferEntry ** e;
  unsigned int pos;
} UTL_Closure;

/**
 * Type of a callback method on every buffer.
 * @param be the buffer entry
 * @param data context for callee
 */
typedef void (*BufferEntryCallback)(BufferEntry * be,
				    void * data);

/* ***************** globals ********************** */

/**
 * Transport service
 */
static Transport_ServiceAPI * transport;

/**
 * Identity service
 */
static Identity_ServiceAPI * identity;

/**
 * Session service
 */
static Session_ServiceAPI * session;

/**
 * Fragmentation service
 */
static Fragmentation_ServiceAPI * fragmentation;

/**
 * Topology service
 */
static Topology_ServiceAPI * topology;

/**
 * Stats service (maybe NULL!)
 */
static Stats_ServiceAPI * stats;

/**
 * The buffer containing all current connections.
 */
static BufferEntry ** CONNECTION_buffer_;

/**
 * Size of the CONNECTION_buffer_
 */
static unsigned int CONNECTION_MAX_HOSTS_;

/**
 * Experimental configuration: disable random padding of encrypted
 * messages.
 */
static int disable_random_padding = NO;

/**
 * Send callbacks for making better use of noise padding...
 */
static SendCallbackList * scl_nextHead;
static SendCallbackList * scl_nextTail;

/**
 * Lock for the connection module.
 */
static Mutex lock;

/**
 * What is the available downstream bandwidth (in bytes
 * per minute)?
 */
static unsigned long long max_bpm;

/**
 * Registered Send-Notify handlers.
 */
static MessagePartHandler * rsns;

/**
 * Size of rsns.
 */
static unsigned int rsnSize;

static int stat_messagesDropped;

static int stat_sizeMessagesDropped;

static int stat_hangupSent;

static int stat_encrypted;

static int stat_decrypted;

static int stat_noise_sent;

/* ******************** CODE ********************* */

#if DEBUG_CONNECTION
static void printMsg(const char *prefix, PeerIdentity *sender,
                     SESSIONKEY *key, const INITVECTOR *iv, int crc) {
  char skey[65];
  char *dst;
  int idx;
  EncName enc;
  
  hash2enc(&sender->hashPubKey, &enc);
  
  dst = skey;
  for (idx=0; idx < SESSIONKEY_LEN; idx++) {
    sprintf(dst, "%02x", key->key[idx]);
    dst += 2;
  }
  *dst = 0;
  
  LOG(LOG_DEBUG,
      "%s: Sender `%s', key `%s', IV %u msg CRC %u\n",
      prefix, &enc, skey, *((int *)iv), crc);
}
#endif

/**
 * This allocates and initializes a BufferEntry.
 * @return the initialized BufferEntry
 */
static BufferEntry * initBufferEntry() {
  BufferEntry * be;

  be = (BufferEntry*) MALLOC(sizeof(BufferEntry));
  memset(be, 0, sizeof(BufferEntry));
  be->isAlive
    = 0;
  be->status
    = STAT_DOWN;
  be->sendBuffer
    = NULL;
  be->sendBufferSize
    = 0;
  be->overflowChain
    = NULL;
  be->session.tsession
    = NULL;
  be->max_bpm
    = MIN_BPM_PER_PEER;
  be->available_send_window
    = be->max_bpm;
  be->recently_received
    = 0;
  be->current_connection_value
    = 0.0;
  be->idealized_limit
    = MIN_BPM_PER_PEER;
  be->max_transmitted_limit
    = MIN_BPM_PER_PEER;
  be->lastSendAttempt
    = 0; /* never */
  be->MAX_SEND_FREQUENCY
    = 50 * cronMILLIS * getCPULoad();
  be->inSendBuffer
    = NO;
  cronTime(&be->last_bps_update); /* now */
  return be;
}

/**
 * Update available_send_window.  Call only when already synchronized.
 * @param be the connection for which to update available_send_window
 */
void updateCurBPS(BufferEntry * be) {
  cron_t now;
  cron_t delta;

  cronTime(&now);
  if (now <= be->last_bps_update)
    return;
  delta = now - be->last_bps_update;
  if (be->max_bpm * delta < cronMINUTES)
    return;
  be->available_send_window =
    be->available_send_window + be->max_bpm * delta / cronMINUTES;
  if (be->available_send_window > (long long) be->max_bpm * MAX_BUF_FACT)
    be->available_send_window = (long long) be->max_bpm * MAX_BUF_FACT;
  be->last_bps_update = now;
}


/**
 * Compute the greatest common denominator (Euklid).
 *
 * @param a
 * @param b
 * @return gcd(a,b)
 */
static int gcd(int a, int b) {
  while (a != 0) {
    int t = a;
    a = b % a;
    b = t;
  }
  return b;
}

/**
 * Approximate a solution to the 0-1 knapsack problem
 * using a greedy heuristic.  This function assumes that
 * the entries in the sendBuffer are ALREADY sorted
 * (by priority/len).
 *
 * The code falls back to this function if the CPU is
 * too busy.  As long as the CPU is idle, solveKnapsack
 * is used.
 *
 * @param be the send buffer that is scheduled
 * @param available what is the maximum length available?
 * @return the overall priority that was achieved
 */
static unsigned int
approximateKnapsack(BufferEntry * be,
		    unsigned int available) {
  unsigned int i;
  unsigned int count;
  SendEntry ** entries;
  int max;
  int left;

  entries = be->sendBuffer;
  count = be->sendBufferSize;
  left = available;
  max = 0;

  for (i=0;i<count;i++) {
    if (entries[i]->len <= left) {
      entries[i]->knapsackSolution = YES;
      left -= entries[i]->len;
      max += entries[i]->pri;
    } else {
      entries[i]->knapsackSolution = NO;
    }
  }
  return max;
}

/**
 * Solve the 0-1 knapsack problem.  Given "count" "entries" of
 * different "len" and "pri"ority and the amount of space "available",
 * compute the "solution", which is the set of entries to transport.
 *
 * Solving this problem is NP complete in "count", but given that
 * available is small, the complexity is actually
 * "O(count*available)".
 *
 * @param be the send buffer that is scheduled
 * @param available what is the maximum length available?
 * @return the overall priority that was achieved
 */
static unsigned int
solveKnapsack(BufferEntry * be,
	      unsigned int available) {
  unsigned int i;
  int j;
  int max;
  long long * v;
  int * efflen;
  cron_t startTime;
  cron_t endTime;
  SendEntry ** entries;
  unsigned int count;
#define VARR(i,j) v[(i)+(j)*(count+1)]

  if (available < 0) {
    BREAK();
    return -1;
  }
  ENTRY();
  entries = be->sendBuffer;
  count = be->sendBufferSize;
  cronTime(&startTime);

  /* fast test: schedule everything? */
  max = 0;
  for (i=0;i<count;i++)
    max += entries[i]->len;
  if (max <= available) {
    /* short cut: take everything! */
    for (i=0;i<count;i++)
      entries[i]->knapsackSolution = YES;
    max = 0;
    for (i=0;i<count;i++)
      max += entries[i]->pri;
    return max;
  }

  /* division of sizes & available by gcd(sizes,available)
     to reduce cost to O(count*available/gcd) in terms of
     CPU and memory.  Since gcd is almost always at least
     4, this is probably a good idea (TM)  :-) */
  efflen = MALLOC(sizeof(int)*count);
  max = available;
  for (i=0;i<count;i++) {
    if (entries[i]->len > 0)
      max = gcd(max, entries[i]->len);
  }
  GNUNET_ASSERT(max != 0);
  available = available / max;
  for (i=0;i<count;i++)
    efflen[i] = entries[i]->len / max;

  /* dynamic programming:
     VARR(i,j) stores the maximum value of any subset
     of objects {1, ... i} that can fit into a knapsack
     of weight j. */
  v = MALLOC(sizeof(long long) * (count+1) * (available+1));
  memset(v,
	 0,
	 sizeof(long long) * (count+1) * (available+1));
  for (j=1;j<=available;j++)
    VARR(0,j) = -1;
  for (i=1;i<=count;i++) {
    for (j=0;j<=available;j++) {
      int take_val;
      int leave_val;

      take_val = -1;
      leave_val = VARR(i-1,j);
      if (j >= efflen[i-1]) {
	take_val = entries[i-1]->pri + VARR(i-1, j-efflen[i-1]);
	if (leave_val > take_val)
	  VARR(i,j) = leave_val;
	else
	  VARR(i,j) = take_val;
      } else
	VARR(i,j) = leave_val;
      /*
      printf("i: %d j: %d (of %d) efflen: %d take: %d "
             "leave %d e[i-1]->pri %d VAR(i-1,j-eff) %lld VAR(i,j) %lld\n",
	     i,
	     j,
	     available,
	     efflen[i-1],
	     take_val,
	     leave_val,
	     entries[i-1]->pri,
	     VARR(i-1,j-efflen[i-1]),
	     VARR(i,j));
      */
    }
  }

  /* find slot with max value, prefer long messages! */
  max = 0;
  j = -1;
  for (i=0;(int)i<=available;i++) {
    if (VARR(count, i) >= max) {
      j = i;
      max = VARR(count, i);
    }
  }

  /* reconstruct selection */
  for (i=0;i<count;i++)
    entries[i]->knapsackSolution = NO;
  for (i=count;i>0;i--) {
    if (j >= efflen[i-1]) {
      if (VARR(i-1, j-efflen[i-1]) + entries[i-1]->pri == VARR(i,j)) {
	j -= efflen[i-1];
	entries[i-1]->knapsackSolution = YES;
      }
    }
  }
  GNUNET_ASSERT(j == 0);
  FREE(v);
  FREE(efflen);
  cronTime(&endTime);

  return max;
}

/**
 * A new packet is supposed to be send out. Should it be
 * dropped because the load is too high?
 * <p>
 *
 * @param priority the highest priority of contents in the packet
 * @return OK if the packet should be handled, SYSERR if the packet should be dropped.
 */
static int outgoingCheck(unsigned int priority) {
  int load;
  unsigned int delta;

  load = getNetworkLoadUp(); /* how much free bandwidth do we have? */
  if (load >= 150) {
    return SYSERR; /* => always drop */
  }
  if (load > 100) {
    if (priority >= EXTREME_PRIORITY) {
      return OK; /* allow administrative msgs */
    } else {
      return SYSERR; /* but nothing else */
    }
  }
  if (load <= 50) { /* everything goes */
    return OK; /* allow */
  }
  /* Now load in [51, 100].  Between 51% and 100% load:
     at 51% require priority >= 1 = (load-50)^3
     at 52% require priority >= 8 = (load-50)^3
     at 75% require priority >= 15626 = (load-50)^3
     at 100% require priority >= 125000 = (load-50)^3
     (cubic function)
  */
  delta = load - 50; /* now delta is in [1,50] with 50 == 100% load */
  if (delta * delta * delta > priority ) {
#if DEBUG_POLICY
    LOG(LOG_DEBUG,
	"Network load is too high (%d%%, priority is %u, require %d), "
	"dropping outgoing.\n",
	load,
	priority,
	delta * delta * delta);
#endif
    return SYSERR; /* drop */
  } else {
#if DEBUG_POLICY
    LOG(LOG_DEBUG,
	"Network load is ok (%d%%, priority is %u >= %d), "
	"sending outgoing.\n",
	load,
	priority,
	delta * delta * delta);
#endif
    return OK; /* allow */
  }
}

/**
 * Check that the send frequency for this
 * buffer is not too high.
 *
 * @return OK if sending a message now is acceptable
 */
static int checkSendFrequency(BufferEntry * be) {
  if (be->max_bpm == 0)
    be->max_bpm = 1;

  if (be->session.mtu == 0) {
    be->MAX_SEND_FREQUENCY = /* ms per message */
      EXPECTED_MTU
      / (be->max_bpm * cronMINUTES / cronMILLIS) /* bytes per ms */
      / 2;
  } else {
    be->MAX_SEND_FREQUENCY = /* ms per message */
      be->session.mtu  /* byte per message */
      / (be->max_bpm * cronMINUTES / cronMILLIS) /* bytes per ms */
      / 2; /* some head-room */
  }
  /* Also: allow at least MINIMUM_SAMPLE_COUNT knapsack
     solutions for any MIN_SAMPLE_TIME! */
  if (be->MAX_SEND_FREQUENCY > MIN_SAMPLE_TIME / MINIMUM_SAMPLE_COUNT)
    be->MAX_SEND_FREQUENCY = MIN_SAMPLE_TIME / MINIMUM_SAMPLE_COUNT;

  if (be->lastSendAttempt + be->MAX_SEND_FREQUENCY > cronTime(NULL)) {
#if DEBUG_CONNECTION
    LOG(LOG_DEBUG,
	"Send frequency too high (CPU load), send deferred.\n");
#endif
    return NO; /* frequency too high, wait */
  }
  return OK;
}

/**
 * Select a subset of the messages for sending.
 *
 * @param *priority is set to the achieved message priority
 * @return total number of bytes of messages selected
 *   including P2P message header.
 */
static unsigned int selectMessagesToSend(BufferEntry * be,
                                         unsigned int *priority) {
  unsigned int totalMessageSize;
  SendEntry *entry;
  int i;
  int j;
  int approxProb;

  totalMessageSize = 0;
  (*priority) = 0;

  for (i=be->sendBufferSize-1;i>=0;i--)
    be->sendBuffer[i]->knapsackSolution = NO;

  if(be->session.mtu == 0) {
    totalMessageSize = sizeof(P2P_PACKET_HEADER);
    i = 0;
    /* assumes entries are sorted by priority! */
    while(i < be->sendBufferSize) {
      entry = be->sendBuffer[i];
      if((totalMessageSize + entry->len < MAX_BUFFER_SIZE) &&
         (entry->pri >= EXTREME_PRIORITY)) {
        entry->knapsackSolution = YES;
        (*priority) += entry->pri;
#if DEBUG_CONNECTION
        LOG(LOG_DEBUG, "Selecting msg %u with length %u\n", i, entry->len);
#endif
        totalMessageSize += entry->len;
      }
      else {
        entry->knapsackSolution = NO;
        break;
      }
      i++;
    }
    if((i == 0) && (be->sendBuffer[i]->len > be->available_send_window))
      return 0;                 /* always wait for the highest-priority
                                   message (otherwise large messages may
                                   starve! */
    while((i < be->sendBufferSize) &&
          (be->available_send_window > totalMessageSize)) {
      entry = be->sendBuffer[i];
      if((entry->len + totalMessageSize <=
          be->available_send_window) &&
         (totalMessageSize + entry->len < MAX_BUFFER_SIZE)) {
        entry->knapsackSolution = YES;
#if DEBUG_CONNECTION
        LOG(LOG_DEBUG, "Selecting msg %u with length %u\n", i, entry->len);
#endif
        totalMessageSize += entry->len;
        (*priority) += entry->pri;
      }
      else {
        entry->knapsackSolution = NO;
        if(totalMessageSize == sizeof(P2P_PACKET_HEADER)) {
          /* if the highest-priority message does not yet
             fit, wait for send window to grow so that
             we can get it out (otherwise we would starve
             high-priority, large messages) */
          return 0;
        }
      }
      i++;
    }
    if((totalMessageSize == sizeof(P2P_PACKET_HEADER)) ||
       (((*priority) < EXTREME_PRIORITY) &&
        ((totalMessageSize / sizeof(P2P_PACKET_HEADER)) < 4) &&
        (weak_randomi(16) != 0))) {
      /* randomization necessary to ensure we eventually send
         a small message if there is nothing else to do! */
      return 0;
    }
  }
  else {                        /* if (be->session.mtu == 0) */
    /* solve knapsack problem, compute accumulated priority */
    approxProb = getCPULoad();
    if(approxProb > 50) {
      if(approxProb > 100)
        approxProb = 100;
      approxProb = 100 - approxProb;  /* now value between 0 and 50 */
      approxProb *= 2;          /* now value between 0 [always approx] and 100 [never approx] */
      /* control CPU load probabilistically! */
      if(weak_randomi(1 + approxProb) == 0) {
        (*priority) = approximateKnapsack(be,
                                          be->session.mtu -
                                          sizeof(P2P_PACKET_HEADER));
#if DEBUG_COLLECT_PRIO == YES
        FPRINTF(prioFile, "%llu 0 %d\n", cronTime(NULL), priority);
#endif
      }
      else {
        (*priority) = solveKnapsack(be,
                                    be->session.mtu -
                                    sizeof(P2P_PACKET_HEADER));
#if DEBUG_COLLECT_PRIO == YES
        FPRINTF(prioFile, "%llu 1 %d\n", cronTime(NULL), priority);
#endif
      }
    }
    else {                      /* never approximate < 50% CPU load */
      (*priority) = solveKnapsack(be,
                                  be->session.mtu -
                                  sizeof(P2P_PACKET_HEADER));
#if DEBUG_COLLECT_PRIO == YES
      FPRINTF(prioFile, "%llu 2 %d\n", cronTime(NULL), priority);
#endif
    }
    j = 0;
    for(i = 0; i < be->sendBufferSize; i++)
      if(be->sendBuffer[i]->knapsackSolution == YES)
        j++;
    if(j == 0) {
      LOG(LOG_ERROR,
          _("`%s' selected %d out of %d messages (MTU: %d).\n"),
          "solveKnapsack",
          j, be->sendBufferSize, be->session.mtu - sizeof(P2P_PACKET_HEADER));

      for(j = 0; j < be->sendBufferSize; j++)
        LOG(LOG_ERROR,
            _("Message details: %u: length %d, priority: %d\n"),
            j, be->sendBuffer[j]->len, be->sendBuffer[j]->pri);
      return 0;
    }

    if(be->available_send_window < be->session.mtu) {
      /* if we have a very high priority, we may
         want to ignore bandwidth availability (e.g. for HANGUP,
         which  has EXTREME_PRIORITY) */
      if((*priority) < EXTREME_PRIORITY) {
#if DEBUG_CONNECTION
        LOG(LOG_DEBUG,
            "bandwidth limits prevent sending (send window %u too small).\n",
            be->available_send_window);
#endif
        return 0;               /* can not send, BPS available is too small */
      }
    }
    totalMessageSize = be->session.mtu;
  }                             /* end MTU > 0 */
  return totalMessageSize;
}


/**
 * Expire old messages from SendBuffer (to avoid
 * running out of memory).
 */
static void expireSendBufferEntries(BufferEntry * be) {
  unsigned long long msgCap;
  int i;
  SendEntry * entry;
  cron_t expired;
  int l;
  unsigned long long usedBytes;
  int j;

  /* if it's more than one connection "lifetime" old, always kill it! */
  expired = cronTime(&be->lastSendAttempt) - SECONDS_PINGATTEMPT * cronSECONDS;
#if DEBUG_CONNECTION
  LOG(LOG_DEBUG,
      "policy prevents sending message\n");
#endif

  l = getCPULoad();
  /* cleanup queue */
  msgCap = be->max_bpm; /* have minute of msgs, but at least one MTU */
  if (msgCap < EXPECTED_MTU)
    msgCap = EXPECTED_MTU;
  if (l < 50) { /* afford more if CPU load is low */
    if (l <= 0)
      l = 1;
    msgCap += (MAX_SEND_BUFFER_SIZE - EXPECTED_MTU) / l;
  }

  usedBytes = 0;
  /* allow at least msgCap bytes in buffer */
  for (i=0;i<be->sendBufferSize;i++)
    if (be->sendBuffer[i] != NULL)
      usedBytes += be->sendBuffer[i]->len;

  for (i=0;i<be->sendBufferSize;i++) { 	
    entry = be->sendBuffer[i];
    if (entry == NULL)
      continue;
    if (entry->transmissionTime <= expired) {
#if DEBUG_CONNECTION
      LOG(LOG_DEBUG,
	  "expiring message, expired %ds ago, queue size is %llu (bandwidth stressed)\n",
	  (int) ((cronTime(NULL) - entry->transmissionTime) / cronSECONDS),
	  usedBytes);
#endif
      if (stats != NULL) {
	stats->change(stat_messagesDropped, 1);
	stats->change(stat_sizeMessagesDropped, entry->len);
      }
      FREENONNULL(entry->closure);
      usedBytes -= entry->len;
      FREE(entry);
      be->sendBuffer[i] = NULL;
    }
  }

  /* cleanup/compact sendBuffer */
  j = 0;
  for (i=0;i<be->sendBufferSize;i++)
    if (be->sendBuffer[i] != NULL)
      be->sendBuffer[j++] = be->sendBuffer[i];
  GROW(be->sendBuffer,
       be->sendBufferSize,
       j);
}

/**
 * For each SendEntry of the BE that has
 * been selected by the knapsack solver,
 * call the callback and make sure that the
 * bytes are ready in entry->closure for
 * transmission.<p>
 *
 * If the preparation fails for an entry,
 * free it.
 * @return number of prepared entries
 */
static unsigned int prepareSelectedMessages(BufferEntry * be) {
  unsigned int ret;
  int i;
  char * tmpMsg;
  SendEntry * entry;

  ret = 0;
  for (i=0;i<be->sendBufferSize;i++) {
    entry = be->sendBuffer[i];

    if (entry->knapsackSolution == YES) {
      if (entry->callback != NULL) {
	tmpMsg = MALLOC(entry->len);
	if (OK == entry->callback(tmpMsg,
				  entry->closure,
				  entry->len)) {
	  entry->callback = NULL;
	  entry->closure = tmpMsg;
	  ret++;
	} else {
	  FREE(tmpMsg);
	  entry->callback = NULL;
	  entry->closure = NULL;
	  FREE(entry);
	  be->sendBuffer[i] = NULL;
	}
      } else {
	ret++;
      }
#if 0
      {
	P2P_MESSAGE_HEADER * hdr;
	EncName enc;

	hdr = (P2P_MESSAGE_HEADER*) entry->closure;
	IFLOG(LOG_DEBUG,
	      hash2enc(&be->session.sender.hashPubKey,
		       &enc));
	LOG(LOG_DEBUG,
	    "Core selected message of type %u and size %u for sending to peer `%s'.\n",
	    ntohs(hdr->type),
	    ntohs(hdr->size),
	    &enc);
      }
#endif
    }
  }
  return ret;
}

/**
 * Compute a random permuation of the send buffer
 * entry such that the selected messages obey
 * the SE flags.
 */
static int * permuteSendBuffer(BufferEntry * be) {
  int * perm;
  int headpos;
  int tailpos;
  int i;
  int j;

  perm = permute(WEAK, be->sendBufferSize);
  headpos = 0;
  tailpos = be->sendBufferSize-1;
  for (i=0;i<be->sendBufferSize;i++) {
    if (be->sendBuffer[perm[i]] == NULL)
      continue;	
    if (be->sendBuffer[perm[i]]->knapsackSolution == YES) {
      switch (be->sendBuffer[perm[i]]->flags & SE_PLACEMENT_FLAG) {
      case SE_FLAG_NONE:
	break;
      case SE_FLAG_PLACE_HEAD:
	/* swap slot with whoever is head now */
	j = perm[headpos];
	perm[headpos++] = perm[i];
	perm[i] = j;
	break;
      case SE_FLAG_PLACE_TAIL:
	/* swap slot with whoever is tail now */
	j = perm[tailpos];
	perm[tailpos--] = perm[i];
	perm[i] = j;
      }
    }
  }
  return perm;
}

/**
 * Free entries in send buffer that were
 * selected as the knapsack solution or
 * that are dead (callback and closure NULL).
 */
static void freeSelectedEntries(BufferEntry * be) {
  int i;
  SendEntry * entry;

  for (i=0;i<be->sendBufferSize;i++) {
    entry = be->sendBuffer[i];
    GNUNET_ASSERT(entry != NULL);
    if (entry->knapsackSolution == YES) {
      GNUNET_ASSERT(entry->callback == NULL);
      FREENONNULL(entry->closure);
      FREE(entry);
      be->sendBuffer[i] = NULL;
    } else if ( (entry->callback == NULL) &&
		(entry->closure == NULL) ) {
      FREE(entry);
      be->sendBuffer[i] = NULL;
    }
  }
}

/**
 * Try to make sure that the transport service for the given buffer is
 * connected.  If the transport service changes, this function also
 * ensures that the pending messages are properly fragmented (if
 * needed).
 *
 * @return OK on success, NO on error
 */
static int ensureTransportConnected(BufferEntry * be) {
  SendEntry ** entries;
  SendEntry * entry;
  int i;
  int ret;
  int j;
  int changed;

  if (be->session.tsession == NULL) {
    be->session.tsession
      = transport->connectFreely(&be->session.sender,
				 YES);
    if (be->session.tsession == NULL)
      return NO;
    be->session.mtu
      = transport->getMTU(be->session.tsession->ttype);
    if (be->session.mtu > 0) {
      /* MTU change may require new fragmentation! */
      changed = YES;
      while (changed) {
	changed = NO;
	entries = be->sendBuffer;
	i = 0;
	ret = be->sendBufferSize;
	while (i < ret) {
	  entry = entries[i];
	  if (entry->len > be->session.mtu - sizeof(P2P_PACKET_HEADER)) {
	    ret--;
	    for (j=i;j<ret;j++)
	      entries[j] = entries[j+1]; /* preserve ordering */
	    GROW(be->sendBuffer,
		 be->sendBufferSize,
		 ret);	
	    /* calling fragment will change be->sendBuffer;
	       thus we need to restart from the beginning afterwards... */
	    fragmentation->fragment(&be->session.sender,
				    be->session.mtu - sizeof(P2P_PACKET_HEADER),
				    entry->pri,
				    entry->transmissionTime,
				    entry->len,
				    entry->callback,
				    entry->closure);
	    FREE(entry);
	    changed = YES;
	    break;
	  } else {
	    i++;
	  }
	} /* for all i (until change) */
      } /* while changed */
    } /* if MTU changed */
  } /* if need to reconnect */
  return OK;
}


/**
 * Send a buffer; assumes that access is already synchronized.  This
 * message solves the knapsack problem, assembles the message
 * (callback to build parts from knapsack, callbacks for padding,
 * random noise padding, crc, encryption) and finally hands the
 * message to the transport service.
 *
 * @param be connection of the buffer that is to be transmitted
 */
static void sendBuffer(BufferEntry * be) {
  unsigned int i;
  unsigned int j;
  unsigned int p;
  unsigned int rsi;
  SendCallbackList * pos;
  P2P_PACKET_HEADER * p2pHdr;
  unsigned int priority;
  int * perm;
  char * plaintextMsg;
  void * encryptedMsg;
  unsigned int totalMessageSize;
  int ret;

  ENTRY();
  /* fast ways out */
  if (be == NULL) {
    BREAK();
    return;
  }
  if ( (be->status != STAT_UP) ||
       (be->sendBufferSize == 0) ||
       (be->inSendBuffer == YES) ) {
    return; /* must not run */
  }
  be->inSendBuffer = YES;

  if ( (OK != ensureTransportConnected(be)) ||
       (be->sendBufferSize == 0) ||
       (OK != checkSendFrequency(be)) ) {
    be->inSendBuffer = NO;
    return;
  }

  /* test if receiver has enough bandwidth available!  */
  updateCurBPS(be);
#if DEBUG_CONNECTION
  LOG(LOG_DEBUG,
      "receiver window available: %lld bytes (MTU: %u)\n",
      be->available_send_window,
      be->session.mtu);
#endif

  totalMessageSize = selectMessagesToSend(be,
					  &priority);
  if (totalMessageSize == 0) {
    expireSendBufferEntries(be);
    be->inSendBuffer = NO;
    return; /* deferr further */
  }
  GNUNET_ASSERT(totalMessageSize > sizeof(P2P_PACKET_HEADER));

  /* check if we (sender) have enough bandwidth available
     if so, trigger callbacks on selected entries; if either
     fails, return (but clean up garbage) */
  if ( (SYSERR == outgoingCheck(priority)) ||
       (0 == prepareSelectedMessages(be)) ) {
    expireSendBufferEntries(be);
    be->inSendBuffer = NO;
    return; /* deferr further */
  }

  /* get permutation of SendBuffer Entries
     such that SE_FLAGS are obeyed */
  perm = permuteSendBuffer(be);

  /* build message (start with sequence number) */
  plaintextMsg = MALLOC(totalMessageSize);
  p2pHdr = (P2P_PACKET_HEADER*) plaintextMsg;
  p2pHdr->timeStamp
    = htonl(TIME(NULL));
  p2pHdr->sequenceNumber
    = htonl(be->lastSequenceNumberSend);
  p2pHdr->bandwidth
    = htonl(be->idealized_limit);
  p = sizeof(P2P_PACKET_HEADER);

  for (i=0;i<be->sendBufferSize;i++) {
    SendEntry * entry = be->sendBuffer[perm[i]];

    if (entry == NULL)
      continue;
    if (entry->knapsackSolution == YES) {
#if DEBUG_CONNECTION
        LOG(LOG_DEBUG, "Queuing msg %u with length %u\n", perm[i], entry->len);
#endif
      GNUNET_ASSERT(entry->callback == NULL);
      GNUNET_ASSERT(p + entry->len <= totalMessageSize);
      memcpy(&plaintextMsg[p],
	     entry->closure,
	     entry->len);
      p += entry->len;
    }
  }
  FREE(perm);
  perm = NULL;

  /* still room left? try callbacks! */
  pos = scl_nextHead;
  while (pos != NULL) {
    if (pos->minimumPadding + p <= totalMessageSize) {
      p += pos->callback(&be->session.sender,
			 &plaintextMsg[p],
			 be->session.mtu - p);
    }
    pos = pos->next;
  }

  /* finally padd with noise */
  if ( (p + sizeof(P2P_MESSAGE_HEADER) <= totalMessageSize) &&
       (disable_random_padding == NO) ) {
    P2P_MESSAGE_HEADER * part;
    unsigned short noiseLen = totalMessageSize - p;

    part = (P2P_MESSAGE_HEADER *) &plaintextMsg[p];
    part->size
      = htons(noiseLen);
    part->type
      = htons(P2P_PROTO_noise);
    for (i=p+sizeof(P2P_MESSAGE_HEADER);
	 i < totalMessageSize;
	 i++)
      plaintextMsg[i] = (char) rand();
    p = totalMessageSize;
    if (stats != NULL)
      stats->change(stat_noise_sent,
		    noiseLen);
  }

  encryptedMsg = MALLOC(p);
  hash(&p2pHdr->sequenceNumber,
       p - sizeof(HashCode512),
       (HashCode512*) encryptedMsg);
  ret = encryptBlock(&p2pHdr->sequenceNumber,
	       p - sizeof(HashCode512),
	       &be->skey_local,
	       (const INITVECTOR*) encryptedMsg, /* IV */
	       &((P2P_PACKET_HEADER*)encryptedMsg)->sequenceNumber);
#if DEBUG_CONNECTION
  printMsg("Encrypting P2P data", &be->session.sender,
    &be->skey_local, (const INITVECTOR*) encryptedMsg,
    crc32N(&((P2P_PACKET_HEADER*)encryptedMsg)->sequenceNumber, ret));
#endif
  if (stats != NULL)
    stats->change(stat_encrypted,
		  p - sizeof(HashCode512));
  GNUNET_ASSERT(be->session.tsession != NULL);
  ret = transport->send(be->session.tsession,
			encryptedMsg,
			p);
  if ( (ret == NO) &&
       (priority >= EXTREME_PRIORITY) ) {
    ret = transport->sendReliable(be->session.tsession,
				  encryptedMsg,
				  p);
  }
  if (ret == YES) {
    if (be->available_send_window > totalMessageSize)
      be->available_send_window -= totalMessageSize;
    else
      be->available_send_window = 0; /* if we overrode limits,
					reset to 0 at least... */
    be->lastSequenceNumberSend++;
    if (be->idealized_limit > be->max_transmitted_limit)
      be->max_transmitted_limit
	= be->idealized_limit;
    else /* age */
      be->max_transmitted_limit
	= (be->idealized_limit + be->max_transmitted_limit*3)/4;

    if (rsnSize > 0) {
      j = sizeof(P2P_PACKET_HEADER);
      while (j < p) {
	P2P_MESSAGE_HEADER * part = (P2P_MESSAGE_HEADER*) &plaintextMsg[j];
	unsigned short plen = htons(part->size);
	if (plen < sizeof(P2P_MESSAGE_HEADER)) {
	  BREAK();
	  break;
	}
	for (rsi=0;rsi<rsnSize;rsi++)
	  rsns[rsi](&be->session.sender,
		    part);
	j += plen;
      }
    }
    freeSelectedEntries(be);
  }
  if ( (ret == SYSERR) &&
       (be->session.tsession != NULL) ) {
    transport->disconnect(be->session.tsession);
    be->session.tsession = NULL;
  }

  FREE(encryptedMsg);
  FREE(plaintextMsg);
  expireSendBufferEntries(be);
  be->inSendBuffer = NO;
}

/**
 * Append a message to the current buffer. This method
 * assumes that the access to be is already synchronized.
 *
 * @param be on which connection to transmit
 * @param se what to transmit (with meta-data)
 */
static void appendToBuffer(BufferEntry * be,
			   SendEntry * se) {
#if DEBUG_CONNECTION
  EncName enc;
#endif
  float apri;
  unsigned int i;
  SendEntry ** ne;
  unsigned long long queueSize;

  ENTRY();
  if ( (se == NULL) || (se->len == 0) ) {
    BREAK();
    FREENONNULL(se);
    return;
  }
  if ( (be->session.mtu != 0) &&
       (se->len > be->session.mtu - sizeof(P2P_PACKET_HEADER)) ) {
    /* this message is so big that it must be fragmented! */
    fragmentation->fragment(&be->session.sender,
			    be->session.mtu - sizeof(P2P_PACKET_HEADER),
			    se->pri,
			    se->transmissionTime,
			    se->len,
			    se->callback,
			    se->closure);
    FREE(se);
    return;
  }

#if DEBUG_CONNECTION
  IFLOG(LOG_DEBUG,
	hash2enc(&be->session.sender.hashPubKey,
		 &enc));
  LOG(LOG_DEBUG,
      "adding message of size %d to buffer of host %s.\n",
      se->len,
      &enc);
#endif
  if ( (be->sendBufferSize > 0) &&
       (be->status != STAT_UP) ) {
    /* as long as we do not have a confirmed
       connection, do NOT queue messages! */
#if DEBUG_CONNECTION
    LOG(LOG_DEBUG,
	"not connected to %s, message dropped\n",
	&enc);
#endif
    FREE(se->closure);
    FREE(se);
    return;
  }
  queueSize = 0;
  for (i=0;i<be->sendBufferSize;i++)
    queueSize += be->sendBuffer[i]->len;

  if (queueSize >= MAX_SEND_BUFFER_SIZE) {
    /* first, try to remedy! */
    sendBuffer(be);
    /* did it work? */

    queueSize = 0;
    for (i=0;i<be->sendBufferSize;i++)
      queueSize += be->sendBuffer[i]->len;

    if (queueSize >= MAX_SEND_BUFFER_SIZE) {
      /* we need to enforce some hard limit here, otherwise we may take
	 FAR too much memory (200 MB easily) */
#if DEBUG_CONNECTION
      LOG(LOG_DEBUG,
	  "queueSize (%llu) >= %d, refusing to queue message.\n",
	  queueSize,
	  MAX_SEND_BUFFER_SIZE);
#endif
      FREE(se->closure);
      FREE(se);
      return;
    }
  }
  /* grow send buffer, insertion sort! */
  ne = MALLOC( (be->sendBufferSize+1) * sizeof(SendEntry*));
  GNUNET_ASSERT(se->len != 0);
  apri = (float) se->pri / (float) se->len;
  i=0;
  while ( (i < be->sendBufferSize) &&
	  ( ((float)be->sendBuffer[i]->pri /
	     (float)be->sendBuffer[i]->len) >= apri) ) {
    ne[i] = be->sendBuffer[i];
    i++;
  }
  ne[i++] = se;
  while (i < be->sendBufferSize+1) {
    ne[i] = be->sendBuffer[i-1];
    i++;
  }
  FREENONNULL(be->sendBuffer);
  be->sendBuffer = ne;
  be->sendBufferSize++;
  sendBuffer(be);
}

/**
 * Look for a host in the table. If the entry is there at the time of
 * checking, returns the entry.
 *
 * @param hostId the ID of the peer for which the connection is returned
 * @return the connection of the host in the table, NULL if not connected
 */
static BufferEntry * lookForHost(const PeerIdentity * hostId) {
  BufferEntry * root;

  root = CONNECTION_buffer_[computeIndex(hostId)];
  while (root != NULL) {
    if (equalsHashCode512(&hostId->hashPubKey,
			  &root->session.sender.hashPubKey))
      return root;
    root = root->overflowChain;
  }
  return NULL;
}

/**
 * Force adding of a host to the buffer. If the node is already in the
 * table, the table entry is returned.  If the connection is down,
 * the session service is asked to try to establish a connection.
 *
 * The connection lock must be held when calling this function.
 *
 * @param establishSession should we try to establish a session?
 * @param hostId for which peer should we get/create a connection
 * @return the table entry for the host
 */
static BufferEntry * addHost(const PeerIdentity * hostId,
			     int establishSession) {
  BufferEntry * root;
  BufferEntry * prev;
#if DEBUG_CONNECTION
  EncName enc;

  IFLOG(LOG_EVERYTHING,
	hash2enc(&hostId->hashPubKey,
		 &enc));
  LOG(LOG_EVERYTHING,
      "Adding host `%s' to the connection table.\n",
      &enc);
#endif

  ENTRY();
  root = lookForHost(hostId);
  if (root == NULL) {
    root = CONNECTION_buffer_[computeIndex(hostId)];
    prev = NULL;
    while (NULL != root) {
      /* settle for entry in the linked list that is down */
      if ( (root->status == STAT_DOWN) ||
	   (equalsHashCode512(&hostId->hashPubKey,
			      &root->session.sender.hashPubKey)) )
	break;
      prev = root;
      root = root->overflowChain;
    }
    if (root == NULL) {
      root = initBufferEntry();
      if (prev == NULL)
	CONNECTION_buffer_[computeIndex(hostId)] = root;
      else
	prev->overflowChain = root;
    }
    root->session.sender = *hostId;
  }
  if ( (root->status == STAT_DOWN) &&
       (establishSession == YES) ) {
    root->lastSequenceNumberReceived = 0;
    session->tryConnect(hostId);
  }
  return root;
}

/**
 * Perform an operation for all connected hosts.  The BufferEntry
 * structure is passed to the method.  No synchronization or other
 * checks are performed.
 *
 * @param method the method to invoke (NULL for couting only)
 * @param arg the second argument to the method
 * @return the number of connected hosts
 */
static int forAllConnectedHosts(BufferEntryCallback method,
				void * arg) {
  unsigned int i;
  int count = 0;
  BufferEntry * be;

  ENTRY();
  for (i=0;i<CONNECTION_MAX_HOSTS_;i++) {
    be = CONNECTION_buffer_[i];
    while (be != NULL) {
      if (be->status == STAT_UP) {
        if (method != NULL)
  	  method(be, arg);
        count++;
      }
      be = be->overflowChain;
    }
  }
  return count;
}

/**
 * Little helper function for forEachConnectedNode.
 *
 * @param be the connection
 * @param arg closure of type fENHWrap giving the function
 *        to call
 */
static void fENHCallback(BufferEntry * be,
			 void * arg) {
  fENHWrap * wrap;

  wrap = (fENHWrap*) arg;
  if (wrap->method != NULL)
    wrap->method(&be->session.sender,
		 wrap->arg);
}


/**
 * Copy the pre-build message part of lenth "len" in closure to the
 * buffer buf. Frees the closure.
 *
 * @param buf the target location where the message is assembled
 * @param closure the pre-build message
 * @param len the length of the pre-build message
 * @return OK (always successful)
 */
static int copyCallback(void * buf,
			void * closure,
			unsigned short len) {
  if (len > 0) {
    memcpy(buf, closure, len);
    FREE(closure);
    return OK;
  } else {
    FREE(closure);
    return SYSERR;
  }
}

/**
 * Shutdown the connection.  Send a HANGUP message to the other side
 * and mark the sessionkey as dead.
 *
 * @param be the connection to shutdown
 */
static void shutdownConnection(BufferEntry * be) {
  P2P_hangup_MESSAGE hangup;
  unsigned int i;
#if DEBUG_CONNECTION
  EncName enc;
#endif

  ENTRY();
#if DEBUG_CONNECTION
  IFLOG(LOG_DEBUG,
	hash2enc(&be->session.sender.hashPubKey,
		 &enc));
  LOG(LOG_DEBUG,
      "Shutting down connection with `%s'\n",
      &enc);
#endif
  if (be->status == STAT_DOWN)
    return; /* nothing to do */
  if (be->status == STAT_UP) {
    SendEntry * se;

    hangup.header.type
      = htons(P2P_PROTO_hangup);
    hangup.header.size
      = htons(sizeof(P2P_hangup_MESSAGE));
    identity->getPeerIdentity(identity->getPublicPrivateKey(),
			      &hangup.sender);
    se = MALLOC(sizeof(SendEntry));
    se->len
      = sizeof(P2P_hangup_MESSAGE);
    se->flags
      = SE_FLAG_PLACE_TAIL;
    se->pri
      = EXTREME_PRIORITY;
    se->transmissionTime
      = cronTime(NULL); /* now */
    se->callback
      = &copyCallback;
    se->closure
      = MALLOC(sizeof(P2P_hangup_MESSAGE));
    se->knapsackSolution 
      = NO;
    memcpy(se->closure,
	   &hangup,
	   sizeof(P2P_hangup_MESSAGE));
    appendToBuffer(be, se);
    if (stats != NULL)
      stats->change(stat_hangupSent,
		    1);
    /* override send frequency and
       really try hard to get the HANGUP
       out! */
    be->lastSendAttempt = 0;
    sendBuffer(be);
  }
  be->skey_remote_created = 0;
  be->status = STAT_DOWN;
  be->idealized_limit = MIN_BPM_PER_PEER;
  be->max_transmitted_limit = MIN_BPM_PER_PEER;
  if (be->session.tsession != NULL) {
    transport->disconnect(be->session.tsession);
    be->session.tsession = NULL;
  }
  for (i=0;i<be->sendBufferSize;i++) {
    FREENONNULL(be->sendBuffer[i]->closure);
    FREE(be->sendBuffer[i]);
  }
  GROW(be->sendBuffer,
       be->sendBufferSize,
       0);
}

/* ******** inbound bandwidth scheduling ************* */		

static void gatherEntries(BufferEntry * be,
			  UTL_Closure * utl) {
  utl->e[utl->pos++] = be;
}

static void resetRecentlyReceived(BufferEntry * be,
				  void * unused) {
  be->recently_received = 0;
}

/**
 * What is the function used to weigh the value of
 * the connection for bandwidth allocation?
 * Ok, with this API we can not implement "max takes all",
 * but it is possible to use:
 *
 * - proportional share: (x) [ bandwidth proportional to contribution ]
 * - square-root (sqrt(x))  [ contributing a lot more gives a little gain ]
 * - square share: (x*x) [ Bush's tax system: if you're rich, you get even more ]
 *
 * Pretty much every monotonically increasing, always
 * positive function can be used.  The main loop normalizes later.
 */
#define SHARE_DISTRIBUTION_FUNCTION(be) (be->current_connection_value)

/**
 * What is the minimum number of peers to connect to that is
 * still acceptable? (By dividing CONNECTION_MAX_HOSTS_ by
 * two, we specify to maintain at least 50% of the maximum
 * number of connections).
 */
static unsigned int minConnect() {
  return CONNECTION_MAX_HOSTS_/2;
}

/**
 * Schedule the available inbound bandwidth among the peers.  Note
 * that this function is called A LOT (dozens of times per minute), so
 * it should execute reasonably fast.
 */
static void scheduleInboundTraffic() {
  unsigned int activePeerCount;
  static cron_t lastRoundStart = 0;
  UTL_Closure utl;
  static cron_t timeDifference;
  cron_t now;
  BufferEntry ** entries;
  double * shares;
  double shareSum;
  unsigned int u;
  unsigned int minCon;
  long long schedulableBandwidth;
  long long decrementSB;
  long long * adjustedRR;
  int didAssign;
  int firstRound;
  int earlyRun;
  int load;

  MUTEX_LOCK(&lock);
  cronTime(&now);

  /* if this is the first round, don't bother... */
  if (lastRoundStart == 0) {
    /* no allocation the first time this function is called! */
    lastRoundStart = now;
    forAllConnectedHosts(&resetRecentlyReceived,
			 NULL);
    MUTEX_UNLOCK(&lock);
    return;
  }

  activePeerCount = forAllConnectedHosts(NULL, NULL);
  if (activePeerCount == 0) {
    MUTEX_UNLOCK(&lock);
    return; /* nothing to be done here. */
  }


 /* if time difference is too small, we don't have enough
     sample data and should NOT update the limits;
     however, if we have FAR to few peers, reschedule
     aggressively (since we are unlikely to get close
     to the limits anyway) */
  timeDifference = now - lastRoundStart;
  earlyRun = 0;
  if (timeDifference < MIN_SAMPLE_TIME) {
    earlyRun = 1;
    if  (activePeerCount > CONNECTION_MAX_HOSTS_ / 16) {
      MUTEX_UNLOCK(&lock);
      return; /* don't update too frequently, we need at least some
		 semi-representative sampling! */
    }
  }
  if (timeDifference == 0)
    timeDifference = 1;

  /* build an array containing all BEs */

  entries = MALLOC(sizeof(BufferEntry*)*activePeerCount);
  utl.pos = 0;
  utl.e = entries;
  forAllConnectedHosts((BufferEntryCallback)&gatherEntries,
		       &utl);


  /* compute shares */
  shares = MALLOC(sizeof(double)*activePeerCount);
  shareSum = 0.0;
  for (u=0;u<activePeerCount;u++) {
    shares[u] = SHARE_DISTRIBUTION_FUNCTION(entries[u]);
    if (shares[u] < 0.0)
      shares[u] = 0.0;
    shareSum += shares[u];
  }

  /* normalize distribution */
  if (shareSum >= 0.00001) { /* avoid numeric glitches... */
    for (u=0;u<activePeerCount;u++) 
      shares[u] = shares[u] / shareSum;    
  } else {
    for (u=0;u<activePeerCount;u++)
      shares[u] = 1 / activePeerCount;
  }

  /* compute how much bandwidth we can bargain with */
  minCon = minConnect();
  if (minCon > activePeerCount)
    minCon = activePeerCount;
  schedulableBandwidth
    = max_bpm - minCon * MIN_BPM_PER_PEER;
  load = getNetworkLoadDown();
  if (load > 100) {
    /* take counter measures! */
    schedulableBandwidth = schedulableBandwidth * 100 / load;
    /* make sure we do not take it down too far */
    if ( (schedulableBandwidth < minCon * MIN_BPM_PER_PEER / 2) &&
	 (max_bpm > minCon * MIN_BPM_PER_PEER * 2) )
      schedulableBandwidth = minCon * MIN_BPM_PER_PEER / 2;
  }

  adjustedRR = MALLOC(sizeof(long long) * activePeerCount);

  /* reset idealized limits; if we want a smoothed-limits
     algorithm, we'd need to compute the new limits separately
     and then merge the values; but for now, let's just go
     hardcore and adjust all values rapidly */
  GNUNET_ASSERT(timeDifference != 0);
  for (u=0;u<activePeerCount;u++) {
    adjustedRR[u] = entries[u]->recently_received * cronMINUTES / timeDifference / 2;

#if DEBUG_CONNECTION
    if (adjustedRR[u] > entries[u]->idealized_limit) {
      EncName enc;
      IFLOG(LOG_INFO,
	    hash2enc(&entries[u]->session.sender.hashPubKey,
		     &enc));
      LOG(LOG_INFO,
	  "peer `%s' transmitted above limit: %llu bpm > %u bpm\n",
	  &enc,
	  adjustedRR[u],
	  entries[u]->idealized_limit);
    }
#endif
    /* Check for peers grossly exceeding send limits. Be a bit
     * reasonable and make the check against the max value we have
     * sent to this peer (assume announcements may have got lost).
     */
    if ( (earlyRun == 0) &&
	 (adjustedRR[u] > 2 * MAX_BUF_FACT *
	  entries[u]->max_transmitted_limit) &&
	 (adjustedRR[u] > 2 * MAX_BUF_FACT *
	  entries[u]->idealized_limit) ) {	
      EncName enc;

      entries[u]->violations++;
      entries[u]->recently_received = 0; /* "clear" slate */
      if (entries[u]->violations > 10) {
	IFLOG(LOG_INFO,
	      hash2enc(&entries[u]->session.sender.hashPubKey,
		       &enc));
	LOG(LOG_INFO,
	    "blacklisting `%s': sent repeatedly %llu bpm "
	    "(limit %u bpm, target %u bpm)\n",
	    &enc,
	    adjustedRR[u],
	    entries[u]->max_transmitted_limit,
	    entries[u]->idealized_limit);
	identity->blacklistHost(&entries[u]->session.sender,
				1 / topology->getSaturation(),
				YES);
	shutdownConnection(entries[u]);
	activePeerCount--;
	entries[u]    = entries[activePeerCount];
	shares[u]     = shares[activePeerCount];
	adjustedRR[u] = adjustedRR[activePeerCount];
	u--;
	continue;
      }
    } else {
      if ( (earlyRun == 0) &&
	   (adjustedRR[u] < entries[u]->max_transmitted_limit/2) &&
	   (entries[u]->violations > 0) ) {
	/* allow very low traffic volume to
	   balance out (rare) times of high
	   volume */
	entries[u]->violations--;
      }
    }

    if (adjustedRR[u] < MIN_BPM_PER_PEER/2)
      adjustedRR[u] = MIN_BPM_PER_PEER/2;
    /* even if we received NO traffic, allow
       at least MIN_BPM_PER_PEER */
  }

  /* now distribute the schedulableBandwidth according
     to the shares.  Note that since we cap peers at twice
     of what they transmitted last, we may not be done with
     just one pass.

     We don't wait until schedulableBandwidth hits 0 since that may
     take forever (due to rounding you can even take that literally).
     The "100" equates to 100 bytes per peer (per minute!) being
     potentially under-allocated.  Since there's always some
     (unencrypted) traffic that we're not quite accounting for anyway,
     that's probably not so bad. */
  didAssign = YES;
  /* in the first round we cap by 2* previous utilization */
  firstRound = YES;
  for (u=0;u<activePeerCount;u++)
    entries[u]->idealized_limit = 0;
  while ( (schedulableBandwidth > CONNECTION_MAX_HOSTS_ * 100) &&
	  (activePeerCount > 0) &&
	  (didAssign == YES) ) {
    didAssign = NO;
    decrementSB = 0;
    for (u=0;u<activePeerCount;u++) {
      /* always allow allocating MIN_BPM_PER_PEER */
      if ( (firstRound == NO) ||
	   (entries[u]->idealized_limit < adjustedRR[u] * 2) ) {
	unsigned int share;

	share = entries[u]->idealized_limit + (unsigned int) (shares[u] * schedulableBandwidth);
	if (share < entries[u]->idealized_limit) 
	  share = 0xFFFFFFFF;  /* int overflow */
	if ( (share > adjustedRR[u] * 2) &&
	     (firstRound == YES) )
	  share = adjustedRR[u] * 2;
	if (share > entries[u]->idealized_limit) {
	  decrementSB += share - entries[u]->idealized_limit;
	  didAssign = YES;	
	}
	if ( (share < MIN_BPM_PER_PEER) &&
	     (minCon > 0) ) {
	  /* use one of the minCon's to keep the connection! */
	  decrementSB -= share;
	  share = MIN_BPM_PER_PEER;
	  minCon--;
	} 
	entries[u]->idealized_limit = share;
      }
    }
    if (decrementSB > schedulableBandwidth) {
      schedulableBandwidth -= decrementSB;
    } else {
      schedulableBandwidth = 0;
      break;
    }
    if ( (activePeerCount > 0) &&
	 (didAssign == NO) ) {
      int * perm = permute(WEAK, activePeerCount);
      /* assign also to random "worthless" (zero-share) peers */
      for (u=0;u<activePeerCount;u++) {
	unsigned int v = perm[u]; /* use perm to avoid preference to low-numbered slots */
	if ( (firstRound == NO) ||
	     (entries[v]->idealized_limit < adjustedRR[u] * 2) ) {
	  unsigned int share;

	  share = entries[v]->idealized_limit + (unsigned int) (schedulableBandwidth);
	  if (share < entries[u]->idealized_limit) 
	    share = 0xFFFFFFFF;  /* int overflow */
	  if ( (firstRound == YES) &&
	       (share > adjustedRR[u] * 2) )
	    share = adjustedRR[u] * 2;
	  schedulableBandwidth -= share - entries[v]->idealized_limit;
	  entries[v]->idealized_limit = share;
	}
      }
      FREE(perm);
      perm = NULL;

      if ( (schedulableBandwidth > 0) &&
	   (activePeerCount > 0) ) {
	/* assign rest disregarding traffic limits */
	perm = permute(WEAK, activePeerCount);
	for (u=0;u<activePeerCount;u++) {
	  unsigned int share;

	  share = entries[perm[u]]->idealized_limit + (unsigned int) (schedulableBandwidth/activePeerCount);	
	  if (share > entries[perm[u]]->idealized_limit) /* no int-overflow? */
	    entries[perm[u]]->idealized_limit = share;
	}
	schedulableBandwidth = 0;
	FREE(perm);
	perm = NULL;
      }
    } /* didAssign == NO? */
    if (firstRound == YES) {
      /* keep some bandwidth off the market
	 for new connections */
      schedulableBandwidth /= 2;
    }
    firstRound = NO;
  } /* while bandwidth to distribute */


  /* randomly add the remaining MIN_BPM_PER_PEER to minCon peers; yes, this will
     yield some fluctuation, but some amount of fluctuation should be
     good since it creates opportunities. */
  if (activePeerCount > 0)
    for (u=0;u<minCon;u++)
      entries[weak_randomi(activePeerCount)]->idealized_limit
	+= MIN_BPM_PER_PEER;

  /* prepare for next round */
  lastRoundStart = now;
  for (u=0;u<activePeerCount;u++) {
#if DEBUG_CONNECTION
    EncName enc;

    IFLOG(LOG_DEBUG,
	  hash2enc(&entries[u]->session.sender.hashPubKey,
		   &enc));
    LOG(LOG_DEBUG,
	"inbound limit for peer %u: %s set to %u bpm\n",
	u,
	&enc,
	entries[u]->idealized_limit);
#endif
    entries[u]->current_connection_value /= 2.0;
    entries[u]->recently_received /= 2;
  }

  /* free memory */
  FREE(adjustedRR);
  FREE(shares);
  FREE(entries);
  for (u=0;u<CONNECTION_MAX_HOSTS_;u++) {
    BufferEntry * be = CONNECTION_buffer_[u];
    if (be == NULL)
      continue;
    if (be->idealized_limit < MIN_BPM_PER_PEER) {
#if DEBUG_CONNECTION || 1
      EncName enc;
      
      IFLOG(LOG_DEBUG,
	    hash2enc(&be->session.sender.hashPubKey,
		     &enc));
      LOG(LOG_DEBUG,
	  "Number of connections too high, shutting down low-traffic connection to %s (had only %u bpm)\n",
	  &enc,
	  be->idealized_limit);
#endif
      shutdownConnection(be);
    }
  }

  MUTEX_UNLOCK(&lock);
}

/* ******** end of inbound bandwidth scheduling ************* */


/**
 * Call this method periodically to drop dead connections.
 *
 * @param unused not used, just to make signature type nicely
 */
static void cronDecreaseLiveness(void * unused) {
  BufferEntry * root;
  BufferEntry * prev;
  BufferEntry * tmp;
  cron_t now;
  int i;

  scheduleInboundTraffic();
  cronTime(&now);
  MUTEX_LOCK(&lock);
  for (i=0;i<CONNECTION_MAX_HOSTS_;i++) {
    root = CONNECTION_buffer_[i];
    prev = NULL;
    while (NULL != root) {
      switch (root->status) {
      case STAT_DOWN:
	/* just compact linked list */
	if (prev == NULL)
	  CONNECTION_buffer_[i] = root->overflowChain;
	else
	  prev->overflowChain = root->overflowChain;
	tmp = root;
	root = root->overflowChain;
	FREE(tmp);
	continue; /* no need to call 'send buffer' */
      case STAT_UP:
	if ( (now > root->isAlive) && /* concurrency might make this false... */
	     (now - root->isAlive > SECONDS_INACTIVE_DROP * cronSECONDS) ) {
	  EncName enc;
	
	  /* switch state form UP to DOWN: too much inactivity */
	  IFLOG(LOG_DEBUG,
		hash2enc(&root->session.sender.hashPubKey,
			 &enc));
	  LOG(LOG_DEBUG,
	      "closing connection with `%s': "
	      "too much inactivity (%llu ms)\n",
	      &enc,
	      now - root->isAlive);
	  shutdownConnection(root);
	  /* the host may still be worth trying again soon: */
	  identity->whitelistHost(&root->session.sender);
	}
	if ( (root->available_send_window >= 60000) &&
	     (root->sendBufferSize < 4) &&
	     (scl_nextHead != NULL) &&
	     (getNetworkLoadUp() < 25) &&
	     (getCPULoad() < 50) ) {
	  /* create some traffic by force! */
	  char * msgBuf;
	  unsigned int mSize;
	  SendCallbackList * pos;

	  msgBuf = MALLOC(60000);
	  pos = scl_nextHead;
	  while (pos != NULL) {
	    if (pos->minimumPadding <= 60000) {
	      mSize = pos->callback(&root->session.sender,
				    msgBuf,
				    60000);
	      if (mSize > 0)
		unicast(&root->session.sender,
			(P2P_MESSAGE_HEADER*) msgBuf,
			0,
			5 * cronMINUTES);
	    }	    
	    pos = pos->next;
	  }
	  FREE(msgBuf);
	}

	break;
      default: /* not up, not down - partial SETKEY exchange */
	if ( (now > root->isAlive) &&
	     (now - root->isAlive > SECONDS_NOPINGPONG_DROP * cronSECONDS) ) {
	  EncName enc;
	  IFLOG(LOG_DEBUG,
		hash2enc(&root->session.sender.hashPubKey, &enc));
	  LOG(LOG_DEBUG,
	      "closing connection to %s: %s not answered.\n",
	      &enc,
	      (root->status == STAT_SETKEY_SENT) ? "SETKEY" : "PING");
	  shutdownConnection(root);
	}
	break;
      } /* end of switch */
      sendBuffer(root);
      prev = root;
      root = root->overflowChain;
    } /* end of while */
  } /* for all buckets */

  MUTEX_UNLOCK(&lock);
}

/**
 * Check the sequence number and timestamp.  Decrypts the
 * message if it was encrypted.  Updates the sequence
 * number as a side-effect.
 *
 * @param sender from which peer did we receive the SEQ message
 * @param msg the p2p message (the decrypted message is stored here, too!)
 * @param size the size of the message
 * @return YES if the message was encrypted,
 *         NO if it was in plaintext,
 *         SYSERR if it was malformed
 */
int checkHeader(const PeerIdentity * sender,
		P2P_PACKET_HEADER * msg,
		unsigned short size) {
  BufferEntry * be;
  int res;
  unsigned int sequenceNumber;
  TIME_T stamp;
  char * tmp;
  HashCode512 hc;
  EncName enc;

  ENTRY();
  GNUNET_ASSERT(msg != NULL);
  GNUNET_ASSERT(sender != NULL);
  hash2enc(&sender->hashPubKey,
	   &enc);
  if (size < sizeof(P2P_PACKET_HEADER)) {
    LOG(LOG_WARNING,
	_("Message from `%s' discarded: invalid format.\n"),
	&enc);
    return SYSERR;
  }
  hash2enc(&sender->hashPubKey,
	   &enc);
  hash(&msg->sequenceNumber,
       size - sizeof(HashCode512),
       &hc);
  if ( equalsHashCode512(&hc,
			 &msg->hash) &&
       (msg->sequenceNumber == 0) &&
       (msg->bandwidth == 0) &&
       (msg->timeStamp == 0) )
    return NO; /* plaintext */

#if DEBUG_CONNECTION
  LOG(LOG_DEBUG,
      "Decrypting message from host `%s'\n",
      &enc);
#endif
  MUTEX_LOCK(&lock);
  be = lookForHost(sender);
  if ( (be == NULL) ||
       (be->status == STAT_DOWN) ||
       (be->status == STAT_SETKEY_SENT) ) {
    LOG(LOG_INFO,
	"Decrypting message from host `%s' failed, no sessionkey (yet)!\n",
	&enc);
    /* try to establish a connection, that way, we don't keep
       getting bogus messages until the other one times out. */
    if ( (be == NULL) || (be->status == STAT_DOWN) )
      addHost(sender, YES);
    MUTEX_UNLOCK(&lock);
    return SYSERR; /* could not decrypt */
  }
  tmp = MALLOC(size - sizeof(HashCode512));
  res = decryptBlock(&be->skey_remote,
		     &msg->sequenceNumber,
		     size - sizeof(HashCode512),
		     (const INITVECTOR*) &msg->hash, /* IV */
		     tmp);
  hash(tmp,
       size - sizeof(HashCode512),
       &hc);
  if ( ! ( (res != OK) &&
	   equalsHashCode512(&hc,
			     &msg->hash)) ) {
    LOG(LOG_INFO,
	"Decrypting message from host `%s' failed, wrong sessionkey!\n",
	&enc);
#if DEBUG_CONNECTION
    printMsg("Wrong sessionkey", sender,
      &be->skey_remote, (const INITVECTOR *) &msg->hash,
      crc32N(&msg->sequenceNumber, size - sizeof(HashCode512)));
#endif
    addHost(sender, YES);
    MUTEX_UNLOCK(&lock);
    FREE(tmp);
    return SYSERR;
  }
  if (stats != NULL)
    stats->change(stat_decrypted,
		  size - sizeof(HashCode512));
  memcpy(&msg->sequenceNumber,
	 tmp,
	 size - sizeof(HashCode512));
  FREE(tmp);
  res = YES;
  sequenceNumber = ntohl(msg->sequenceNumber);
  if (be->lastSequenceNumberReceived >= sequenceNumber) {
    res = SYSERR;
    if ( (be->lastSequenceNumberReceived - sequenceNumber <= 32) &&
	 (be->lastSequenceNumberReceived != sequenceNumber) ) {
      unsigned int rotbit = 1 << (be->lastSequenceNumberReceived - sequenceNumber - 1);
      if ( (be->lastPacketsBitmap & rotbit) == 0) {
	be->lastPacketsBitmap |= rotbit;
	res = OK;
      }
    }
    if (res == SYSERR) {
      LOG(LOG_WARNING,
	  _("Invalid sequence number"
	    " %u <= %u, dropping message.\n"),
	  sequenceNumber,
	  be->lastSequenceNumberReceived);
      MUTEX_UNLOCK(&lock);
      return SYSERR;
    }
  } else {
    be->lastPacketsBitmap =
      be->lastPacketsBitmap
      << (sequenceNumber - be->lastSequenceNumberReceived);
    be->lastSequenceNumberReceived = sequenceNumber;
  }
  stamp = ntohl(msg->timeStamp);
  if (stamp + 1 * cronDAYS < TIME(NULL)) {
    LOG(LOG_INFO,
	_("Message received more than one day old. Dropped.\n"));
    MUTEX_UNLOCK(&lock);
    return SYSERR;
  }

  be->max_bpm = ntohl(msg->bandwidth);
#if DEBUG_CONNECTION
  LOG(LOG_DEBUG,
      "Received bandwidth cap of %u bpm\n",
      be->max_bpm);
#endif
  if (be->available_send_window >= be->max_bpm) {
    be->available_send_window = be->max_bpm;
    cronTime(&be->last_bps_update);
  }
  be->recently_received += size;
  MUTEX_UNLOCK(&lock);
  return YES;
}

/**
 * Handler for processing P2P HANGUP message.  Terminates
 * a connection (if HANGUP message is valid).
 *
 * @param sender the peer sending the HANGUP message
 * @param msg the HANGUP message
 * @return OK on success, SYSERR on error
 */
static int handleHANGUP(const PeerIdentity * sender,
			const P2P_MESSAGE_HEADER * msg) {
  BufferEntry * be;
  EncName enc;

  ENTRY();
  if (ntohs(msg->size) != sizeof(P2P_hangup_MESSAGE))
    return SYSERR;
  if (!hostIdentityEquals(sender,
			  &((P2P_hangup_MESSAGE*)msg)->sender))
    return SYSERR;
  IFLOG(LOG_INFO,
	hash2enc(&sender->hashPubKey,
		 &enc));
  LOG(LOG_INFO,
      "received HANGUP from `%s'\n",
      &enc);
  MUTEX_LOCK(&lock);
  be = lookForHost(sender);
  if (be == NULL) {
    MUTEX_UNLOCK(&lock);
    return SYSERR;
  }
  shutdownConnection(be);
  MUTEX_UNLOCK(&lock);
  return OK;
}


/**
 * Assign a session key for traffic from or to a given peer.
 * If the core does not yet have an entry for the given peer
 * in the connection table, a new entry is created.
 *
 * @param key the sessionkey,
 * @param peer the other peer,
 * @param forSending NO if it is the key for receiving,
 *                   YES if it is the key for sending
 */
void assignSessionKey(const SESSIONKEY * key,
		      const PeerIdentity * peer,
		      TIME_T age,
		      int forSending) {
  BufferEntry * be;

  MUTEX_LOCK(&lock);
  be = lookForHost(peer);
  if (be == NULL)
    be = addHost(peer, NO);
  if (be != NULL) {
    cronTime(&be->isAlive);
    if (forSending == YES) {
      be->skey_local = *key;
      be->skey_local_created = age;
      be->status = STAT_SETKEY_SENT | (be->status & STAT_SETKEY_RECEIVED);
    } else { /* for receiving */
      if ( ((be->status & STAT_SETKEY_RECEIVED) == 0) ||
	   (be->skey_remote_created < age) ) {
	if (0 != memcmp(key,
			&be->skey_remote,
			sizeof(SESSIONKEY))) {
	  be->skey_remote = *key;
	  be->lastSequenceNumberReceived = 0;
	}
	be->skey_remote_created = age;
	be->status |= STAT_SETKEY_RECEIVED;
      }
    }
  }
  MUTEX_UNLOCK(&lock);
}

/**
 * Confirm that a connection is up.
 *
 * @param peer the other peer,
 */
void confirmSessionUp(const PeerIdentity * peer) {
  BufferEntry * be;

  MUTEX_LOCK(&lock);
  be = lookForHost(peer);
  if (be != NULL) {
    cronTime(&be->isAlive);
    identity->whitelistHost(peer);
    if ( ( (be->status & STAT_SETKEY_SENT) > 0) &&
	 ( (be->status & STAT_SETKEY_RECEIVED) > 0) &&
	 (OK == ensureTransportConnected(be)) &&
	 (be->status != STAT_UP) ) {
      be->status = STAT_UP;
      be->lastSequenceNumberReceived = 0;
      be->lastSequenceNumberSend = 1;
    }
  }
  MUTEX_UNLOCK(&lock);
}


/**
 * Get the current number of slots in the connection table (as computed
 * from the available bandwidth).
 */
int getSlotCount() {
  return CONNECTION_MAX_HOSTS_;
}

/**
 * Is the given slot used?
 * @return 0 if not, otherwise number of peers in
 * the slot
 */
int isSlotUsed(int slot) {
  BufferEntry * be;
  int ret;
  ret = 0;
  MUTEX_LOCK(&lock);
  if ( (slot >= 0) && (slot < CONNECTION_MAX_HOSTS_) ) {
    be = CONNECTION_buffer_[slot];
    while (be != NULL) {
      if (be->status == STAT_UP)
	ret++;
      be = be->overflowChain;
    }
  }
  MUTEX_UNLOCK(&lock);
  return ret;
}

/**
 * Get the time of the last encrypted message that was received
 * from the given peer.
 * @param time updated with the time
 * @return SYSERR if we are not connected to the peer at the moment
 */
int getLastActivityOf(const PeerIdentity * peer,
		      cron_t * time) {
  int ret;
  BufferEntry * be;

  ret = 0;
  MUTEX_LOCK(&lock);
  be = lookForHost(peer);
  if ( (be != NULL) &&
       (be->status == STAT_UP) ) {
    *time = be->isAlive;
    ret = OK;
  } else {
    *time = 0;
    ret = SYSERR;
  }
  MUTEX_UNLOCK(&lock);
  return ret;
}

/**
 * Obtain the session key used for traffic from or to a given peer.
 *
 * @param key the sessionkey (set)
 * @param age the age of the key (set)
 * @param peer the other peer,
 * @param forSending NO if it is the key for receiving,
 *                   YES if it is the key for sending
 * @return SYSERR if no sessionkey is known to the core,
 *         OK if the sessionkey was set.
 */
int getCurrentSessionKey(const PeerIdentity * peer,
			 SESSIONKEY * key,
			 TIME_T * age,
			 int forSending) {
  int ret;
  BufferEntry * be;
  ret = SYSERR;
  MUTEX_LOCK(&lock);
  be = lookForHost(peer);
  if (be != NULL) {
    if (forSending == YES) {
      if ((be->status & STAT_SETKEY_SENT) > 0) {
	*key = be->skey_local;
	*age = be->skey_local_created;
	ret = OK;
      }
    } else { /* for receiving */
      if ((be->status & STAT_SETKEY_RECEIVED) > 0) {
	*key = be->skey_remote;
	*age = be->skey_remote_created;
	ret = OK;
      }
    }
  }
  MUTEX_UNLOCK(&lock);
  return ret;
}

/**
 * Consider switching the transport mechanism used for contacting
 * the given node. This function is called when the handler handles
 * an encrypted connection. For example, if we are sending SMTP
 * messages to a node behind a NAT box, but that node has established
 * a TCP connection to us, it might just be better to send replies
 * on that TCP connection instead of keeping SMTP going.<p>
 *
 * Taking the transport over only makes sense if the cost is lower.
 * This method checks this.  If not, the transport session is
 * disconnected.
 *
 * @param tsession the transport session that is for grabs
 * @param sender the identity of the other node
 */
void considerTakeover(const PeerIdentity * sender,
		      TSession * tsession) {
  BufferEntry * be;

  ENTRY();
  if (tsession == NULL)
    return;
  MUTEX_LOCK(&lock);
  be = lookForHost(sender);
  if (be != NULL) {
    if (be->status != STAT_DOWN) {
      unsigned int cost = -1;
      if (be->session.tsession != NULL)
	cost = transport->getCost(be->session.tsession->ttype);
      /* Question: doesn't this always do takeover in tcp/udp
	 case, which have the same costs? Should it? -IW

	 Answer: this will always switch to TCP in the long run (if
	 that is possible) since udpAssociate always
	 returns SYSERR. This is intended since for long-running
	 sessions, TCP is the better choice. UDP is only better for
	 sending very few messages (e.g. attempting an initial exchange
	 to get to know each other). See also transport paper and the
	 data on throughput. - CG
      */
      if (transport->getCost(tsession->ttype) < cost) {
	if (transport->associate(tsession) == OK) {
	  if (be->session.tsession != NULL)
	    transport->disconnect(be->session.tsession);
	  be->session.tsession = tsession;
	  be->session.mtu = transport->getMTU(tsession->ttype);
	}
      } /* end if cheaper AND possible */
    } /* end if connected */
  }
  MUTEX_UNLOCK(&lock);
  transport->disconnect(tsession);
}


/**
 * The configuration may have changed.  In particular, bandwidth
 * limits may now be different.  Adjust the connection table
 * accordingly.
 */
static void connectionConfigChangeCallback() {
  unsigned long long new_max_bpm;
  unsigned int i;

  MUTEX_LOCK(&lock);
  /* max_bpm may change... */
  new_max_bpm
    = 60 * getConfigurationInt("LOAD",
			       "MAXNETDOWNBPSTOTAL");
  if (new_max_bpm == 0)
    new_max_bpm = 50000 * 60; /* assume 50 kbps */
  if (max_bpm != new_max_bpm) {
    unsigned int newMAXHOSTS = 0;

    max_bpm = new_max_bpm;
    newMAXHOSTS
      = max_bpm / (MIN_BPM_PER_PEER*2);
    /* => for 1000 bps, we get 12 (rounded DOWN to 8) connections! */
    if (newMAXHOSTS < 2)
      newMAXHOSTS = 2; /* strict minimum is 2 */
    if (newMAXHOSTS > 256)
      newMAXHOSTS = 256; /* limit, before we run out of sockets! */
    i = 1;
    while (i <= newMAXHOSTS)
      i*=2;
    newMAXHOSTS = i/2; /* make sure it's a power of 2 */

    if (newMAXHOSTS != CONNECTION_MAX_HOSTS_) {
      /* change size of connection buffer!!! */
      unsigned int olen;
      BufferEntry ** newBuffer;

      olen = CONNECTION_MAX_HOSTS_;
      CONNECTION_MAX_HOSTS_ = newMAXHOSTS;
      setConfigurationInt("gnunetd",
			  "connection-max-hosts",
			  CONNECTION_MAX_HOSTS_);
      newBuffer = (BufferEntry**) MALLOC(sizeof(BufferEntry*)*newMAXHOSTS);
      for (i=0;i<CONNECTION_MAX_HOSTS_;i++)
	newBuffer[i] = NULL;

      /* rehash! */
      for (i=0;i<olen;i++) {
	BufferEntry * be;

	be = CONNECTION_buffer_[i];
	while (be != NULL) {
	  BufferEntry * next;
	  unsigned int j;

	  next = be->overflowChain;
	  j = computeIndex(&be->session.sender);
	  be->overflowChain = newBuffer[j];
	  newBuffer[j] = be;
	  be = next;
	}
      }
      FREENONNULL(CONNECTION_buffer_);
      CONNECTION_buffer_ = newBuffer;

      LOG(LOG_DEBUG,
	  "connection goal is %s%d peers (%llu BPS bandwidth downstream)\n",
	  (olen == 0) ? "" : "now ",
	  CONNECTION_MAX_HOSTS_,
	  max_bpm);

    }
  }
  disable_random_padding = testConfigurationString("GNUNETD-EXPERIMENTAL",
						   "PADDING",
						   "NO");
  MUTEX_UNLOCK(&lock);
}

/**
 * Initialize this module.
 */
void initConnection() {
  GNUNET_ASSERT(P2P_MESSAGE_OVERHEAD
		== sizeof(P2P_PACKET_HEADER));
  GNUNET_ASSERT(sizeof(P2P_hangup_MESSAGE) == 68);
  ENTRY();
  scl_nextHead
    = NULL;
  scl_nextTail
    = NULL;
  MUTEX_CREATE_RECURSIVE(&lock);
  registerConfigurationUpdateCallback(&connectionConfigChangeCallback);
  CONNECTION_MAX_HOSTS_ = 0;
  connectionConfigChangeCallback();
  registerp2pHandler(P2P_PROTO_hangup,
		     &handleHANGUP);
  addCronJob(&cronDecreaseLiveness,
	     1 * cronSECONDS,
	     1 * cronSECONDS,
	     NULL);
#if DEBUG_COLLECT_PRIO == YES
  prioFile = FOPEN("/tmp/knapsack_prio.txt", "w");
#endif

  transport = requestService("transport");
  GNUNET_ASSERT(transport != NULL);
  identity  = requestService("identity");
  GNUNET_ASSERT(identity != NULL);
  session  = requestService("session");
  GNUNET_ASSERT(session != NULL);
  fragmentation = requestService("fragmentation");
  GNUNET_ASSERT(fragmentation != NULL);
  topology = requestService("topology");
  GNUNET_ASSERT(topology != NULL);
  stats = requestService("stats");
  if (stats != NULL) {
    stat_messagesDropped
      = stats->create(gettext_noop("# outgoing messages dropped"));
    stat_sizeMessagesDropped
      = stats->create(gettext_noop("# bytes of outgoing messages dropped"));
    stat_hangupSent
      = stats->create(gettext_noop("# connections closed (HANGUP sent)"));
    stat_encrypted
      = stats->create(gettext_noop("# bytes encrypted"));
    stat_decrypted
      = stats->create(gettext_noop("# bytes decrypted"));
    stat_noise_sent
      = stats->create(gettext_noop("# bytes noise sent"));
  }
  transport->start(&core_receive);
}


/**
 * Shutdown the connection module.
 */
void doneConnection() {
  unsigned int i;
  BufferEntry * be;
  SendCallbackList * scl;

  ENTRY();
  transport->stop();
  unregisterConfigurationUpdateCallback(&connectionConfigChangeCallback);
  delCronJob(&cronDecreaseLiveness,
	     1 * cronSECONDS,
	     NULL);
  for (i=0;i<CONNECTION_MAX_HOSTS_;i++) {
    BufferEntry * prev;

    prev = NULL;
    be = CONNECTION_buffer_[i];
    while (be != NULL) {
      LOG(LOG_DEBUG,
	  "Closing connection: shutdown\n");
      shutdownConnection(be);
      prev = be;
      be = be->overflowChain;
      FREE(prev);
    }
  }
  MUTEX_DESTROY(&lock);
  FREENONNULL(CONNECTION_buffer_);
  CONNECTION_buffer_ = NULL;
  CONNECTION_MAX_HOSTS_ = 0;
  while (scl_nextHead != NULL) {
    scl = scl_nextHead;
    scl_nextHead = scl_nextHead->next;
    FREE(scl);
  }
  scl_nextTail = NULL;
  releaseService(transport);
  transport = NULL;
  releaseService(identity);
  identity = NULL;
  releaseService(session);
  session = NULL;
  releaseService(fragmentation);
  fragmentation = NULL;
  releaseService(topology);
  topology = NULL;
  releaseService(stats);
  stats = NULL;
#if DEBUG_COLLECT_PRIO == YES
  fclose(prioFile);
#endif
}


/**
 * Wrapper around forAllConnectedHosts.  Calls a given
 * method for each connected host.
 *
 * @param method method to call for each connected peer
 * @param arg second argument to method
 * @return number of connected nodes
 */
int forEachConnectedNode(PerNodeCallback method,
			 void * arg) {
  fENHWrap wrap;
  int ret;

  wrap.method = method;
  wrap.arg = arg;
  MUTEX_LOCK(&lock);
  ret = forAllConnectedHosts(&fENHCallback,
			     &wrap);
  MUTEX_UNLOCK(&lock);
  return ret;
}

/**
 * Print the contents of the connection buffer (for debugging).
 */
void printConnectionBuffer() {
  unsigned int i;
  BufferEntry * tmp;
  EncName hostName;
  EncName skey_local;
  EncName skey_remote;
  unsigned int ttype;

  MUTEX_LOCK(&lock);
  ENTRY();
  for (i=0;i<CONNECTION_MAX_HOSTS_;i++) {
    tmp = CONNECTION_buffer_[i];
    while (tmp != NULL) {
      if (tmp->status != STAT_DOWN) {
        IFLOG(LOG_MESSAGE,
  	      hash2enc(&tmp->session.sender.hashPubKey,
  	  	       &hostName);
	      hash2enc((HashCode512*) &tmp->skey_local,
		       &skey_local);
	      hash2enc((HashCode512*) &tmp->skey_remote,
		       &skey_remote));
	hostName.encoding[4] = '\0';
	skey_local.encoding[4] = '\0';
	skey_remote.encoding[4] = '\0';
	ttype = 0;
	if (tmp->session.tsession != NULL)
	  ttype = tmp->session.tsession->ttype;
	LOG(LOG_MESSAGE,
  	    "CONNECTION-TABLE: %3d-%1d-%2d-%4ds"
	    " (of %ds) BPM %4llu %8ut-%3u: %s-%s-%s\n",
	    i,
	    tmp->status,
	    ttype,
	    (int) ((cronTime(NULL) - tmp->isAlive)/cronSECONDS),
	    SECONDS_INACTIVE_DROP,
	    tmp->recently_received,
	    tmp->idealized_limit,
	    tmp->sendBufferSize,
	    &hostName,
	    &skey_local,
	    &skey_remote);
      }
      tmp = tmp->overflowChain;
    }
  }
  MUTEX_UNLOCK(&lock);
}

/**
 * Register a callback method that should be invoked whenever a
 * message is about to be send that has more than minimumPadding bytes
 * left before maxing out the MTU. The callback method can then be
 * used to add additional content to the message (instead of the
 * random noise that is added by otherwise). Note that if the MTU is 0
 * (for streams), the callback method will always be called with
 * padding set to the maximum number of bytes left in the buffer
 * allocated for the send.
 *
 * @param minimumPadding how large must the padding be in order
 *   to call this method?
 * @param callback the method to invoke. The receiver is the
 *   receiver of the message, position is the reference to the
 *   first unused position in the buffer where GNUnet is building
 *   the message, padding is the number of bytes left in that buffer.
 *   The callback method must return the number of bytes written to
 *   that buffer (must be a positive number).
 * @return OK if the handler was registered, SYSERR on error
 */
int registerSendCallback(const unsigned int minimumPadding,
			 BufferFillCallback callback) {
  SendCallbackList * scl;

  ENTRY();
  scl = MALLOC(sizeof(SendCallbackList));
  scl->minimumPadding = minimumPadding;
  scl->callback = callback;
  scl->next = NULL;
  MUTEX_LOCK(&lock);
  if (scl_nextTail == NULL) {
    scl_nextHead = scl;
    scl_nextTail = scl;
  } else {
    scl_nextTail->next = scl;
    scl_nextTail = scl;
  }
  MUTEX_UNLOCK(&lock);
  return OK;
}

/**
 * Unregister a handler that was registered with registerSendCallback.
 *
 * @param minimumPadding how large must the padding be in order
 *   to call this method?
 * @param callback the method to invoke. The receiver is the
 *   receiver of the message, position is the reference to the
 *   first unused position in the buffer where GNUnet is building
 *   the message, padding is the number of bytes left in that buffer.
 *   The callback method must return the number of bytes written to
 *   that buffer (must be a positive number).
 * @return OK if the handler was removed, SYSERR on error
 */
int unregisterSendCallback(const unsigned int minimumPadding,
			   BufferFillCallback callback) {
  SendCallbackList * pos;
  SendCallbackList * prev;

  prev = NULL;
  MUTEX_LOCK(&lock);
  pos = scl_nextHead;
  while (pos != NULL) {
    if ( (pos->callback == callback) &&
	 (pos->minimumPadding == minimumPadding) ) {
      if (prev == NULL)
	scl_nextHead = pos->next;
      else
	prev->next = pos->next;
      if (scl_nextTail == pos)
	scl_nextTail = prev;
      FREE(pos);
      MUTEX_UNLOCK(&lock);
      return OK;
    }
    prev = pos;
    pos = pos->next;
  }
  MUTEX_UNLOCK(&lock);
  return SYSERR;
}

/**
 * Send a plaintext message to another node.  This is
 * not the usual way for communication and should ONLY be
 * used by modules that are responsible for setting up
 * sessions.  This bypasses resource allocation, bandwidth
 * scheduling, knapsack solving and lots of other goodies
 * from the GNUnet core.
 *
 * @param session the transport session
 * @param msg the message to transmit, should contain P2P_MESSAGE_HEADERs
 * @return OK on success, SYSERR on failure, NO on temporary failure
 */
int sendPlaintext(TSession * tsession,
		  const char * msg,
		  unsigned int size) {
  char * buf;
  int ret;
  P2P_PACKET_HEADER * hdr;

  GNUNET_ASSERT(tsession != NULL);
  if ( (transport->getMTU(tsession->ttype)>0) &&
       (transport->getMTU(tsession->ttype)<size + sizeof(P2P_PACKET_HEADER)) ) {
    BREAK();
    return SYSERR;
  }
  buf = MALLOC(size + sizeof(P2P_PACKET_HEADER));
  hdr = (P2P_PACKET_HEADER*) buf;
  hdr->sequenceNumber = 0;
  hdr->timeStamp = 0;
  hdr->bandwidth = 0;
  memcpy(&buf[sizeof(P2P_PACKET_HEADER)],
	 msg,
	 size);
  hash(&hdr->sequenceNumber,
       size + sizeof(P2P_PACKET_HEADER) - sizeof(HashCode512),
       &hdr->hash);
  ret = transport->send(tsession,
			buf,
			size + sizeof(P2P_PACKET_HEADER));
  FREE(buf);
  return ret;
}


/**
 * Send an encrypted, on-demand build message to another node.
 *
 * @param hostId the target node
 * @param callback the callback to build the message
 * @param closure the second argument to callback
 * @param len how long is the message going to be?
 * @param importance how important is the message?
 * @param maxdelay how long can the message wait?
 */
void unicastCallback(const PeerIdentity * hostId,
		     BuildMessageCallback callback,
		     void * closure,
		     unsigned short len,
		     unsigned int importance,
		     unsigned int maxdelay) {
  BufferEntry * be;
#if DEBUG_CONNECTION
  EncName enc;

  IFLOG(LOG_DEBUG,
	hash2enc(&hostId->hashPubKey,
		 &enc));
  LOG(LOG_DEBUG,
      "%s: sending message to host %s message of size %d\n",
      __FUNCTION__,
      &enc,
      len);
#endif
  ENTRY();
  MUTEX_LOCK(&lock);
  be = addHost(hostId, YES);
  if ( (be != NULL) &&
       (be->status != STAT_DOWN) ) {
    SendEntry * entry;

    entry = MALLOC(sizeof(SendEntry));
    entry->len = len;
    entry->flags = SE_FLAG_NONE;
    entry->pri = importance;
    entry->transmissionTime = cronTime(NULL) + maxdelay;
    entry->callback = callback;
    entry->closure = closure;
    entry->knapsackSolution = NO;
    appendToBuffer(be,
		   entry);
  } else {
    FREENONNULL(closure);
  }
  MUTEX_UNLOCK(&lock);
}

/**
 * Send an encrypted message to another node.
 *
 * @param receiver the target node
 * @param msg the message to send, NULL to tell the
 *   core to try to establish a session
 * @param importance how important is the message?
 * @param maxdelay how long can the message be delayed?
 */
void unicast(const PeerIdentity * receiver,
	     const P2P_MESSAGE_HEADER * msg,
	     unsigned int importance,
	     unsigned int maxdelay) {
  char * closure;
  unsigned short len;

  if (msg == NULL) {
    /* little hack for topology,
       which cannot do this directly
       due to cyclic dependencies! */
    if (getBandwidthAssignedTo(receiver) == 0)
      session->tryConnect(receiver);
    return;
  }
  len = ntohs(msg->size);
  if (len == 0)
    return;
  closure = MALLOC(len);
  memcpy(closure,
	 msg,
	 len);
  unicastCallback(receiver,
		  &copyCallback,
		  closure,
		  len,
		  importance,
		  maxdelay);
}

/**
 * Are we connected to this peer?
 *
 * @param hi the peer in question
 * @return NO if we are not connected, YES if we are
 */
int isConnected(const PeerIdentity * hi) {
  BufferEntry * be;

  MUTEX_LOCK(&lock);
  be = lookForHost(hi);
  MUTEX_UNLOCK(&lock);
  if (be == NULL) {
    return NO;
  } else {
    return (be->status == STAT_UP);
  }
}
	
/**
 * Compute the hashtable index of a host id.
 *
 * @param hostId the ID of a peer
 * @return the index for this peer in the connection table
 */
unsigned int computeIndex(const PeerIdentity * hostId) {
  unsigned int res = (((unsigned int)hostId->hashPubKey.bits[0]) &
		      ((unsigned int)(CONNECTION_MAX_HOSTS_ - 1)));
  GNUNET_ASSERT(res <  CONNECTION_MAX_HOSTS_);
  return res;
}

/**
 * Obtain the lock for the connection module
 *
 * @return the lock
 */
Mutex * getConnectionModuleLock() {
  return &lock;
}

unsigned int getBandwidthAssignedTo(const PeerIdentity * node) {
  BufferEntry * be;
  unsigned int ret;

  ENTRY();
  MUTEX_LOCK(&lock);
  be = lookForHost(node);
  if ( (be != NULL) &&
       (be->status == STAT_UP) ) {
    ret = be->idealized_limit;
    if (ret == 0)
      ret = 1;
  } else {
    ret = 0;
  }
  MUTEX_UNLOCK(&lock);
  return ret;
}

/**
 * Increase the preference for traffic from some other peer.
 * @param node the identity of the other peer
 * @param preference how much should the traffic preference be increased?
 */
void updateTrafficPreference(const PeerIdentity * node,
			     double preference) {
  BufferEntry * be;

  ENTRY();
  MUTEX_LOCK(&lock);
  be = lookForHost(node);
  if (be != NULL)
    be->current_connection_value += preference;
  MUTEX_UNLOCK(&lock);
}

/**
 * Disconnect a particular peer.  Sends a HANGUP message to the other
 * side and mark the sessionkey as dead.
 *
 * @param peer the peer to disconnect
 */
void disconnectFromPeer(const PeerIdentity *node) {
  BufferEntry * be;
  EncName enc;

  ENTRY();
  MUTEX_LOCK(&lock);
  be = lookForHost(node);
  if (be != NULL) {
    IFLOG(LOG_DEBUG,
	  hash2enc(&node->hashPubKey,
		   &enc));
    LOG(LOG_DEBUG,
	"Closing connection to `%s' as requested by application.\n",
	&enc);
    shutdownConnection(be);
  }
  MUTEX_UNLOCK(&lock);
}

/**
 * Register a handler that is to be called for each
 * message that leaves the peer.
 *
 * @param callback the method to call for each
 *        P2P message part that is transmitted
 * @return OK on success, SYSERR if there is a problem
 */
int registerSendNotify(MessagePartHandler callback) {
  if (callback == NULL)
    return SYSERR;
  MUTEX_LOCK(&lock);
  GROW(rsns,
       rsnSize,
       rsnSize+1);
  rsns[rsnSize-1] = callback;
  MUTEX_UNLOCK(&lock);
  return OK;
}

/**
 * Unregister a handler that is to be called for each
 * message that leaves the peer.
 *
 * @param callback the method to call for each
 *        P2P message part that is transmitted
 * @return OK on success, SYSERR if there is a problem
 */
int unregisterSendNotify(MessagePartHandler callback) {
  int i;
  MUTEX_LOCK(&lock);
  for (i=0;i<rsnSize;i++) {
    if (rsns[i] == callback) {
      rsns[i] = rsns[rsnSize-1];
      GROW(rsns,
	   rsnSize,
	   rsnSize-1);
      MUTEX_UNLOCK(&lock);
      return OK;
    }
  }
  MUTEX_UNLOCK(&lock);
  return SYSERR;
}


/* end of connection.c */
