/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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

#define DEBUG_CONNECTION GNUNET_NO

/**
 * output knapsack priorities into a file?
 */
#define DEBUG_COLLECT_PRIO GNUNET_NO

/**
 * If an attempt to establish a connection is not answered
 * within 150s, drop.
 */
#define SECONDS_NOPINGPONG_DROP 150

/**
 * If an established connection is inactive for 5 minutes,
 * drop.  Needs to be smaller than timeouts in the
 * transports.
 */
#define SECONDS_INACTIVE_DROP 300

/**
 * After 2 minutes on an inactive connection, probe the other
 * node with a ping if we have achieved less than 50% of our
 * connectivity goal.  Also, messages that are older than
 * this value are discarded as too old.
 */
#define SECONDS_PINGATTEMPT 120

/**
 * High priority message that needs to go through fast,
 * but not if policies would be disregarded.
 */
#define ADMIN_PRIORITY 0xFFFF

/**
 * How long should we blacklist a peer after a
 * disconnect?  This value should probably be
 * increased in the future (once more peers
 * run versions beyond 0.7.2a.
 */
#define SECONDS_BLACKLIST_AFTER_DISCONNECT 300

/**
 * How long should we blacklist a peer after a
 * failed connect?  For now, 2 minutes (should
 * probably be much higher).
 */
#define SECONDS_BLACKLIST_AFTER_FAILED_CONNECT 120

/**
 * If we under-shoot our bandwidth limitation in one time period, how
 * much of that limit are we allowed to 'roll-over' into the next
 * period?  The number given here is a factor of the total per-minute
 * bandwidth limit.
 */
#define MAX_BUF_FACT 2

/**
 * Expected MTU for a streaming connection.
 * (one bit of content plus 1k header overhead)
 */
#define EXPECTED_MTU (32768 + 1024)

/**
 * How many ping/pong messages to we want to transmit
 * per SECONDS_INACTIVE_DROP interval? (must be >= 4 to
 * keep connection alive with reasonable probability).
 */
#define TARGET_MSG_SID 8

/**
 * What is the minimum number of bytes per minute that
 * we allocate PER peer? (5 minutes inactivity timeout,
 * 32768 MTU, 8 MSGs => 8 * 32768 / 5 = ~50000 bpm [ ~800 bps])
 */
#define MIN_BPM_PER_PEER (TARGET_MSG_SID * EXPECTED_MTU * 60 / SECONDS_INACTIVE_DROP)

/**
 * Minimum number of sample messages (per peer) before we recompute
 * traffic assignments?
 */
#define MINIMUM_SAMPLE_COUNT 2

/**
 * How often do we expect to re-run the traffic allocation
 * code? (depends on MINIMUM_SAMPLE_COUNT and MIN_BPM_PER_PEER
 * and MTU size). [2 * 32 M / 50 = 75s ]
 */
#define MIN_SAMPLE_TIME (MINIMUM_SAMPLE_COUNT * GNUNET_CRON_MINUTES * EXPECTED_MTU / MIN_BPM_PER_PEER)

/**
 * Hard limit on the send buffer size (per connection, in bytes),
 * Must be larger than EXPECTED_MTU.
 */
#define MAX_SEND_BUFFER_SIZE (EXPECTED_MTU * 8)

/**
 * How often is another peer allowed to transmit above
 * the limit before we shutdown the connection?
 * (note that the violation counter also ages and that
 * advertised bandwidth limits are adjusted to a
 * fraction according to the current violation counter).
 */
#define MAX_VIOLATIONS 10

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


#if 0
#define ENTRY() check_invariants()
#else
#define ENTRY() ;
#endif

#if 0
#define EXIT() check_invariants()
#else
#define EXIT() ;
#endif

#if DEBUG_COLLECT_PRIO
FILE *prioFile;
#endif


/* ******************** typedefs ******************* */

/**
 * Type of the linked list of send callbacks (to
 * implement a round-robbin invocation chain).
 */
struct SendCallbackList
{

  /**
   * Did we say that this is a linked list?
   */
  struct SendCallbackList *next;

  /**
   * The callback method.
   */
  GNUNET_BufferFillCallback callback;

  /**
   * Minimum number of bytes that must be available
   * to call this callback.
   */
  unsigned int minimumPadding;

  /**
   * The higher the priority, the higher preference
   * will be given to polling this callback (compared to
   * other callbacks).  This linked list should be
   * sorted by descending priority value.
   */
  unsigned int priority;

};

struct DisconnectNotificationList
{

  struct DisconnectNotificationList *next;

  GNUNET_NodeIteratorCallback callback;

  void *cls;

};


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
typedef struct
{
  GNUNET_MessageHeader header;
  GNUNET_PeerIdentity sender;
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
 * priority, when the message was passed to ciphertext_send, a callback to
 * fill in the actual message and a closure (argument to the
 * callback).
 */
typedef struct
{

  /**
   * callback to call to create the message part
   */
  GNUNET_BuildMessageCallback callback;

  /**
   * argument to callback, call GNUNET_free_non_null(closure) if we
   * can not transmit this MessagePart.
   */
  void *closure;

  /**
   * when do/did we intend to transmit?
   */
  GNUNET_CronTime transmissionTime;

  /**
   * how important is this message part?
   */
  unsigned int pri;

  /**
   * GNUNET_YES if selected by knapsack for sending
   */
  int knapsackSolution;

  /**
   * how long is this message part expected to be?
   */
  unsigned short len;

  /**
   * flags
   */
  unsigned short flags;

} SendEntry;

/**
 * A tsession is a token provided by the transport
 * API to refer to a connection of the transport
 * layer.
 */
typedef struct
{
  /**
   * To whom are we connected with this session?
   */
  GNUNET_PeerIdentity sender;

  /**
   * The session handle specific for the transport service.
   */
  GNUNET_TSession *tsession;

  /**
   * The MTU for this session, 0 for streaming transports.
   */
  unsigned short mtu;

} Session;


/**
 * Type of the connection table.
 */
typedef struct BufferEntry_
{
  /**
   * Session for the connection
   */
  Session session;

  /**
   * the current session key used for encryption
   */
  GNUNET_AES_SessionKey skey_local;

  /**
   * at which time was the local sessionkey created
   */
  GNUNET_Int32Time skey_local_created;

  /**
   * the current session key used for decryption
   */
  GNUNET_AES_SessionKey skey_remote;

  /**
   * at which time was the remote sessionkey created
   */
  GNUNET_Int32Time skey_remote_created;

  /**
   * is this host alive? timestamp of the time of the last-active
   * point (as witnessed by some higher-level application, typically
   * topology+pingpong)
   */
  GNUNET_CronTime isAlive;

  /**
   * At what time did we initially establish (STAT_UP) this connection?
   * Should be zero if status != STAT_UP.
   */
  GNUNET_CronTime time_established;

  /**
   * Status of the connection (STAT_XXX)
   */
  unsigned int status;

  /**
   * last sequence number received on this connection (highest)
   */
  unsigned int lastSequenceNumberReceived;

  /**
   * bit map indicating which of the 32 sequence numbers before the last
   * were received (good for accepting out-of-order packets and
   * estimating reliability of the connection)
   */
  unsigned int lastPacketsBitmap;

  /**
   * last sequence number transmitted
   */
  unsigned int lastSequenceNumberSend;

  /**
   * number of entries in the send buffer
   */
  unsigned int sendBufferSize;

  /**
   * buffer of entries waiting to be transmitted
   */
  SendEntry **sendBuffer;

  /**
   * time of the last send-attempt (to avoid
   * solving knapsack's too often)
   */
  GNUNET_CronTime lastSendAttempt;

  /**
   * a GNUNET_hash collision overflow chain
   */
  struct BufferEntry_ *overflowChain;


  /* *********** outbound bandwidth limits ********** */

  /**
   * byte-per-minute limit for this connection
   */
  unsigned int max_bpm;

  /**
   * Size of the available send window in bytes for this connection
   * (incremented every minute by max_bpm, bounded by max_bpm (no
   * back-log larger than MAX_BUF_FACT minutes, bandwidth-hogs are sampled at a
   * frequency of about 78s!); may get negative if we have VERY high
   * priority content
   */
  long long available_send_window;

  /**
   * time of the last increment of available_send_window
   */
  GNUNET_CronTime last_bps_update;

  /* *********** inbound bandwidth accounting ******** */

  /**
   * How much downstream capacity of this peer
   * has been reserved for our traffic?
   */
  long long available_downstream;

  /**
   * When did we last update the reserved downstream
   * availability data?
   */
  GNUNET_CronTime last_reservation_update;

  /**
   * how much traffic (bytes) did we receive on this connection since
   * the last update-round?
   */
  long long recently_received;

  /**
   * How valueable were the messages of this peer recently?
   */
  double current_connection_value;

  /**
   * the highest bandwidth limit that a well-behaved peer
   * must have received by now
   */
  unsigned int max_transmitted_limit;

  /**
   * what is the limit that we are currently shooting for? (bytes per minute)
   */
  unsigned int idealized_limit;

  /**
   * How often has the other peer violated the traffic bounds
   * recently?
   */
  unsigned int violations;

  /**
   * are we currently in "sendBuffer" for this entry?
   */
  int inSendBuffer;

  /**
   * Did we already select this entry for bandwidth
   * assignment due to high uptime this round?
   */
  int tes_selected;

  /**
   * Should we consider switching to a non-fragmenting
   * transport?
   */
  int consider_transport_switch;

} BufferEntry;

typedef struct
{
  BufferEntry **e;
  unsigned int pos;
} UTL_Closure;

/**
 * Type of a callback method on every buffer.
 * @param be the buffer entry
 * @param data context for callee
 */
typedef void (*BufferEntryCallback) (BufferEntry * be, void *data);

/* ***************** globals ********************** */

/**
 * Transport service
 */
static GNUNET_Transport_ServiceAPI *transport;

/**
 * Identity service
 */
static GNUNET_Identity_ServiceAPI *identity;

/**
 * Session service
 */
static GNUNET_Session_ServiceAPI *session;

/**
 * Fragmentation service
 */
static GNUNET_Fragmentation_ServiceAPI *fragmentation;

/**
 * Topology service
 */
static GNUNET_Topology_ServiceAPI *topology;

/**
 * Stats service (maybe NULL!)
 */
static GNUNET_Stats_ServiceAPI *stats;

/**
 * The buffer containing all current connections.
 */
static BufferEntry **CONNECTION_buffer_;

/**
 * Size of the CONNECTION_buffer_
 */
static unsigned int CONNECTION_MAX_HOSTS_;

/**
 * Experimental configuration: disable random padding of encrypted
 * messages.
 */
static int disable_random_padding = GNUNET_NO;

/**
 * Send callbacks for making better use of noise padding...
 */
static struct SendCallbackList *scl_head;

/**
 * Callbacks for disconnect notifications.
 */
static struct DisconnectNotificationList *disconnect_notification_list;

/**
 * Lock for the connection module.
 */
static struct GNUNET_Mutex *lock;

/**
 * What is the available downstream bandwidth (in bytes
 * per minute)?
 */
static unsigned long long max_bpm;

/**
 * What is the available upstream bandwidth (in bytes
 * per minute)?
 */
static unsigned long long max_bpm_up;

/**
 * Registered Send-Notify handlers.
 */
static GNUNET_P2PRequestHandler *rsns;

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_GC_Configuration *cfg;

static struct GNUNET_LoadMonitor *load_monitor;

static struct GNUNET_CronManager *cron;


/**
 * Size of rsns.
 */
static unsigned int rsnSize;

static int stat_messagesDropped;

static int stat_sizeMessagesDropped;

static int stat_hangupSent;

static int stat_closedTransport;

static int stat_shutdown_excessive_bandwidth;

static int stat_shutdown_insufficient_bandwidth;

static int stat_shutdown_timeout;

static int stat_shutdown_connect_timeout;

static int stat_shutdown_hangup_received;

static int stat_encrypted;

static int stat_transmitted;

static int stat_received;

static int stat_decrypted;

static int stat_noise_sent;

static int stat_total_allowed_sent;

static int stat_total_allowed_inc;

static int stat_total_allowed_now;

static int stat_total_lost_sent;

static int stat_total_allowed_recv;

static int stat_total_send_buffer_size;

static int stat_transport_switches;

static int stat_avg_lifetime;

/* ******************** CODE ********************* */

static void
check_invariants ()
{
  int i;
  BufferEntry *root;

  GNUNET_mutex_lock (lock);
  for (i = 0; i < CONNECTION_MAX_HOSTS_; i++)
    {
      root = CONNECTION_buffer_[i];
      while (NULL != root)
        {
          if (root->session.tsession != NULL)
            GNUNET_GE_ASSERT (NULL,
                              GNUNET_OK ==
                              transport->assert_associated (root->session.
                                                            tsession,
                                                            __FILE__));
          root = root->overflowChain;
        }
    }
  GNUNET_mutex_unlock (lock);
}

/**
 * Notify all disconnect-callbacks that a peer
 * was disconnected.
 */
static void
notify_disconnect (BufferEntry * be)
{
  struct DisconnectNotificationList *l = disconnect_notification_list;
  while (l != NULL)
    {
      l->callback (&be->session.sender, l->cls);
      l = l->next;
    }
}

/**
 * This allocates and initializes a BufferEntry.
 * @return the initialized BufferEntry
 */
static BufferEntry *
initBufferEntry ()
{
  BufferEntry *be;
  GNUNET_CronTime now;

  be = GNUNET_malloc (sizeof (BufferEntry));
  memset (be, 0, sizeof (BufferEntry));
  be->isAlive = 0;
  be->status = STAT_DOWN;
  be->sendBuffer = NULL;
  be->sendBufferSize = 0;
  be->overflowChain = NULL;
  be->session.tsession = NULL;
  be->max_bpm = MIN_BPM_PER_PEER;
  be->available_send_window = be->max_bpm;
  be->recently_received = 0;
  be->current_connection_value = 0.0;
  be->idealized_limit = MIN_BPM_PER_PEER;
  be->max_transmitted_limit = MIN_BPM_PER_PEER;
  be->lastSendAttempt = 0;      /* never */
  be->inSendBuffer = GNUNET_NO;
  now = GNUNET_get_time ();
  be->last_bps_update = now;
  be->last_reservation_update = now;
  return be;
}

/**
 * Update available_send_window.  Call only when already synchronized.
 * @param be the connection for which to update available_send_window
 */
static void
updateCurBPS (BufferEntry * be)
{
  GNUNET_CronTime now;
  GNUNET_CronTime delta;
  long long increment;
  long long limit;

  now = GNUNET_get_time ();
  if (now <= be->last_bps_update)
    return;
  delta = now - be->last_bps_update;
  increment = (long long) be->max_bpm * delta / GNUNET_CRON_MINUTES;
  if (increment < 100)
    return;                     /* avoid loosing > 1% due to rounding */
  if (stats != NULL)
    stats->change (stat_total_allowed_inc, increment);
  be->available_send_window += increment;
#if 0
  printf ("Have %u bpm over %llu ms, adding %lld bytes\n",
          be->max_bpm, delta, increment);
#endif
  limit = (long long) be->max_bpm * MAX_BUF_FACT;
  if (be->available_send_window > limit)
    {
      if (stats != NULL)
        stats->change (stat_total_lost_sent,
                       be->available_send_window - limit);
      be->available_send_window = limit;
    }
  be->last_bps_update = now;
}


/**
 * Compute the greatest common denominator (Euklid).
 *
 * @param a
 * @param b
 * @return gcd(a,b)
 */
static int
gcd (int a, int b)
{
  while (a != 0)
    {
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
approximateKnapsack (BufferEntry * be, unsigned int available)
{
  unsigned int i;
  unsigned int count;
  SendEntry **entries;
  int max;
  int left;

  entries = be->sendBuffer;
  count = be->sendBufferSize;
  left = available;
  max = 0;

  for (i = 0; i < count; i++)
    {
      if (entries[i]->len <= left)
        {
          entries[i]->knapsackSolution = GNUNET_YES;
          left -= entries[i]->len;
          max += entries[i]->pri;
        }
      else
        {
          entries[i]->knapsackSolution = GNUNET_NO;
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
solveKnapsack (BufferEntry * be, unsigned int available)
{
  unsigned int i;
  int j;
  int max;
  long long *v;
  int *efflen;
  SendEntry **entries;
  unsigned int count;
#define VARR(i,j) v[(i)+(j)*(count+1)]

  ENTRY ();
  entries = be->sendBuffer;
  count = be->sendBufferSize;

  /* fast test: schedule everything? */
  max = 0;
  for (i = 0; i < count; i++)
    max += entries[i]->len;
  if (max <= available)
    {
      /* short cut: take everything! */
      for (i = 0; i < count; i++)
        entries[i]->knapsackSolution = GNUNET_YES;
      max = 0;
      for (i = 0; i < count; i++)
        max += entries[i]->pri;
      return max;
    }

  /* division of sizes & available by gcd(sizes,available)
     to reduce cost to O(count*available/gcd) in terms of
     CPU and memory.  Since gcd is almost always at least
     4, this is probably a good idea (TM)  :-) */
  efflen = GNUNET_malloc (sizeof (int) * count);
  max = available;
  for (i = 0; i < count; i++)
    if (entries[i]->len > 0)
      max = gcd (max, entries[i]->len);
  GNUNET_GE_ASSERT (ectx, max != 0);
  available = available / max;
  for (i = 0; i < count; i++)
    efflen[i] = entries[i]->len / max;

  /* dynamic programming:
     VARR(i,j) stores the maximum value of any subset
     of objects {1, ... i} that can fit into a knapsack
     of weight j. */
  v = GNUNET_malloc (sizeof (long long) * (count + 1) * (available + 1));
  memset (v, 0, sizeof (long long) * (count + 1) * (available + 1));
  for (j = 1; j <= available; j++)
    VARR (0, j) = -1;
  for (i = 1; i <= count; i++)
    {
      for (j = 0; j <= available; j++)
        {
          int take_val;
          int leave_val;

          take_val = -1;
          leave_val = VARR (i - 1, j);
          if (j >= efflen[i - 1])
            {
              take_val =
                entries[i - 1]->pri + VARR (i - 1, j - efflen[i - 1]);
              if (leave_val > take_val)
                VARR (i, j) = leave_val;
              else
                VARR (i, j) = take_val;
            }
          else
            VARR (i, j) = leave_val;
        }
    }

  /* find slot with max value, prefer long messages! */
  max = 0;
  j = -1;
  for (i = 0; (int) i <= available; i++)
    {
      if (VARR (count, i) >= max)
        {
          j = i;
          max = VARR (count, i);
        }
    }

  /* reconstruct selection */
  for (i = 0; i < count; i++)
    entries[i]->knapsackSolution = GNUNET_NO;
  for (i = count; i > 0; i--)
    {
      if (j >= efflen[i - 1])
        {
          if (VARR (i - 1, j - efflen[i - 1]) + entries[i - 1]->pri ==
              VARR (i, j))
            {
              j -= efflen[i - 1];
              entries[i - 1]->knapsackSolution = GNUNET_YES;
            }
        }
    }
  GNUNET_GE_ASSERT (ectx, j == 0);
  GNUNET_free (v);
  GNUNET_free (efflen);

  return max;
}

/**
 * A new packet is supposed to be send out. Should it be
 * dropped because the load is too high?
 * <p>
 *
 * @param priority the highest priority of contents in the packet
 * @param overhead how much is the header-overhead? 1 for just
 *                 the header, 2 for header is 50%, 3 for header is 33%, etc.
 *                 (the higher the better)
 * @return GNUNET_OK if the packet should be handled, GNUNET_SYSERR if the packet should be dropped.
 */
static int
outgoingCheck (unsigned int priority, unsigned int overhead)
{
  int load;
  unsigned int delta;

  load = GNUNET_network_monitor_get_load (load_monitor, GNUNET_ND_UPLOAD);      /* how much free bandwidth do we have? */
  if (load >= 150)
    return GNUNET_SYSERR;       /* => always drop */
  if (load > 100)
    {
      if (priority >= GNUNET_EXTREME_PRIORITY)
        return GNUNET_OK;       /* allow administrative msgs */
      return GNUNET_SYSERR;     /* but nothing else */
    }
  if (load <= 75 + overhead)
    return GNUNET_OK;
  delta = load - overhead - 75;
  /* Now delta in [0, 25] */
  if (delta * delta * delta > priority)
    {
#if DEBUG_POLICY
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Network load is too high (%d%%, priority is %u, require %d), "
                     "dropping outgoing.\n", load, priority,
                     delta * delta * delta);
#endif
      return GNUNET_SYSERR;     /* drop */
    }
  else
    {
#if DEBUG_POLICY
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Network load is ok (%d%%, priority is %u >= %d), "
                     "sending outgoing.\n", load, priority,
                     delta * delta * delta);
#endif
      return GNUNET_OK;         /* allow */
    }
}

/**
 * Check that the send frequency for this
 * buffer is not too high.
 *
 * @return GNUNET_OK if sending a message now is acceptable
 */
static int
checkSendFrequency (BufferEntry * be)
{
  GNUNET_CronTime msf;
  int load;
  unsigned int i;

  for (i = 0; i < be->sendBufferSize; i++)
    if (be->sendBuffer[i]->pri >= GNUNET_EXTREME_PRIORITY)
      return GNUNET_OK;

  if (be->max_bpm == 0)
    be->max_bpm = 1;

  if (be->session.mtu == 0)
    {
      msf =                     /* ms per message */
        EXPECTED_MTU / (be->max_bpm * GNUNET_CRON_MINUTES / GNUNET_CRON_MILLISECONDS);  /* bytes per ms */
    }
  else
    {
      msf =                     /* ms per message */
        be->session.mtu         /* byte per message */
        / (be->max_bpm * GNUNET_CRON_MINUTES / GNUNET_CRON_MILLISECONDS);       /* bytes per ms */
    }
  /* Also: allow at least 2 * MINIMUM_SAMPLE_COUNT knapsack
     solutions for any MIN_SAMPLE_TIME! */
  if (msf > 2 * MIN_SAMPLE_TIME / MINIMUM_SAMPLE_COUNT)
    msf = 2 * MIN_SAMPLE_TIME / MINIMUM_SAMPLE_COUNT;
  load = GNUNET_cpu_get_load (ectx, cfg);
  if (load == -1)
    load = 50;
  /* adjust frequency based on send buffer size */
  i = be->sendBufferSize;
  if (i > 100)
    i = 100;
  if (i <= 25)
    i = 25;
  /* adjust send frequency; if load is smaller
     than i%, decrease frequency, otherwise
     increase it (quadratically)! */
  msf = msf * load * load / i / i;
  if (be->lastSendAttempt + msf > GNUNET_get_time ())
    {
#if DEBUG_CONNECTION
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Send frequency too high (CPU load), send deferred.\n");
#endif
      return GNUNET_NO;         /* frequency too high, wait */
    }
  return GNUNET_OK;
}

/**
 * Select a subset of the messages for sending.
 *
 * @param *priority is set to the achieved message priority
 * @return total number of bytes of messages selected
 *   including P2P message header.
 */
static unsigned int
selectMessagesToSend (BufferEntry * be, unsigned int *priority)
{
  unsigned int totalMessageSize;
  SendEntry *entry;
  int i;
  int j;
  int approxProb;
  GNUNET_CronTime deadline;

  totalMessageSize = 0;
  (*priority) = 0;

  for (i = be->sendBufferSize - 1; i >= 0; i--)
    be->sendBuffer[i]->knapsackSolution = GNUNET_NO;

  if (be->session.mtu == 0)
    {
      totalMessageSize = sizeof (GNUNET_TransportPacket_HEADER);
      deadline = (GNUNET_CronTime) - 1L;        /* infinity */

      i = 0;
      /* assumes entries are sorted by priority! */
      while (i < be->sendBufferSize)
        {
          entry = be->sendBuffer[i];
          if ((totalMessageSize + entry->len < GNUNET_MAX_BUFFER_SIZE - 64) &&
              (entry->pri >= GNUNET_EXTREME_PRIORITY))
            {
              entry->knapsackSolution = GNUNET_YES;
              if (entry->transmissionTime < deadline)
                deadline = entry->transmissionTime;
              (*priority) += entry->pri;
              totalMessageSize += entry->len;
            }
          else
            {
              entry->knapsackSolution = GNUNET_NO;
              break;
            }
          i++;
        }
      if ((i == 0) && (be->sendBuffer[i]->len > be->available_send_window))
        {
          return 0;             /* always wait for the highest-priority
                                   message (otherwise large messages may
                                   starve! */
        }
      while ((i < be->sendBufferSize) &&
             (be->available_send_window > totalMessageSize))
        {
          entry = be->sendBuffer[i];
          if ((entry->len + totalMessageSize <= be->available_send_window) &&
              (totalMessageSize + entry->len < GNUNET_MAX_BUFFER_SIZE - 64))
            {
              entry->knapsackSolution = GNUNET_YES;
              if (entry->transmissionTime < deadline)
                deadline = entry->transmissionTime;
              totalMessageSize += entry->len;
              (*priority) += entry->pri;
            }
          else
            {
              entry->knapsackSolution = GNUNET_NO;
              if (totalMessageSize == sizeof (GNUNET_TransportPacket_HEADER))
                {
                  /* if the highest-priority message does not yet
                     fit, wait for send window to grow so that
                     we can get it out (otherwise we would starve
                     high-priority, large messages) */
                  return 0;
                }
            }
          i++;
        }
      if ((totalMessageSize == sizeof (GNUNET_TransportPacket_HEADER)) ||
          (((*priority) < GNUNET_EXTREME_PRIORITY) &&
           ((totalMessageSize / sizeof (GNUNET_TransportPacket_HEADER)) < 4)
           && (deadline > GNUNET_get_time () + 500 * GNUNET_CRON_MILLISECONDS)
           && (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 16) != 0)))
        {
          /* randomization necessary to ensure we eventually send
             a small message if there is nothing else to do! */
          return 0;
        }
    }
  else
    {                           /* if (be->session.mtu == 0) */
      /* solve knapsack problem, compute accumulated priority */
      approxProb = GNUNET_cpu_get_load (ectx, cfg);
      if (approxProb < 0)
        approxProb = 50;        /* failed to determine load, assume 50% */
      if (approxProb > 50)
        {
          if (approxProb > 100)
            approxProb = 100;
          approxProb = 100 - approxProb;        /* now value between 0 and 50 */
          approxProb *= 2;      /* now value between 0 [always approx] and 100 [never approx] */
          /* control CPU load probabilistically! */
          if (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 1 + approxProb)
              == 0)
            {
              (*priority) = approximateKnapsack (be,
                                                 be->session.mtu -
                                                 sizeof
                                                 (GNUNET_TransportPacket_HEADER));
#if DEBUG_COLLECT_PRIO
              FPRINTF (prioFile, "%llu 0 %u\n", GNUNET_get_time (),
                       *priority);
#endif
            }
          else
            {
              (*priority) = solveKnapsack (be,
                                           be->session.mtu -
                                           sizeof
                                           (GNUNET_TransportPacket_HEADER));
#if DEBUG_COLLECT_PRIO
              FPRINTF (prioFile, "%llu 1 %u\n", GNUNET_get_time (),
                       *priority);
#endif
            }
        }
      else
        {                       /* never approximate < 50% CPU load */
          (*priority) = solveKnapsack (be,
                                       be->session.mtu -
                                       sizeof
                                       (GNUNET_TransportPacket_HEADER));
#if DEBUG_COLLECT_PRIO
          FPRINTF (prioFile, "%llu 2 %u\n", GNUNET_get_time (), *priority);
#endif
        }
      j = 0;
      totalMessageSize = 0;
      for (i = 0; i < be->sendBufferSize; i++)
        {
          if (be->sendBuffer[i]->knapsackSolution == GNUNET_YES)
            {
              totalMessageSize += be->sendBuffer[i]->len;
              j++;
            }
        }
      if ((j == 0) ||
          (totalMessageSize >
           be->session.mtu - sizeof (GNUNET_TransportPacket_HEADER)))
        {
          GNUNET_GE_BREAK (ectx, 0);
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK |
                         GNUNET_GE_DEVELOPER,
                         _
                         ("`%s' selected %d out of %d messages (MTU: %d).\n"),
                         __FUNCTION__, j, be->sendBufferSize,
                         be->session.mtu -
                         sizeof (GNUNET_TransportPacket_HEADER));

          for (j = 0; j < be->sendBufferSize; j++)
            GNUNET_GE_LOG (ectx,
                           GNUNET_GE_ERROR | GNUNET_GE_BULK |
                           GNUNET_GE_DEVELOPER,
                           _
                           ("Message details: %u: length %d, priority: %d\n"),
                           j, be->sendBuffer[j]->len, be->sendBuffer[j]->pri);
          return 0;
        }

      if (be->available_send_window < be->session.mtu)
        {
          /* if we have a very high priority, we may
             want to ignore bandwidth availability (e.g. for HANGUP,
             which  has GNUNET_EXTREME_PRIORITY) */
          if ((*priority) < GNUNET_EXTREME_PRIORITY)
            {
#if DEBUG_CONNECTION
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                             GNUNET_GE_USER,
                             "bandwidth limits prevent sending (send window %u too small).\n",
                             be->available_send_window);
#endif
              return 0;         /* can not send, BPS available is too small */
            }
        }
      totalMessageSize = be->session.mtu;
    }                           /* end MTU > 0 */
  return totalMessageSize;
}


/**
 * Expire old messages from SendBuffer (to avoid
 * running out of memory).
 */
static void
expireSendBufferEntries (BufferEntry * be)
{
  unsigned long long msgCap;
  int i;
  SendEntry *entry;
  GNUNET_CronTime expired;
  int load;
  unsigned long long usedBytes;
  int j;

  /* if it's more than one connection "lifetime" old, always kill it! */
  be->lastSendAttempt = GNUNET_get_time ();
  expired = be->lastSendAttempt - SECONDS_PINGATTEMPT * GNUNET_CRON_SECONDS;
  load = GNUNET_cpu_get_load (ectx, cfg);
  if (load < 0)
    load = 50;                  /* failed to determine load, assume 50% */
  /* cleanup queue: keep enough buffer for one minute */
  msgCap = be->max_bpm;         /* have minute of msgs */
  if (msgCap < EXPECTED_MTU)
    msgCap = EXPECTED_MTU;      /* have at least one MTU */
  if (msgCap > max_bpm_up)
    msgCap = max_bpm_up;        /* have no more than max-bpm for entire daemon */
  if (load < GNUNET_IDLE_LOAD_THRESHOLD)
    {                           /* afford more if CPU load is low */
      if (load == 0)
        load = 1;               /* avoid division by zero */
      msgCap += (MAX_SEND_BUFFER_SIZE - EXPECTED_MTU) / load;
    }

  usedBytes = 0;
  /* allow at least msgCap bytes in buffer */
  for (i = 0; i < be->sendBufferSize; i++)
    {
      entry = be->sendBuffer[i];
      if (entry == NULL)
        continue;

      if ((entry->transmissionTime <= expired) || (usedBytes > msgCap))
        {
#if DEBUG_CONNECTION
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "expiring message, expired %ds ago, queue size is %llu (bandwidth stressed)\n",
                         (int) ((GNUNET_get_time () -
                                 entry->transmissionTime) /
                                GNUNET_CRON_SECONDS), usedBytes);
#endif
          if (stats != NULL)
            {
              stats->change (stat_messagesDropped, 1);
              stats->change (stat_sizeMessagesDropped, entry->len);
            }
          GNUNET_free_non_null (entry->closure);
          GNUNET_free (entry);
          be->sendBuffer[i] = NULL;
        }
      else
        usedBytes += entry->len;
    }

  /* cleanup/compact sendBuffer */
  j = 0;
  for (i = 0; i < be->sendBufferSize; i++)
    if (be->sendBuffer[i] != NULL)
      be->sendBuffer[j++] = be->sendBuffer[i];
  GNUNET_array_grow (be->sendBuffer, be->sendBufferSize, j);
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
static unsigned int
prepareSelectedMessages (BufferEntry * be)
{
  unsigned int ret;
  int i;
  char *tmpMsg;
  SendEntry *entry;

  ret = 0;
  for (i = 0; i < be->sendBufferSize; i++)
    {
      entry = be->sendBuffer[i];

      if (entry->knapsackSolution == GNUNET_YES)
        {
          if (entry->callback != NULL)
            {
              tmpMsg = GNUNET_malloc (entry->len);
              if (GNUNET_OK ==
                  entry->callback (tmpMsg, entry->closure, entry->len))
                {
                  entry->callback = NULL;
                  entry->closure = tmpMsg;
                  ret++;
                }
              else
                {
                  GNUNET_free (tmpMsg);
                  entry->callback = NULL;
                  entry->closure = NULL;
                  GNUNET_free (entry);
                  be->sendBuffer[i] = NULL;
                }
            }
          else
            {
              ret++;
            }
#if 0
          {
            GNUNET_MessageHeader *hdr;
            GNUNET_EncName enc;

            hdr = (GNUNET_MessageHeader *) entry->closure;
            IF_GELOG (ectx,
                      GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                      GNUNET_hash_to_enc (&be->session.sender.hashPubKey,
                                          &enc));
            GNUNET_GE_LOG (ectx,
                           GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                           GNUNET_GE_USER,
                           "Core selected message of type %u and size %u for sending to peer `%s'.\n",
                           ntohs (hdr->type), ntohs (hdr->size), &enc);
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
 *
 * @param  selected_total set to the number of
 *         entries returned
 * @return allocated (caller-frees) buffer with
 *         permuted SendEntries
 */
static SendEntry **
permuteSendBuffer (BufferEntry * be, unsigned int *selected_total)
{
  unsigned int tailpos;
  unsigned int headpos;
  unsigned int rnd;
  unsigned int i;
  unsigned int j;
  unsigned int stotal;
  SendEntry **ret;
  SendEntry *tmp;

  stotal = 0;
  for (i = 0; i < be->sendBufferSize; i++)
    {
      if (be->sendBuffer[i] == NULL)
        continue;
      if (be->sendBuffer[i]->knapsackSolution == GNUNET_YES)
        stotal++;
    }
  *selected_total = stotal;
  if (stotal == 0)
    return NULL;
  ret = GNUNET_malloc (stotal * sizeof (SendEntry *));
  j = 0;
  for (i = 0; i < be->sendBufferSize; i++)
    {
      if (be->sendBuffer[i] == NULL)
        continue;
      if (be->sendBuffer[i]->knapsackSolution == GNUNET_YES)
        ret[j++] = be->sendBuffer[i];
    }
  for (j = 0; j < stotal; j++)
    {
      rnd = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, stotal);
      tmp = ret[j];
      ret[j] = ret[rnd];
      ret[rnd] = tmp;
    }
  tailpos = stotal - 1;
  headpos = 0;
  for (i = 0; i <= tailpos; i++)
    {
      if (i >= stotal)
        break;                  /* corner case: integer underflow on tailpos */
      switch (ret[i]->flags & SE_PLACEMENT_FLAG)
        {
        case SE_FLAG_NONE:
          break;
        case SE_FLAG_PLACE_HEAD:
          /* swap slot with whoever is head now */
          tmp = ret[headpos];
          ret[headpos++] = ret[i];
          ret[i] = tmp;
          break;
        case SE_FLAG_PLACE_TAIL:
          /* swap slot with whoever is tail now */
          tmp = ret[tailpos];
          ret[tailpos--] = ret[i];
          ret[i] = tmp;
        }
    }
  return ret;
}

/**
 * Free entries in send buffer that were
 * selected as the knapsack solution or
 * that are dead (callback and closure NULL).
 */
static void
freeSelectedEntries (BufferEntry * be)
{
  int i;
  SendEntry *entry;

  for (i = 0; i < be->sendBufferSize; i++)
    {
      entry = be->sendBuffer[i];
      GNUNET_GE_ASSERT (ectx, entry != NULL);
      if (entry->knapsackSolution == GNUNET_YES)
        {
          GNUNET_GE_ASSERT (ectx, entry->callback == NULL);
          GNUNET_free_non_null (entry->closure);
          GNUNET_free (entry);
          be->sendBuffer[i] = NULL;
        }
      else if ((entry->callback == NULL) && (entry->closure == NULL))
        {
          GNUNET_free (entry);
          be->sendBuffer[i] = NULL;
        }
    }
}

/**
 * The MTU has changed.  We may have messages larger than the
 * MTU in the buffer.  Check if this is the case, and if so,
 * fragment those messages.
 */
static void
fragmentIfNecessary (BufferEntry * be)
{
  SendEntry **entries;
  SendEntry *entry;
  unsigned int i;
  unsigned int ret;
  unsigned int j;
  int changed;

  if (be->session.mtu == 0)
    return;                     /* clearly not necessary */

  /* MTU change may require new fragmentation! */
  changed = GNUNET_YES;
  while (changed)
    {
      changed = GNUNET_NO;
      entries = be->sendBuffer;
      ret = be->sendBufferSize;
      for (i = 0; i < ret; i++)
        {
          entry = entries[i];
          if (entry->len <=
              be->session.mtu - sizeof (GNUNET_TransportPacket_HEADER))
            continue;
          ret--;
          for (j = i; j < ret; j++)
            entries[j] = entries[j + 1];        /* preserve ordering */
          GNUNET_array_grow (be->sendBuffer, be->sendBufferSize, ret);
          /* calling fragment will change be->sendBuffer;
             thus we need to restart from the beginning afterwards... */
          be->consider_transport_switch = GNUNET_YES;
          fragmentation->fragment (&be->session.sender,
                                   be->session.mtu -
                                   sizeof (GNUNET_TransportPacket_HEADER),
                                   entry->pri, entry->transmissionTime,
                                   entry->len, entry->callback,
                                   entry->closure);
          GNUNET_free (entry);
          changed = GNUNET_YES;
          break;                /* "entries" changed as side-effect of fragment call */
        }
    }                           /* while changed */
}

/**
 * Try to make sure that the transport service for the given buffer is
 * connected.  If the transport service changes, this function also
 * ensures that the pending messages are properly fragmented (if
 * needed).
 *
 * @return GNUNET_OK on success, GNUNET_NO on error
 */
static int
ensureTransportConnected (BufferEntry * be)
{
  if (be->session.tsession != NULL)
    return GNUNET_OK;
  be->session.tsession =
    transport->connect_freely (&be->session.sender, GNUNET_NO, __FILE__);
  if (be->session.tsession == NULL)
    {
      be->status = STAT_DOWN;
      be->time_established = 0;
      return GNUNET_NO;
    }
  be->session.mtu = transport->mtu_get (be->session.tsession->ttype);
  fragmentIfNecessary (be);
  return GNUNET_OK;
}

/**
 * Send a buffer; assumes that access is already synchronized.  This
 * message solves the knapsack problem, assembles the message
 * (callback to build parts from knapsack, callbacks for padding,
 * random noise padding, crc, encryption) and finally hands the
 * message to the transport service.
 *
 * @param be connection of the buffer that is to be transmitted
 * @return GNUNET_YES if we might want to be re-run
 */
static int
sendBuffer (BufferEntry * be)
{
  unsigned int i;
  unsigned int j;
  unsigned int p;
  unsigned int rsi;
  struct SendCallbackList *pos;
  GNUNET_TransportPacket_HEADER *p2pHdr;
  unsigned int priority;
  char *plaintextMsg;
  void *encryptedMsg;
  unsigned int totalMessageSize;
  int ret;
  SendEntry **entries;
  unsigned int stotal;
  GNUNET_TSession *tsession;

  ENTRY ();
  /* fast ways out */
  if (be == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  if ((be->status != STAT_UP) ||
      (be->sendBufferSize == 0) || (be->inSendBuffer == GNUNET_YES))
    {
      return GNUNET_NO;         /* must not run */
    }
  be->inSendBuffer = GNUNET_YES;
  if ((GNUNET_OK != ensureTransportConnected (be)) ||
      (GNUNET_OK != checkSendFrequency (be)))
    {
      be->inSendBuffer = GNUNET_NO;
      return GNUNET_NO;
    }

  /* test if receiver has enough bandwidth available!  */
  updateCurBPS (be);
  totalMessageSize = selectMessagesToSend (be, &priority);
  if ((totalMessageSize == 0) && ((be->sendBufferSize != 0) || (be->session.mtu != 0) ||        /* only if transport has congestion control! */
                                  (be->available_send_window <
                                   2 * EXPECTED_MTU)))
    {
      expireSendBufferEntries (be);
      be->inSendBuffer = GNUNET_NO;
      return GNUNET_NO;         /* deferr further */
    }
  if (totalMessageSize == 0)
    totalMessageSize = EXPECTED_MTU + sizeof (GNUNET_TransportPacket_HEADER);
  GNUNET_GE_ASSERT (ectx,
                    totalMessageSize >
                    sizeof (GNUNET_TransportPacket_HEADER));
  if ((be->session.mtu != 0) && (totalMessageSize > be->session.mtu))
    {
      GNUNET_GE_BREAK (ectx, 0);
      be->inSendBuffer = GNUNET_NO;
      return GNUNET_NO;
    }
  ret = transport->send_now_test (be->session.tsession,
                                  totalMessageSize,
                                  (priority >=
                                   GNUNET_EXTREME_PRIORITY) ? GNUNET_YES :
                                  GNUNET_NO);
  /* ret: GNUNET_YES: ok to send, GNUNET_NO: not ready yet, GNUNET_SYSERR: session down
     or serious internal error */
  if (ret == GNUNET_SYSERR)
    {
      /* transport session is gone! re-establish! */
      tsession = be->session.tsession;
      be->session.tsession = NULL;
      if (tsession != NULL)
        transport->disconnect (tsession, __FILE__);
      ensureTransportConnected (be);
      if (be->session.tsession == NULL)
        {
#if DEBUG_CONNECTION
          GNUNET_EncName enc;
          IF_GELOG (ectx,
                    GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                    GNUNET_hash_to_enc (&be->session.sender.hashPubKey,
                                        &enc));
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                         GNUNET_GE_DEVELOPER,
                         "Session is DOWN for `%s' due to transport disconnect\n",
                         &enc);
#endif
          be->status = STAT_DOWN;
          be->time_established = 0;
          notify_disconnect (be);
          if (stats != NULL)
            stats->change (stat_closedTransport, 1);
          for (i = 0; i < be->sendBufferSize; i++)
            {
              GNUNET_free_non_null (be->sendBuffer[i]->closure);
              GNUNET_free (be->sendBuffer[i]);
            }
          GNUNET_array_grow (be->sendBuffer, be->sendBufferSize, 0);
        }
      /* This may have changed the MTU => need to re-do
         everything.  Since we don't want to possibly
         loop forever, give it another shot later;
         so even if "ensureTransportConnected" succeded,
         abort for now! */
    }
  if (GNUNET_YES != ret)
    {
      /* transport's buffer full -- no point in
         creating the actual message! */
      expireSendBufferEntries (be);
      be->inSendBuffer = GNUNET_NO;
      return GNUNET_NO;
    }
  /* check if we (sender) have enough bandwidth available
     if so, trigger callbacks on selected entries; if either
     fails, return (but clean up garbage) */
  if (GNUNET_SYSERR == outgoingCheck (priority,
                                      totalMessageSize /
                                      sizeof (GNUNET_TransportPacket_HEADER)))
    {
      expireSendBufferEntries (be);
      be->inSendBuffer = GNUNET_NO;
      return GNUNET_NO;         /* deferr further */
    }

  /* get permutation of SendBuffer Entries
     such that SE_FLAGS are obeyed */
  if (0 != prepareSelectedMessages (be))
    {
      entries = permuteSendBuffer (be, &stotal);
      if ((stotal == 0) || (entries == NULL))
        {
          /* no messages selected!? */
          GNUNET_GE_BREAK (ectx, 0);
          be->inSendBuffer = GNUNET_NO;
          GNUNET_free (entries);
          return GNUNET_NO;
        }
    }
  else
    {
      entries = NULL;
      stotal = 0;
    }

  /* build message */
  plaintextMsg = GNUNET_malloc (totalMessageSize);
  p2pHdr = (GNUNET_TransportPacket_HEADER *) plaintextMsg;
  p2pHdr->timeStamp = htonl (GNUNET_get_time_int32 (NULL));
  p2pHdr->sequenceNumber = htonl (be->lastSequenceNumberSend);
  p2pHdr->bandwidth =
    htonl (be->idealized_limit * (MAX_VIOLATIONS - be->violations) /
           MAX_VIOLATIONS);
  p = sizeof (GNUNET_TransportPacket_HEADER);
  for (i = 0; i < stotal; i++)
    {
      SendEntry *entry = entries[i];

      GNUNET_GE_ASSERT (ectx,
                        (entry != NULL) &&
                        (entry->knapsackSolution == GNUNET_YES) &&
                        (entry->callback == NULL) &&
                        (p + entry->len <= totalMessageSize));
      memcpy (&plaintextMsg[p], entry->closure, entry->len);
      p += entry->len;
    }
  GNUNET_free_non_null (entries);
  entries = NULL;
  if (p > totalMessageSize)
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_free (plaintextMsg);
      be->inSendBuffer = GNUNET_NO;
      return GNUNET_NO;
    }
  /* still room left? try callbacks! */
  pos = scl_head;
  while ((pos != NULL) && (p < totalMessageSize))
    {
      if ((pos->minimumPadding + p >= p) &&
          (pos->minimumPadding + p <= totalMessageSize))
        {
          rsi = pos->callback (&be->session.sender,
                               &plaintextMsg[p], totalMessageSize - p);
          GNUNET_GE_BREAK (ectx, rsi + p <= totalMessageSize);
          if ((rsi + p < p) || (rsi + p > totalMessageSize))
            {
              GNUNET_GE_BREAK (ectx, 0);
              GNUNET_free (plaintextMsg);
              be->inSendBuffer = GNUNET_NO;
              return GNUNET_NO;
            }
          p += rsi;
        }
      pos = pos->next;
    }
  if (((be->session.mtu != 0) &&
       (p > be->session.mtu)) || (p > totalMessageSize))
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_free (plaintextMsg);
      be->inSendBuffer = GNUNET_NO;
      return GNUNET_NO;
    }
  /* finally padd with noise */
  if ((p + sizeof (GNUNET_MessageHeader) <= totalMessageSize) &&
      (p < totalMessageSize) &&
      (p + sizeof (GNUNET_MessageHeader) > p)
      && (disable_random_padding == GNUNET_NO))
    {
      GNUNET_MessageHeader part;
      unsigned short noiseLen = totalMessageSize - p;

      part.size = htons (noiseLen);
      part.type = htons (GNUNET_P2P_PROTO_NOISE);
      memcpy (&plaintextMsg[p], &part, sizeof (GNUNET_MessageHeader));
      for (i = p + sizeof (GNUNET_MessageHeader); i < totalMessageSize; i++)
        plaintextMsg[i] = (char) rand ();
      p = totalMessageSize;
      if (stats != NULL)
        stats->change (stat_noise_sent, noiseLen);
    }
  if (((be->session.mtu != 0) &&
       (p > be->session.mtu)) || (p > totalMessageSize))
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_free (plaintextMsg);
      be->inSendBuffer = GNUNET_NO;
      return GNUNET_NO;
    }

  encryptedMsg = GNUNET_malloc (p);
  GNUNET_hash (&p2pHdr->sequenceNumber,
               p - sizeof (GNUNET_HashCode),
               (GNUNET_HashCode *) encryptedMsg);
  ret = GNUNET_AES_encrypt (&p2pHdr->sequenceNumber, p - sizeof (GNUNET_HashCode), &be->skey_local, (const GNUNET_AES_InitializationVector *) encryptedMsg,     /* IV */
                            &((GNUNET_TransportPacket_HEADER *)
                              encryptedMsg)->sequenceNumber);
  if (stats != NULL)
    stats->change (stat_encrypted, p - sizeof (GNUNET_HashCode));
  GNUNET_GE_ASSERT (ectx, be->session.tsession != NULL);
  ret = transport->send (be->session.tsession, encryptedMsg, p, GNUNET_NO);
  if ((ret == GNUNET_NO) && (priority >= GNUNET_EXTREME_PRIORITY))
    {
      ret =
        transport->send (be->session.tsession, encryptedMsg, p, GNUNET_YES);
    }
  if (ret == GNUNET_YES)
    {
      if (stats != NULL)
        stats->change (stat_transmitted, p);
      be->available_send_window -= p;
      be->lastSequenceNumberSend++;
      GNUNET_CORE_connection_reserve_downstream_bandwidth (&be->session.
                                                           sender, 0);
      if (be->idealized_limit > be->max_transmitted_limit)
        be->max_transmitted_limit = be->idealized_limit;
      else                      /* age */
        be->max_transmitted_limit
          = (be->idealized_limit + be->max_transmitted_limit * 3) / 4;

      if (rsnSize > 0)
        {
          j = sizeof (GNUNET_TransportPacket_HEADER);
          while (j < p)
            {
              GNUNET_MessageHeader *part =
                (GNUNET_MessageHeader *) & plaintextMsg[j];
              unsigned short plen = ntohs (MAKE_UNALIGNED (part->size));
              if (plen < sizeof (GNUNET_MessageHeader))
                {
                  GNUNET_GE_BREAK (ectx, 0);
                  break;
                }
              for (rsi = 0; rsi < rsnSize; rsi++)
                rsns[rsi] (&be->session.sender, part);
              j += plen;
            }
        }
      freeSelectedEntries (be);
    }
  if ((ret == GNUNET_SYSERR) && (be->session.tsession != NULL))
    {
#if DEBUG_CONNECTION
      GNUNET_EncName enc;
      IF_GELOG (ectx,
                GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                GNUNET_hash_to_enc (&be->session.sender.hashPubKey, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                     GNUNET_GE_DEVELOPER,
                     "Session is DOWN for `%s' due to transmission error\n",
                     &enc);
#endif
      tsession = be->session.tsession;
      be->session.tsession = NULL;
      be->status = STAT_DOWN;
      be->time_established = 0;
      notify_disconnect (be);
      if (stats != NULL)
        stats->change (stat_closedTransport, 1);
      transport->disconnect (tsession, __FILE__);
      for (i = 0; i < be->sendBufferSize; i++)
        {
          GNUNET_free_non_null (be->sendBuffer[i]->closure);
          GNUNET_free (be->sendBuffer[i]);
        }
      GNUNET_array_grow (be->sendBuffer, be->sendBufferSize, 0);
    }

  GNUNET_free (encryptedMsg);
  GNUNET_free (plaintextMsg);
  expireSendBufferEntries (be);
  be->inSendBuffer = GNUNET_NO;
  return GNUNET_NO;
}

/**
 * Append a message to the current buffer. This method
 * assumes that the access to be is already synchronized.
 *
 * @param be on which connection to transmit
 * @param se what to transmit (with meta-data)
 */
static void
appendToBuffer (BufferEntry * be, SendEntry * se)
{
#if DEBUG_CONNECTION
  GNUNET_EncName enc;
#endif
  float apri;
  unsigned int i;
  SendEntry **ne;
  unsigned long long queueSize;

  ENTRY ();
  if ((se == NULL) || (se->len == 0))
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_free_non_null (se);
      return;
    }
  if ((be->session.mtu != 0) &&
      (se->len > be->session.mtu - sizeof (GNUNET_TransportPacket_HEADER)))
    {
      be->consider_transport_switch = GNUNET_YES;
      /* this message is so big that it must be fragmented! */
      fragmentation->fragment (&be->session.sender,
                               be->session.mtu -
                               sizeof (GNUNET_TransportPacket_HEADER),
                               se->pri, se->transmissionTime, se->len,
                               se->callback, se->closure);
      GNUNET_free (se);
      return;
    }

  if ((be->sendBufferSize > 0) && (be->status != STAT_UP))
    {
      /* as long as we do not have a confirmed
         connection, do NOT queue messages! */
#if DEBUG_CONNECTION
      IF_GELOG (ectx,
                GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                GNUNET_hash_to_enc (&be->session.sender.hashPubKey, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "not connected to `%s', message dropped\n", &enc);
#endif
      GNUNET_free (se->closure);
      GNUNET_free (se);
      return;
    }
  queueSize = 0;
  for (i = 0; i < be->sendBufferSize; i++)
    queueSize += be->sendBuffer[i]->len;

  if (queueSize >= MAX_SEND_BUFFER_SIZE)
    {
      /* first, try to remedy! */
      sendBuffer (be);
      /* did it work? */

      queueSize = 0;
      for (i = 0; i < be->sendBufferSize; i++)
        queueSize += be->sendBuffer[i]->len;

      if (queueSize >= MAX_SEND_BUFFER_SIZE)
        {
          /* we need to enforce some hard limit here, otherwise we may take
             FAR too much memory (200 MB easily) */
          GNUNET_free (se->closure);
          GNUNET_free (se);
          return;
        }
    }
  /* grow send buffer, insertion sort! */
  ne = GNUNET_malloc ((be->sendBufferSize + 1) * sizeof (SendEntry *));
  GNUNET_GE_ASSERT (ectx, se->len != 0);
  apri = (float) se->pri / (float) se->len;
  i = 0;
  while ((i < be->sendBufferSize) &&
         (((float) be->sendBuffer[i]->pri /
           (float) be->sendBuffer[i]->len) >= apri))
    {
      ne[i] = be->sendBuffer[i];
      i++;
    }
  ne[i++] = se;
  while (i < be->sendBufferSize + 1)
    {
      ne[i] = be->sendBuffer[i - 1];
      i++;
    }
  GNUNET_free_non_null (be->sendBuffer);
  be->sendBuffer = ne;
  be->sendBufferSize++;
  sendBuffer (be);
}

/**
 * Look for a host in the table. If the entry is there at the time of
 * checking, returns the entry.
 *
 * @param hostId the ID of the peer for which the connection is returned
 * @return the connection of the host in the table, NULL if not connected
 */
static BufferEntry *
lookForHost (const GNUNET_PeerIdentity * hostId)
{
  BufferEntry *root;

  root =
    CONNECTION_buffer_[GNUNET_CORE_connection_compute_index_of_peer (hostId)];
  while (root != NULL)
    {
      if (0 == memcmp (&hostId->hashPubKey,
                       &root->session.sender.hashPubKey,
                       sizeof (GNUNET_HashCode)))
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
static BufferEntry *
addHost (const GNUNET_PeerIdentity * hostId, int establishSession)
{
  BufferEntry *root;
  BufferEntry *prev;
  unsigned int index;

  ENTRY ();
  root = lookForHost (hostId);
  index = GNUNET_CORE_connection_compute_index_of_peer (hostId);
  if (root == NULL)
    {
      root = CONNECTION_buffer_[index];
      prev = NULL;
      while (NULL != root)
        {
          /* settle for entry in the linked list that is down */
          if ((root->status == STAT_DOWN) ||
              (0 == memcmp (&hostId->hashPubKey,
                            &root->session.sender.hashPubKey,
                            sizeof (GNUNET_HashCode))))
            break;
          prev = root;
          root = root->overflowChain;
        }
      if (root == NULL)
        {
          root = initBufferEntry ();
          if (prev == NULL)
            CONNECTION_buffer_[index] = root;
          else
            prev->overflowChain = root;
        }
      root->session.sender = *hostId;
    }
  if ((root->status == STAT_DOWN) && (establishSession == GNUNET_YES))
    {
      root->lastSequenceNumberReceived = 0;
      session->tryConnect (hostId);
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
static int
forAllConnectedHosts (BufferEntryCallback method, void *arg)
{
  unsigned int i;
  int count = 0;
  BufferEntry *be;

  for (i = 0; i < CONNECTION_MAX_HOSTS_; i++)
    {
      be = CONNECTION_buffer_[i];
      while (be != NULL)
        {
          if (be->status == STAT_UP)
            {
              if (method != NULL)
                method (be, arg);
              count++;
            }
          be = be->overflowChain;
        }
    }
  return count;
}

struct fENHWrap
{
  GNUNET_NodeIteratorCallback method;
  void *arg;
};

/**
 * Little helper function for GNUNET_CORE_connection_iterate_peers.
 *
 * @param be the connection
 * @param arg closure of type fENHWrap giving the function
 *        to call
 */
static void
fENHCallback (BufferEntry * be, void *arg)
{
  struct fENHWrap *wrap = arg;

  if (wrap->method != NULL)
    wrap->method (&be->session.sender, wrap->arg);
}

/**
 * Shutdown the connection.  Send a HANGUP message to the other side
 * and mark the sessionkey as dead.  Assumes access is already
 * synchronized.
 *
 * @param be the connection to shutdown
 */
static void
shutdownConnection (BufferEntry * be)
{
  P2P_hangup_MESSAGE hangup;
  unsigned int i;
  GNUNET_TSession *tsession;
#if DEBUG_CONNECTION
  GNUNET_EncName enc;
#endif

  ENTRY ();
#if DEBUG_CONNECTION
  IF_GELOG (ectx,
            GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&be->session.sender.hashPubKey, &enc));
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Shutting down connection with `%s'\n", &enc);
#endif
  if (be->status == STAT_DOWN)
    return;                     /* nothing to do */
  if (be->status == STAT_UP)
    {
      SendEntry *se;
#if DEBUG_CONNECTION
      GNUNET_EncName enc;
      IF_GELOG (ectx,
                GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                GNUNET_hash_to_enc (&be->session.sender.hashPubKey, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                     GNUNET_GE_DEVELOPER,
                     "Session DOWN for `%s' due to HANGUP received\n", &enc);
#endif
      hangup.header.type = htons (GNUNET_P2P_PROTO_HANG_UP);
      hangup.header.size = htons (sizeof (P2P_hangup_MESSAGE));
      identity->getPeerIdentity (identity->getPublicPrivateKey (),
                                 &hangup.sender);
      se = GNUNET_malloc (sizeof (SendEntry));
      se->len = sizeof (P2P_hangup_MESSAGE);
      se->flags = SE_FLAG_PLACE_TAIL;
      se->pri = GNUNET_EXTREME_PRIORITY;
      se->transmissionTime = GNUNET_get_time ();        /* now */
      se->callback = NULL;
      se->closure = GNUNET_malloc (sizeof (P2P_hangup_MESSAGE));
      se->knapsackSolution = GNUNET_NO;
      memcpy (se->closure, &hangup, sizeof (P2P_hangup_MESSAGE));
      appendToBuffer (be, se);
      if (stats != NULL)
        stats->change (stat_hangupSent, 1);
      /* override send frequency and
         really try hard to get the HANGUP
         out! */
      be->lastSendAttempt = 0;
      sendBuffer (be);
    }
  be->skey_remote_created = 0;
  be->status = STAT_DOWN;
  notify_disconnect (be);
  be->time_established = 0;
  be->idealized_limit = MIN_BPM_PER_PEER;
  be->max_transmitted_limit = MIN_BPM_PER_PEER;
  if (be->session.tsession != NULL)
    {
      tsession = be->session.tsession;
      be->session.tsession = NULL;
      transport->disconnect (tsession, __FILE__);
    }
  for (i = 0; i < be->sendBufferSize; i++)
    {
      GNUNET_free_non_null (be->sendBuffer[i]->closure);
      GNUNET_free (be->sendBuffer[i]);
    }
  GNUNET_array_grow (be->sendBuffer, be->sendBufferSize, 0);
}

/* ******** inbound bandwidth scheduling ************* */

static void
gatherEntries (BufferEntry * be, void *cls)
{
  UTL_Closure *utl = cls;
  utl->e[utl->pos++] = be;
}

static void
resetRecentlyReceived (BufferEntry * be, void *unused)
{
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
static unsigned int
minConnect ()
{
  return CONNECTION_MAX_HOSTS_ / 2;
}

static int
remaining_connection_iterator (GNUNET_NodeIteratorCallback callback,
                               void *cb_arg, void *cls)
{
  UTL_Closure *utl = cls;
  unsigned int u;
  unsigned int r;

  r = 0;
  for (u = 0; u < utl->pos; u++)
    if (utl->e[u]->idealized_limit >= MIN_BPM_PER_PEER)
      {
        r++;
        if (callback != NULL)
          callback (&utl->e[u]->session.sender, cb_arg);
      }
  return r;
}

/**
 * Schedule the available inbound bandwidth among the peers.  Note
 * that this function is called A LOT (dozens of times per minute), so
 * it should execute reasonably fast.
 */
static void
scheduleInboundTraffic ()
{
  unsigned int activePeerCount;
  static GNUNET_CronTime lastRoundStart = 0;
  UTL_Closure utl;
  static GNUNET_CronTime timeDifference;
  GNUNET_CronTime now;
  BufferEntry **entries;
  double *shares;
  double shareSum;
  unsigned int u;
  unsigned int v;
  unsigned int minCon;
  unsigned int guardCon;
  long long schedulableBandwidth;
  long long decrementSB;
  long long *adjustedRR;
  int didAssign;
  int firstRound;
  int earlyRun;
  int load;
  unsigned int *perm;
  GNUNET_CronTime min_uptime;
  unsigned int min_uptime_slot;
#if DEBUG_CONNECTION
  GNUNET_EncName enc;
#endif

  GNUNET_mutex_lock (lock);
  now = GNUNET_get_time ();

  /* if this is the first round, don't bother... */
  if (lastRoundStart == 0)
    {
      /* no allocation the first time this function is called! */
      lastRoundStart = now;
      forAllConnectedHosts (&resetRecentlyReceived, NULL);
      GNUNET_mutex_unlock (lock);
      return;
    }
  activePeerCount = forAllConnectedHosts (NULL, NULL);
  if (activePeerCount == 0)
    {
      GNUNET_mutex_unlock (lock);
      return;                   /* nothing to be done here. */
    }

  /* if time difference is too small, we don't have enough
     sample data and should NOT update the limits;
     however, if we have FAR to few peers, reschedule
     aggressively (since we are unlikely to get close
     to the limits anyway) */
  timeDifference = now - lastRoundStart;
  earlyRun = 0;
  if (timeDifference < MIN_SAMPLE_TIME)
    {
      earlyRun = 1;
      if (activePeerCount > CONNECTION_MAX_HOSTS_ / 8)
        {
          GNUNET_mutex_unlock (lock);
          return;               /* don't update too frequently, we need at least some
                                   semi-representative sampling! */
        }
    }
  if (timeDifference == 0)
    timeDifference = 1;

  /* build an array containing all BEs */
  entries = GNUNET_malloc (sizeof (BufferEntry *) * activePeerCount);
  utl.pos = 0;
  utl.e = entries;
  forAllConnectedHosts (&gatherEntries, &utl);

  /* compute latest shares based on traffic preferences */
  shares = GNUNET_malloc (sizeof (double) * activePeerCount);
  shareSum = 0.0;
  for (u = 0; u < activePeerCount; u++)
    {
      shares[u] = SHARE_DISTRIBUTION_FUNCTION (entries[u]);
      if (shares[u] < 0.0)
        shares[u] = 0.0;
      shareSum += shares[u];
    }

  /* normalize distribution */
  if (shareSum >= 0.00001)
    {                           /* avoid numeric glitches... */
      for (u = 0; u < activePeerCount; u++)
        shares[u] = shares[u] / shareSum;
    }
  else
    {
      /* proportional shareing */
      for (u = 0; u < activePeerCount; u++)
        shares[u] = 1 / activePeerCount;
    }

  /* compute how much bandwidth we can bargain with */
  minCon = minConnect ();
  guardCon = topology->countGuardedConnections ();
  if (guardCon > minCon)
    minCon = guardCon;
  if (minCon > activePeerCount)
    minCon = activePeerCount;
  if (max_bpm > minCon * MIN_BPM_PER_PEER)
    {
      schedulableBandwidth = max_bpm - minCon * MIN_BPM_PER_PEER;
    }
  else
    {
      schedulableBandwidth = 0;
      minCon = max_bpm / MIN_BPM_PER_PEER;
    }
  load = GNUNET_network_monitor_get_load (load_monitor, GNUNET_ND_DOWNLOAD);
  if (load > 100)               /* take counter measure */
    schedulableBandwidth = schedulableBandwidth * 100 / load;
  /* compute recent activity profile of the peer */
  adjustedRR = GNUNET_malloc (sizeof (long long) * activePeerCount);
  GNUNET_GE_ASSERT (ectx, timeDifference != 0);
  for (u = 0; u < activePeerCount; u++)
    {
      adjustedRR[u]
        =
        entries[u]->recently_received * GNUNET_CRON_MINUTES / timeDifference /
        2;

#if DEBUG_CONNECTION
      if (adjustedRR[u] > entries[u]->idealized_limit)
        {
          IF_GELOG (ectx,
                    GNUNET_GE_INFO | GNUNET_GE_BULK | GNUNET_GE_USER,
                    GNUNET_hash_to_enc (&entries[u]->session.sender.
                                        hashPubKey, &enc));
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_INFO | GNUNET_GE_BULK | GNUNET_GE_USER,
                         "peer `%s' transmitted above limit: %llu bpm > %u bpm\n",
                         &enc, adjustedRR[u], entries[u]->idealized_limit);
        }
#endif
      /* Check for peers grossly exceeding send limits.  Be a bit
       * reasonable and make the check against the max value we have
       * sent to this peer (assume announcements may have got lost).
       */
      if ((earlyRun == 0) &&
          (adjustedRR[u] > 2 * MAX_BUF_FACT *
           entries[u]->max_transmitted_limit) &&
          (adjustedRR[u] > 2 * MAX_BUF_FACT * entries[u]->idealized_limit))
        {
          entries[u]->violations++;
          entries[u]->recently_received = 0;    /* "clear" slate */
          if (entries[u]->violations > MAX_VIOLATIONS)
            {
#if DEBUG_CONNECTION
              IF_GELOG (ectx,
                        GNUNET_GE_INFO | GNUNET_GE_BULK | GNUNET_GE_DEVELOPER,
                        GNUNET_hash_to_enc (&entries[u]->session.sender.
                                            hashPubKey, &enc));
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_INFO | GNUNET_GE_BULK |
                             GNUNET_GE_DEVELOPER,
                             "blacklisting `%s': sent repeatedly %llu bpm "
                             "(limit %u bpm, target %u bpm)\n", &enc,
                             adjustedRR[u], entries[u]->max_transmitted_limit,
                             entries[u]->idealized_limit);
#endif
              identity->blacklistHost (&entries[u]->session.sender, 24 * 60 * 60,       /* 1 day */
                                       GNUNET_YES);
              if (stats != NULL)
                stats->change (stat_shutdown_excessive_bandwidth, 1);
              shutdownConnection (entries[u]);
              activePeerCount--;
              entries[u] = entries[activePeerCount];
              shares[u] = shares[activePeerCount];
              adjustedRR[u] = adjustedRR[activePeerCount];
              u--;
              continue;
            }
        }
      else
        {
          if ((earlyRun == 0) &&
              (adjustedRR[u] < entries[u]->max_transmitted_limit / 2) &&
              (entries[u]->violations > 0))
            {
              /* allow very low traffic volume to
                 balance out (rare) times of high
                 volume */
              entries[u]->violations--;
            }
        }
      /* even if we received GNUNET_NO traffic, allow
         at least MIN_BPM_PER_PEER */
      if (adjustedRR[u] < MIN_BPM_PER_PEER)
        adjustedRR[u] = MIN_BPM_PER_PEER;
      /* initial adjustedRR's should reflect aged value
         from previous idealized_limit / iteration */
      adjustedRR[u] = (entries[u]->idealized_limit * 3 + adjustedRR[u]) / 4;
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

  didAssign = GNUNET_YES;
  /* in the first round we cap by 2* previous utilization */
  firstRound = GNUNET_YES;
  for (u = 0; u < activePeerCount; u++)
    {
      GNUNET_CORE_connection_reserve_downstream_bandwidth (&entries
                                                           [u]->
                                                           session.sender, 0);
      entries[u]->idealized_limit = 0;
    }
  while ((schedulableBandwidth > activePeerCount * 100) &&
         (activePeerCount > 0) && (didAssign == GNUNET_YES))
    {
      didAssign = GNUNET_NO;
      decrementSB = 0;
      for (u = 0; u < activePeerCount; u++)
        {
          if ((firstRound == GNUNET_NO) ||
              (entries[u]->idealized_limit < adjustedRR[u] * 2))
            {
              unsigned int share;

              share =
                entries[u]->idealized_limit +
                (unsigned int) (shares[u] * schedulableBandwidth);
              if (share < entries[u]->idealized_limit)
                share = 0xFFFFFFFF;     /* int overflow */
              if ((share > adjustedRR[u] * 2) && (firstRound == GNUNET_YES))
                share = adjustedRR[u] * 2;
              /* always allow allocating MIN_BPM_PER_PEER */
              if ((share < MIN_BPM_PER_PEER) &&
                  ((minCon > 0) &&
                   ((guardCon < minCon) ||
                    (topology->isConnectionGuarded
                     (&entries[u]->session.sender,
                      &remaining_connection_iterator, &utl)))))
                {
                  /* use one of the minCon's to keep the connection! */
                  share += MIN_BPM_PER_PEER;
                  decrementSB -= MIN_BPM_PER_PEER;      /* do not count */
                  minCon--;
                  if (topology->isConnectionGuarded
                      (&entries[u]->session.sender,
                       &remaining_connection_iterator, &utl))
                    guardCon--;
                }
              if (share > entries[u]->idealized_limit)
                {
                  decrementSB += share - entries[u]->idealized_limit;
                  didAssign = GNUNET_YES;
                  entries[u]->idealized_limit = share;
                }
            }
        }                       /* end for all peers */

      if (decrementSB < schedulableBandwidth)
        {
          schedulableBandwidth -= decrementSB;
        }
      else
        {
          schedulableBandwidth = 0;
          break;
        }
      if ((activePeerCount > 0) && (didAssign == GNUNET_NO))
        {
          perm = GNUNET_permute (GNUNET_RANDOM_QUALITY_WEAK, activePeerCount);
          /* assign also to random "worthless" (zero-share) peers */
          for (u = 0; u < activePeerCount; u++)
            {
              unsigned int v = perm[u]; /* use perm to avoid preference to low-numbered slots */
              if ((firstRound == GNUNET_NO) ||
                  (entries[v]->idealized_limit < adjustedRR[v] * 2))
                {
                  unsigned int share;

                  share =
                    entries[v]->idealized_limit +
                    (unsigned int) (schedulableBandwidth);
                  if (share < entries[v]->idealized_limit)
                    share = 0xFFFFFFFF; /* int overflow */
                  if ((firstRound == GNUNET_YES)
                      && (share > adjustedRR[v] * 2))
                    share = adjustedRR[v] * 2;
                  if (share > entries[v]->idealized_limit)
                    {
                      schedulableBandwidth -=
                        share - entries[v]->idealized_limit;
                      entries[v]->idealized_limit = share;
                    }
                }
            }
          GNUNET_free (perm);
          perm = NULL;
        }                       /* didAssign == GNUNET_NO? */
      if (firstRound == GNUNET_YES)
        {
          /* keep some bandwidth off the market
             for new connections */
          schedulableBandwidth = (schedulableBandwidth * 7) / 8;
        }
      firstRound = GNUNET_NO;
    }                           /* while bandwidth to distribute */

  if ((schedulableBandwidth > 0) && (activePeerCount > 0))
    {
      /* assign rest disregarding traffic limits */
      perm = GNUNET_permute (GNUNET_RANDOM_QUALITY_WEAK, activePeerCount);
      for (u = 0; u < activePeerCount; u++)
        {
          unsigned int share;
          unsigned int v = perm[u];     /* use perm to avoid preference to low-numbered slots */

          share =
            entries[v]->idealized_limit +
            (unsigned int) (schedulableBandwidth / activePeerCount);
          if (share >= entries[v]->idealized_limit)
            {                   /* no int-overflow? */
              entries[v]->idealized_limit = share;
            }
          else
            {
              entries[v]->idealized_limit = 0xFFFF0000;
            }
        }
      schedulableBandwidth = 0;
      GNUNET_free (perm);
      perm = NULL;
    }

  /* add the remaining MIN_BPM_PER_PEER to the minCon peers
     with the highest connection uptimes; by linking this with
     connection uptime, we reduce fluctuation */
  if (activePeerCount > 0)
    {
      if (minCon >= activePeerCount)
        {
          /* in this case, just add to all peers */
          for (u = 0; u < minCon; u++)
            {
              entries[u % activePeerCount]->idealized_limit
                += MIN_BPM_PER_PEER;
            }
        }
      else
        {                       /* minCon < activePeerCount */
          min_uptime = GNUNET_get_time ();
          min_uptime_slot = -1;
          for (v = 0; v < activePeerCount; v++)
            entries[v]->tes_selected = GNUNET_NO;
          for (u = 0; u < minCon; u++)
            {
              for (v = 0; v < activePeerCount; v++)
                {
                  if ((entries[v]->time_established != 0) &&
                      (entries[v]->time_established < min_uptime) &&
                      (entries[v]->tes_selected == GNUNET_NO))
                    {
                      min_uptime_slot = v;
                      min_uptime = entries[v]->time_established;
                    }
                }
              if (min_uptime_slot != -1)
                {
                  entries[min_uptime_slot]->tes_selected = GNUNET_YES;
                  entries[min_uptime_slot]->idealized_limit
                    += MIN_BPM_PER_PEER;
                }
            }                   /* for minCon */
        }                       /* if minCon < activePeerCount */
    }                           /* if we had active peers */

  /* prepare for next round */
  lastRoundStart = now;
  for (u = 0; u < activePeerCount; u++)
    {
#if DEBUG_CONNECTION
      IF_GELOG (ectx,
                GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_USER,
                GNUNET_hash_to_enc (&entries[u]->session.sender.hashPubKey,
                                    &enc));
      GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_USER,
                     "inbound limit for peer %u: %4s set to %u bpm (ARR: %lld, uptime: %llus, value: %lf)\n",
                     u, &enc, entries[u]->idealized_limit, adjustedRR[u],
                     (GNUNET_get_time () -
                      entries[u]->time_established) / GNUNET_CRON_SECONDS,
                     entries[u]->current_connection_value);
#endif
      if ((timeDifference > 50)
          &&
          (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, timeDifference + 1)
           > 50))
        entries[u]->current_connection_value *= 0.9;    /* age */
      decrementSB =
        entries[u]->idealized_limit * timeDifference / GNUNET_CRON_MINUTES /
        2;
      if ((decrementSB == 0)
          &&
          (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, timeDifference + 1)
           != 0))
        decrementSB = 1;
      if (entries[u]->recently_received >= decrementSB)
        entries[u]->recently_received -= decrementSB;
      else
        entries[u]->recently_received = 0;
    }

  /* free memory */
  GNUNET_free (adjustedRR);
  GNUNET_free (shares);

  for (u = 0; u < activePeerCount; u++)
    {
      BufferEntry *be = entries[u];

      if (be->idealized_limit < MIN_BPM_PER_PEER)
        {
#if DEBUG_CONNECTION
          IF_GELOG (ectx,
                    GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                    GNUNET_hash_to_enc (&be->session.sender.hashPubKey,
                                        &enc));
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                         GNUNET_GE_DEVELOPER,
                         "Number of connections too high, shutting down low-traffic connection to `%s' (had only %u bpm)\n",
                         &enc, be->idealized_limit);
#endif
          /* We need to avoid giving a too low limit (especially 0, which
             would indicate a plaintext msg).  So we set the limit to the
             minimum value AND try to shutdown the connection. */
          be->idealized_limit = MIN_BPM_PER_PEER;
          /* do not try to reconnect any time soon! */
          identity->blacklistHost (&be->session.sender,
                                   SECONDS_BLACKLIST_AFTER_DISCONNECT,
                                   GNUNET_YES);
          if (stats != NULL)
            stats->change (stat_shutdown_insufficient_bandwidth, 1);
          shutdownConnection (be);
        }
      else
        {
#if 0
          printf ("Assigned %u bytes to peer %u\n", be->idealized_limit, u);
#endif
        }
    }

  GNUNET_free (entries);
  GNUNET_mutex_unlock (lock);
}

/* ******** end of inbound bandwidth scheduling ************* */

/**
 * note: should we see that this cron job takes excessive amounts of
 * CPU on some systems, we may consider adding an OPTION to reduce the
 * frequency.  However, on my system, larger values significantly
 * impact the performance of the UDP transport for large (fragmented)
 * messages -- and 10ms does not cause any noticeable CPU load during
 * testing.
 */
#define CDL_FREQUENCY (10 * GNUNET_CRON_MILLISECONDS)

/**
 * Call this method periodically to drop dead connections.
 *
 * @param unused not used, just to make signature type nicely
 */
static void
cronDecreaseLiveness (void *unused)
{
  BufferEntry *root;
  BufferEntry *prev;
  BufferEntry *tmp;
  SendEntry *entry;
  GNUNET_CronTime now;
  int i;
  unsigned long long total_allowed_sent;
  unsigned long long total_allowed_now;
  unsigned long long total_allowed_recv;
  unsigned long long total_send_buffer_size;
  GNUNET_CronTime total_connection_lifetime;
  unsigned int connection_count;
  int load_nup;
  int load_cpu;
  GNUNET_TSession *tsession;

  ENTRY ();
  load_cpu = GNUNET_cpu_get_load (ectx, cfg);
  load_nup = GNUNET_network_monitor_get_load (load_monitor, GNUNET_ND_UPLOAD);
  scheduleInboundTraffic ();
  now = GNUNET_get_time ();
  total_allowed_sent = 0;
  total_allowed_recv = 0;
  total_allowed_now = 0;
  total_send_buffer_size = 0;
  connection_count = 0;
  total_connection_lifetime = 0;
  GNUNET_mutex_lock (lock);
  for (i = 0; i < CONNECTION_MAX_HOSTS_; i++)
    {
      root = CONNECTION_buffer_[i];
      prev = NULL;
      while (NULL != root)
        {
          total_send_buffer_size += root->sendBufferSize;
          switch (root->status)
            {
            case STAT_DOWN:
              /* just compact linked list */
              if (prev == NULL)
                CONNECTION_buffer_[i] = root->overflowChain;
              else
                prev->overflowChain = root->overflowChain;
              tmp = root;
              root = root->overflowChain;
              GNUNET_free (tmp);
              continue;         /* no need to call 'send buffer' */
            case STAT_UP:
              if ((root->time_established < now) &&
                  (root->time_established != 0))
                {
                  connection_count++;
                  total_connection_lifetime += now - root->time_established;
                }
              updateCurBPS (root);
              total_allowed_sent += root->max_bpm;
              total_allowed_recv += root->idealized_limit;
              total_allowed_now += root->available_send_window;
              if ((now > root->isAlive) &&      /* concurrency might make this false... */
                  (now - root->isAlive >
                   SECONDS_INACTIVE_DROP * GNUNET_CRON_SECONDS))
                {
#if DEBUG_CONNECTION
                  GNUNET_EncName enc;

                  /* switch state form UP to DOWN: too much inactivity */
                  IF_GELOG (ectx,
                            GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                            GNUNET_GE_DEVELOPER,
                            GNUNET_hash_to_enc (&root->session.sender.
                                                hashPubKey, &enc));
                  GNUNET_GE_LOG (ectx,
                                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                                 GNUNET_GE_DEVELOPER,
                                 "Closing connection with `%s': "
                                 "too much inactivity (%llu ms)\n", &enc,
                                 now - root->isAlive);
#endif
                  /* peer timed out -- shutdown connection */
                  identity->blacklistHost (&root->session.sender,
                                           SECONDS_BLACKLIST_AFTER_DISCONNECT,
                                           GNUNET_YES);
                  if (stats != NULL)
                    stats->change (stat_shutdown_timeout, 1);
                  shutdownConnection (root);
                }
              if ((root->consider_transport_switch == GNUNET_YES)
                  && (load_cpu < GNUNET_IDLE_LOAD_THRESHOLD))
                {
                  GNUNET_TSession *alternative;

                  GNUNET_GE_BREAK (NULL, root->session.mtu != 0);
                  alternative =
                    transport->connect_freely (&root->session.sender,
                                               GNUNET_NO, __FILE__);
                  if ((alternative != NULL)
                      && (transport->mtu_get (alternative->ttype) == 0))
                    {
                      tsession = root->session.tsession;
                      root->session.mtu = 0;
                      root->session.tsession = alternative;
                      alternative = NULL;
                      root->consider_transport_switch = GNUNET_NO;
                      if (tsession != NULL)
                        transport->disconnect (tsession, __FILE__);
                      if (stats != NULL)
                        stats->change (stat_transport_switches, 1);
                    }
                  if (alternative != NULL)
                    transport->disconnect (alternative, __FILE__);
                }
              if ((root->available_send_window > 35 * 1024) &&
                  (root->sendBufferSize < 4) &&
                  (scl_head != NULL) &&
                  (root->status == STAT_UP) &&
                  (load_nup < GNUNET_IDLE_LOAD_THRESHOLD) &&
                  (load_cpu < GNUNET_IDLE_LOAD_THRESHOLD))
                {
                  /* create some traffic by force! */
                  char *msgBuf;
                  unsigned int mSize;
                  struct SendCallbackList *pos;
                  unsigned int hSize;
                  unsigned int off;

                  hSize = root->available_send_window;
                  if (hSize > 63 * 1024)
                    hSize = 63 * 1024;
                  msgBuf = GNUNET_malloc (hSize);
                  pos = scl_head;
                  off = 0;
                  while ((pos != NULL) && (hSize > 0))
                    {
                      if (pos->minimumPadding <= hSize - off)
                        {
                          mSize = pos->callback (&root->session.sender,
                                                 &msgBuf[off], hSize - off);
                          GNUNET_GE_BREAK (ectx, mSize <= hSize - off);
                          off += mSize;
                        }
                      pos = pos->next;
                    }
                  if (off > 0)
                    {
                      msgBuf = GNUNET_realloc (msgBuf, off);
                      entry = GNUNET_malloc (sizeof (SendEntry));
                      entry->len = off;
                      entry->flags = SE_FLAG_NONE;
                      entry->pri = 0;
                      entry->transmissionTime =
                        GNUNET_get_time () + 5 * GNUNET_CRON_MINUTES;
                      entry->callback = NULL;
                      entry->closure = msgBuf;
                      entry->knapsackSolution = GNUNET_NO;
                      appendToBuffer (root, entry);
                    }
                  else
                    {
                      GNUNET_free (msgBuf);
                    }
                }
              break;
            default:           /* not up, not down - partial SETKEY exchange */
              if ((now > root->isAlive) &&
                  (now - root->isAlive >
                   SECONDS_NOPINGPONG_DROP * GNUNET_CRON_SECONDS))
                {
#if DEBUG_CONNECTION
                  GNUNET_EncName enc;

                  IF_GELOG (ectx,
                            GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                            GNUNET_GE_DEVELOPER,
                            GNUNET_hash_to_enc (&root->session.sender.
                                                hashPubKey, &enc));
                  GNUNET_GE_LOG (ectx,
                                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                                 GNUNET_GE_DEVELOPER,
                                 "closing connection to %s: %s not answered.\n",
                                 &enc,
                                 (root->status ==
                                  STAT_SETKEY_SENT) ? "SETKEY" : "PING");
#endif
                  /* do not try to reconnect any time soon,
                     but allow the other peer to connect to
                     us -- after all, we merely failed to
                     establish a session in the first place! */
                  identity->blacklistHost (&root->session.sender,
                                           SECONDS_BLACKLIST_AFTER_FAILED_CONNECT,
                                           GNUNET_NO);
                  if (stats != NULL)
                    stats->change (stat_shutdown_connect_timeout, 1);
                  shutdownConnection (root);
                }
              break;
            }                   /* end of switch */
          sendBuffer (root);
          prev = root;
          root = root->overflowChain;
        }                       /* end of while */
    }                           /* for all buckets */
  GNUNET_mutex_unlock (lock);
  if (stats != NULL)
    {
      if (total_allowed_sent > max_bpm_up)
        total_allowed_sent = max_bpm_up;
      stats->set (stat_total_allowed_sent, total_allowed_sent / 60);    /* bpm to bps */
      stats->set (stat_total_allowed_recv, total_allowed_recv / 60);    /* bpm to bps */
      stats->set (stat_total_allowed_now, total_allowed_now);
      stats->set (stat_total_send_buffer_size, total_send_buffer_size);
      if (connection_count > 0)
        stats->set (stat_avg_lifetime,
                    total_connection_lifetime / connection_count);
      else
        stats->set (stat_avg_lifetime, 0);
    }
  EXIT ();
}

/**
 * Check the sequence number and timestamp.  Decrypts the
 * message if it was encrypted.  Updates the sequence
 * number as a side-effect.
 *
 * @param sender from which peer did we receive the SEQ message
 * @param msg the p2p message (the decrypted message is stored here, too!)
 * @param size the size of the message
 * @return GNUNET_YES if the message was encrypted,
 *         GNUNET_NO if it was in plaintext,
 *         GNUNET_SYSERR if it was malformed
 */
int
GNUNET_CORE_connection_check_header (const GNUNET_PeerIdentity * sender,
                                     GNUNET_TransportPacket_HEADER * msg,
                                     unsigned short size)
{
  BufferEntry *be;
  int res;
  unsigned int sequenceNumber;
  GNUNET_Int32Time stamp;
  char *tmp;
  GNUNET_HashCode hc;
  GNUNET_EncName enc;

  ENTRY ();
  GNUNET_GE_ASSERT (ectx, msg != NULL);
  GNUNET_GE_ASSERT (ectx, sender != NULL);
  if (size < sizeof (GNUNET_TransportPacket_HEADER))
    {
      IF_GELOG (ectx,
                GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_DEVELOPER,
                GNUNET_hash_to_enc (&sender->hashPubKey, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_DEVELOPER,
                     _("Message from `%s' discarded: invalid format.\n"),
                     &enc);
      EXIT ();
      return GNUNET_SYSERR;
    }
  if (stats != NULL)
    stats->change (stat_received, size);
  GNUNET_hash_to_enc (&sender->hashPubKey, &enc);
  GNUNET_hash (&msg->sequenceNumber, size - sizeof (GNUNET_HashCode), &hc);
  if (0 == memcmp (&hc,
                   &msg->hash, sizeof (GNUNET_HashCode)) &&
      (msg->sequenceNumber == 0) &&
      (msg->bandwidth == 0) && (msg->timeStamp == 0))
    {
      EXIT ();
      return GNUNET_NO;         /* plaintext */
    }

  GNUNET_mutex_lock (lock);
  be = lookForHost (sender);
  if ((be == NULL) ||
      (be->status == STAT_DOWN) || (be->status == STAT_SETKEY_SENT))
    {
#if DEBUG_CONNECTION
      IF_GELOG (ectx,
                GNUNET_GE_INFO | GNUNET_GE_BULK | GNUNET_GE_DEVELOPER,
                GNUNET_hash_to_enc (&sender->hashPubKey, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_BULK | GNUNET_GE_DEVELOPER,
                     "Decrypting message from host `%s' failed, no sessionkey (yet)!\n",
                     &enc);
#endif
      /* try to establish a connection, that way, we don't keep
         getting bogus messages until the other one times out. */
      if ((be == NULL) || (be->status == STAT_DOWN))
        addHost (sender, GNUNET_YES);
      GNUNET_mutex_unlock (lock);
      EXIT ();
      return GNUNET_SYSERR;     /* could not decrypt */
    }
  tmp = GNUNET_malloc (size - sizeof (GNUNET_HashCode));
  res = GNUNET_AES_decrypt (&be->skey_remote, &msg->sequenceNumber, size - sizeof (GNUNET_HashCode), (const GNUNET_AES_InitializationVector *) &msg->hash,      /* IV */
                            tmp);
  GNUNET_hash (tmp, size - sizeof (GNUNET_HashCode), &hc);
  if (!
      ((res != GNUNET_OK)
       && (0 == memcmp (&hc, &msg->hash, sizeof (GNUNET_HashCode)))))
    {
#if DEBUG_CONNECTION
      IF_GELOG (ectx,
                GNUNET_GE_INFO | GNUNET_GE_BULK | GNUNET_GE_DEVELOPER,
                GNUNET_hash_to_enc (&sender->hashPubKey, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_BULK | GNUNET_GE_DEVELOPER,
                     "Decrypting message from host `%s' failed, wrong sessionkey!\n",
                     &enc);
#endif
      addHost (sender, GNUNET_YES);
      GNUNET_mutex_unlock (lock);
      GNUNET_free (tmp);
      EXIT ();
      return GNUNET_SYSERR;
    }
  if (stats != NULL)
    stats->change (stat_decrypted, size - sizeof (GNUNET_HashCode));
  memcpy (&msg->sequenceNumber, tmp, size - sizeof (GNUNET_HashCode));
  GNUNET_free (tmp);
  res = GNUNET_YES;
  sequenceNumber = ntohl (msg->sequenceNumber);
  if (be->lastSequenceNumberReceived >= sequenceNumber)
    {
      res = GNUNET_SYSERR;
      if ((be->lastSequenceNumberReceived - sequenceNumber <= 32) &&
          (be->lastSequenceNumberReceived != sequenceNumber))
        {
          unsigned int rotbit =
            1 << (be->lastSequenceNumberReceived - sequenceNumber - 1);
          if ((be->lastPacketsBitmap & rotbit) == 0)
            {
              be->lastPacketsBitmap |= rotbit;
              res = GNUNET_OK;
            }
        }
      if (res == GNUNET_SYSERR)
        {
#if DEBUG_CONNECTION
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                         GNUNET_GE_DEVELOPER,
                         _("Invalid sequence number"
                           " %u <= %u, dropping message.\n"), sequenceNumber,
                         be->lastSequenceNumberReceived);
#endif
          GNUNET_mutex_unlock (lock);
          EXIT ();
          return GNUNET_SYSERR;
        }
    }
  else
    {
      be->lastPacketsBitmap =
        be->lastPacketsBitmap
        << (sequenceNumber - be->lastSequenceNumberReceived);
      be->lastSequenceNumberReceived = sequenceNumber;
    }
  stamp = ntohl (msg->timeStamp);
  if (stamp + 1 * GNUNET_CRON_DAYS < GNUNET_get_time_int32 (NULL))
    {
#if DEBUG_CONNECTION
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Message received more than one day old. Dropped.\n"));
#endif
      GNUNET_mutex_unlock (lock);
      EXIT ();
      return GNUNET_SYSERR;
    }

  be->max_bpm = ntohl (msg->bandwidth);
  if (be->available_send_window > (long long) be->max_bpm * MAX_BUF_FACT)
    {
      if (stats != NULL)
        stats->change (stat_total_lost_sent,
                       be->available_send_window
                       - (long long) be->max_bpm * MAX_BUF_FACT);
      be->available_send_window = (long long) be->max_bpm * MAX_BUF_FACT;
      be->last_bps_update = GNUNET_get_time ();
    }
  be->recently_received += size;
  GNUNET_mutex_unlock (lock);
  EXIT ();
  return GNUNET_YES;
}

/**
 * Handler for processing P2P HANGUP message.  Terminates
 * a connection (if HANGUP message is valid).
 *
 * @param sender the peer sending the HANGUP message
 * @param msg the HANGUP message
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
handleHANGUP (const GNUNET_PeerIdentity * sender,
              const GNUNET_MessageHeader * msg)
{
  BufferEntry *be;
#if DEBUG_CONNECTION
  GNUNET_EncName enc;
#endif

  ENTRY ();
  if (ntohs (msg->size) != sizeof (P2P_hangup_MESSAGE))
    return GNUNET_SYSERR;
  if (0 != memcmp (sender,
                   &((P2P_hangup_MESSAGE *) msg)->sender,
                   sizeof (GNUNET_PeerIdentity)))
    return GNUNET_SYSERR;
#if DEBUG_CONNECTION
  IF_GELOG (ectx,
            GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
            GNUNET_hash_to_enc (&sender->hashPubKey, &enc));
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                 "received HANGUP from `%s'\n", &enc);
#endif
  GNUNET_mutex_lock (lock);
  be = lookForHost (sender);
  if (be == NULL)
    {
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  /* do not try to reconnect any time soon! */
  identity->blacklistHost (&be->session.sender,
                           SECONDS_BLACKLIST_AFTER_DISCONNECT, GNUNET_YES);
  if (stats != NULL)
    stats->change (stat_shutdown_hangup_received, 1);
  shutdownConnection (be);
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}


/**
 * Assign a session key for traffic from or to a given peer.
 * If the core does not yet have an entry for the given peer
 * in the connection table, a new entry is created.
 *
 * @param key the sessionkey,
 * @param peer the other peer,
 * @param forSending GNUNET_NO if it is the key for receiving,
 *                   GNUNET_YES if it is the key for sending
 */
void
GNUNET_CORE_connection_assign_session_key_to_peer (const GNUNET_AES_SessionKey
                                                   * key,
                                                   const GNUNET_PeerIdentity *
                                                   peer, GNUNET_Int32Time age,
                                                   int forSending)
{
  BufferEntry *be;

  ENTRY ();
  GNUNET_mutex_lock (lock);
  be = lookForHost (peer);
  if (be == NULL)
    be = addHost (peer, GNUNET_NO);
  if (be != NULL)
    {
      be->isAlive = GNUNET_get_time ();
      if (forSending == GNUNET_YES)
        {
          be->skey_local = *key;
          be->skey_local_created = age;
          be->status = STAT_SETKEY_SENT | (be->status & STAT_SETKEY_RECEIVED);
        }
      else
        {                       /* for receiving */
          if (((be->status & STAT_SETKEY_RECEIVED) == 0) ||
              (be->skey_remote_created < age))
            {
              if (0 !=
                  memcmp (key, &be->skey_remote,
                          sizeof (GNUNET_AES_SessionKey)))
                {
                  be->skey_remote = *key;
                  be->lastSequenceNumberReceived = 0;
                }
              be->skey_remote_created = age;
              be->status |= STAT_SETKEY_RECEIVED;
            }
        }
    }
  GNUNET_mutex_unlock (lock);
  EXIT ();
}

/**
 * Confirm that a connection is up.
 *
 * @param peer the other peer,
 */
void
GNUNET_CORE_connection_mark_session_as_confirmed (const GNUNET_PeerIdentity *
                                                  peer)
{
  BufferEntry *be;

  ENTRY ();
  GNUNET_mutex_lock (lock);
  be = lookForHost (peer);
  if (be != NULL)
    {
      be->isAlive = GNUNET_get_time ();
      identity->whitelistHost (peer);
      if (((be->status & STAT_SETKEY_SENT) > 0) &&
          ((be->status & STAT_SETKEY_RECEIVED) > 0) &&
          (GNUNET_OK == ensureTransportConnected (be))
          && (be->status != STAT_UP))
        {
#if DEBUG_CONNECTION
          GNUNET_EncName enc;
          IF_GELOG (ectx,
                    GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                    GNUNET_hash_to_enc (&peer->hashPubKey, &enc));
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                         GNUNET_GE_DEVELOPER,
                         "Received confirmation that session is UP for `%s'\n",
                         &enc);
#endif
          be->time_established = GNUNET_get_time ();
          be->status = STAT_UP;
          be->lastSequenceNumberReceived = 0;
          be->lastSequenceNumberSend = 1;
        }
    }
  GNUNET_mutex_unlock (lock);
  EXIT ();
}


/**
 * Get the current number of slots in the connection table (as computed
 * from the available bandwidth).
 */
int
GNUNET_CORE_connection_get_slot_count ()
{
  return CONNECTION_MAX_HOSTS_;
}

/**
 * Is the given slot used?
 * @return 0 if not, otherwise number of peers in
 * the slot
 */
int
GNUNET_CORE_connection_is_slot_used (int slot)
{
  BufferEntry *be;
  int ret;

  ENTRY ();
  ret = 0;
  GNUNET_mutex_lock (lock);
  if ((slot >= 0) && (slot < CONNECTION_MAX_HOSTS_))
    {
      be = CONNECTION_buffer_[slot];
      while (be != NULL)
        {
          if (be->status == STAT_UP)
            ret++;
          be = be->overflowChain;
        }
    }
  GNUNET_mutex_unlock (lock);
  EXIT ();
  return ret;
}

/**
 * Get the time of the last encrypted message that was received
 * from the given peer.
 * @param time updated with the time
 * @return GNUNET_SYSERR if we are not connected to the peer at the moment
 */
int
GNUNET_CORE_connection_get_last_activity_of_peer (const GNUNET_PeerIdentity *
                                                  peer,
                                                  GNUNET_CronTime * time)
{
  int ret;
  BufferEntry *be;

  ENTRY ();
  ret = 0;
  GNUNET_mutex_lock (lock);
  be = lookForHost (peer);
  if ((be != NULL) && (be->status == STAT_UP))
    {
      *time = be->isAlive;
      ret = GNUNET_OK;
    }
  else
    {
      *time = 0;
      ret = GNUNET_SYSERR;
    }
  GNUNET_mutex_unlock (lock);
  EXIT ();
  return ret;
}

/**
 * Obtain the session key used for traffic from or to a given peer.
 *
 * @param key the sessionkey (set)
 * @param age the age of the key (set)
 * @param peer the other peer,
 * @param forSending GNUNET_NO if it is the key for receiving,
 *                   GNUNET_YES if it is the key for sending
 * @return GNUNET_SYSERR if no sessionkey is known to the core,
 *         GNUNET_OK if the sessionkey was set.
 */
int
GNUNET_CORE_connection_get_session_key_of_peer (const GNUNET_PeerIdentity *
                                                peer,
                                                GNUNET_AES_SessionKey * key,
                                                GNUNET_Int32Time * age,
                                                int forSending)
{
  int ret;
  BufferEntry *be;

  ENTRY ();
  ret = GNUNET_SYSERR;
  GNUNET_mutex_lock (lock);
  be = lookForHost (peer);
  if (be != NULL)
    {
      if (forSending == GNUNET_YES)
        {
          if ((be->status & STAT_SETKEY_SENT) > 0)
            {
              if (key != NULL)
                *key = be->skey_local;
              if (age != NULL)
                *age = be->skey_local_created;
              ret = GNUNET_OK;
            }
        }
      else
        {                       /* for receiving */
          if ((be->status & STAT_SETKEY_RECEIVED) > 0)
            {
              if (key != NULL)
                *key = be->skey_remote;
              if (age != NULL)
                *age = be->skey_remote_created;
              ret = GNUNET_OK;
            }
        }
    }
  GNUNET_mutex_unlock (lock);
  EXIT ();
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
 * This method checks this.
 *
 * @param tsession the transport session that is for grabs
 * @param sender the identity of the other node
 */
void
GNUNET_CORE_connection_consider_takeover (const GNUNET_PeerIdentity * sender,
                                          GNUNET_TSession * tsession)
{
  BufferEntry *be;
  unsigned int cost;
  GNUNET_TSession *ts;

  ENTRY ();
  if (tsession == NULL)
    return;
  if (0 != memcmp (sender, &tsession->peer, sizeof (GNUNET_PeerIdentity)))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return;
    }
  GNUNET_mutex_lock (lock);
  be = addHost (sender, GNUNET_NO);
  if (be == NULL)
    {
      GNUNET_mutex_unlock (lock);
      EXIT ();
      return;
    }
  cost = -1;
  if (be->session.tsession != NULL)
    cost = transport->cost_get (be->session.tsession->ttype);
  /* Question: doesn't this always do takeover in tcp/udp
     case, which have the same costs? Should it? -IW

     Answer: this will always switch to TCP in the long run (if
     that is possible) since udpAssociate always
     returns GNUNET_SYSERR. This is intended since for long-running
     sessions, TCP is the better choice. UDP is only better for
     sending very few messages (e.g. attempting an initial exchange
     to get to know each other). See also transport paper and the
     data on throughput. - CG
   */
  if (((transport->cost_get (tsession->ttype) < cost) ||
       ((be->consider_transport_switch == GNUNET_YES) &&
        (transport->mtu_get (tsession->ttype) == 0))) &&
      (GNUNET_OK == transport->associate (tsession, __FILE__)))
    {
      GNUNET_GE_ASSERT (NULL,
                        GNUNET_OK == transport->assert_associated (tsession,
                                                                   __FILE__));
      ts = be->session.tsession;
      if (ts != NULL)
        {
          be->session.tsession = NULL;
          transport->disconnect (ts, __FILE__);
        }
      be->session.tsession = tsession;
      be->session.mtu = transport->mtu_get (tsession->ttype);
      if ((be->consider_transport_switch == GNUNET_YES) &&
          (transport->mtu_get (tsession->ttype) == 0))
        be->consider_transport_switch = GNUNET_NO;
      check_invariants ();
      fragmentIfNecessary (be);
    }
  EXIT ();
  GNUNET_mutex_unlock (lock);
  EXIT ();
}


/**
 * The configuration may have changed.  In particular, bandwidth
 * limits may now be different.  Adjust the connection table
 * accordingly.
 */
static int
connectionConfigChangeCallback (void *ctx,
                                struct GNUNET_GC_Configuration *cfg,
                                struct GNUNET_GE_Context *ectx,
                                const char *section, const char *option)
{
  unsigned long long new_max_bpm;
  unsigned int i;

  if (0 != strcmp (section, "LOAD"))
    return 0;                   /* fast path */
  if (-1 == GNUNET_GC_get_configuration_value_number (cfg, "LOAD", "MAXNETDOWNBPSTOTAL", 0, ((unsigned long long) -1) / 60, 50000,      /* default: 50 kbps */
                                                      &new_max_bpm))
    return GNUNET_SYSERR;
  GNUNET_GC_get_configuration_value_number (cfg, "LOAD", "MAXNETUPBPSTOTAL", 0, ((unsigned long long) -1) / 60, 50000,  /* default: 50 kbps */
                                            &max_bpm_up);
  max_bpm_up *= 60;             /* bps -> bpm */
  GNUNET_mutex_lock (lock);
  new_max_bpm = 60 * new_max_bpm;
  if (max_bpm != new_max_bpm)
    {
      unsigned int newMAXHOSTS = 0;

      max_bpm = new_max_bpm;
      newMAXHOSTS = max_bpm / (MIN_BPM_PER_PEER * 4);
      /* => for 1000 bps, we get 12 (rounded DOWN to 8) connections! */
      if (newMAXHOSTS < GNUNET_MIN_CONNECTION_TARGET * 2)
        newMAXHOSTS = GNUNET_MIN_CONNECTION_TARGET * 2;
      if (newMAXHOSTS > 256)
        newMAXHOSTS = 256;      /* limit, otherwise we run out of sockets! */

      if (newMAXHOSTS != CONNECTION_MAX_HOSTS_)
        {
          /* change size of connection buffer!!! */
          unsigned int olen;
          BufferEntry **newBuffer;

          olen = CONNECTION_MAX_HOSTS_;
          CONNECTION_MAX_HOSTS_ = newMAXHOSTS;
          GNUNET_GE_BREAK (ectx,
                           0 == GNUNET_GC_set_configuration_value_number (cfg,
                                                                          ectx,
                                                                          "gnunetd",
                                                                          "connection-max-hosts",
                                                                          CONNECTION_MAX_HOSTS_));
          newBuffer =
            (BufferEntry **) GNUNET_malloc (sizeof (BufferEntry *) *
                                            newMAXHOSTS);
          for (i = 0; i < CONNECTION_MAX_HOSTS_; i++)
            newBuffer[i] = NULL;

          /* rehash! */
          for (i = 0; i < olen; i++)
            {
              BufferEntry *be;

              be = CONNECTION_buffer_[i];
              while (be != NULL)
                {
                  BufferEntry *next;
                  unsigned int j;

                  next = be->overflowChain;
                  j =
                    GNUNET_CORE_connection_compute_index_of_peer
                    (&be->session.sender);
                  be->overflowChain = newBuffer[j];
                  newBuffer[j] = be;
                  be = next;
                }
            }
          GNUNET_free_non_null (CONNECTION_buffer_);
          CONNECTION_buffer_ = newBuffer;

          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "connection goal is %s%d peers (%llu BPM bandwidth downstream)\n",
                         (olen == 0) ? "" : "now ", CONNECTION_MAX_HOSTS_,
                         max_bpm);

        }
    }
  disable_random_padding = GNUNET_GC_get_configuration_value_yesno (cfg,
                                                                    "GNUNETD-EXPERIMENTAL",
                                                                    "PADDING",
                                                                    GNUNET_NO);
  GNUNET_mutex_unlock (lock);
  return 0;
}

/**
 * Initialize this module.
 */
void
GNUNET_CORE_connection_init (struct GNUNET_GE_Context *e,
                             struct GNUNET_GC_Configuration *c,
                             struct GNUNET_LoadMonitor *m,
                             struct GNUNET_CronManager *cm)
{
  ectx = e;
  cfg = c;
  load_monitor = m;
  cron = cm;
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_P2P_MESSAGE_OVERHEAD ==
                    sizeof (GNUNET_TransportPacket_HEADER));
  GNUNET_GE_ASSERT (ectx, sizeof (P2P_hangup_MESSAGE) == 68);
  ENTRY ();
  scl_head = NULL;
  connectionConfigChangeCallback (NULL, cfg, ectx, "LOAD", "NOTHING");
  GNUNET_GE_ASSERT (ectx,
                    0 == GNUNET_GC_attach_change_listener (cfg,
                                                           &connectionConfigChangeCallback,
                                                           NULL));
  GNUNET_GE_ASSERT (ectx, CONNECTION_MAX_HOSTS_ != 0);
  GNUNET_CORE_p2p_register_handler (GNUNET_P2P_PROTO_HANG_UP, &handleHANGUP);
  GNUNET_cron_add_job (cron,
                       &cronDecreaseLiveness, CDL_FREQUENCY, CDL_FREQUENCY,
                       NULL);
#if DEBUG_COLLECT_PRIO
  prioFile = FOPEN ("/tmp/knapsack_prio.txt", "w");
#endif

  transport = GNUNET_CORE_request_service ("transport");
  GNUNET_GE_ASSERT (ectx, transport != NULL);
  identity = GNUNET_CORE_request_service ("identity");
  GNUNET_GE_ASSERT (ectx, identity != NULL);
  session = GNUNET_CORE_request_service ("session");
  GNUNET_GE_ASSERT (ectx, session != NULL);
  fragmentation = GNUNET_CORE_request_service ("fragmentation");
  GNUNET_GE_ASSERT (ectx, fragmentation != NULL);
  topology = GNUNET_CORE_request_service ("topology");
  GNUNET_GE_ASSERT (ectx, topology != NULL);
  stats = GNUNET_CORE_request_service ("stats");
  if (stats != NULL)
    {
      stat_messagesDropped = stats->create (gettext_noop (      /* number of messages dropped by GNUnet core
                                                                   due to resource constraints */
                                                           "# outgoing messages dropped"));
      stat_sizeMessagesDropped = stats->create (gettext_noop (  /* bytes of messages dropped by GNUnet core
                                                                   due to resource constraints */
                                                               "# bytes of outgoing messages dropped"));
      stat_hangupSent
        = stats->create (gettext_noop ("# connections closed (HANGUP sent)"));
      stat_closedTransport
        =
        stats->create (gettext_noop
                       ("# connections closed (transport issue)"));
      stat_encrypted = stats->create (gettext_noop (    /* includes encrypted but then
                                                           not transmitted data */
                                                     "# bytes encrypted"));
      stat_transmitted = stats->create (gettext_noop (  /* encrypted data, confirmed by
                                                           transport, without transport
                                                           headers */
                                                       "# bytes transmitted"));
      stat_received = stats->create (gettext_noop (     /* encrypted data received
                                                           (incl. invalid/undecryptable data)
                                                           without transport headers */
                                                    "# bytes received"));
      stat_decrypted = stats->create (gettext_noop (    /* bytes successfully decrypted */
                                                     "# bytes decrypted"));
      stat_noise_sent = stats->create (gettext_noop ("# bytes noise sent"));
      stat_total_allowed_sent
        =
        stats->create (gettext_noop ("# total bytes per second send limit"));
      stat_total_allowed_recv =
        stats->create (gettext_noop
                       ("# total bytes per second receive limit"));
      stat_total_send_buffer_size =
        stats->create (gettext_noop
                       ("# total number of messages in send buffers"));
      stat_total_lost_sent =
        stats->create (gettext_noop
                       ("# total number of bytes we were allowed to send but did not"));
      stat_total_allowed_inc =
        stats->create (gettext_noop
                       ("# total number of bytes we were allowed to sent"));
      stat_total_allowed_now =
        stats->create (gettext_noop
                       ("# total number of bytes we are currently allowed to send"));
      stat_transport_switches =
        stats->create (gettext_noop
                       ("# transports switched to stream transport"));
      stat_avg_lifetime =
        stats->create (gettext_noop
                       ("# average connection lifetime (in ms)"));
      stat_shutdown_excessive_bandwidth =
        stats->create (gettext_noop
                       ("# conn. shutdown: other peer sent too much"));
      stat_shutdown_insufficient_bandwidth =
        stats->create (gettext_noop
                       ("# conn. shutdown: we lacked bandwidth"));
      stat_shutdown_timeout =
        stats->create (gettext_noop
                       ("# conn. shutdown: other peer timed out"));
      stat_shutdown_connect_timeout =
        stats->create (gettext_noop
                       ("# conn. shutdown: timed out during connect"));
      stat_shutdown_hangup_received =
        stats->create (gettext_noop
                       ("# conn. shutdown: other peer requested it"));
    }
  transport->start (&GNUNET_CORE_p2p_receive);
  EXIT ();
}


/**
 * Shutdown the connection module.
 */
void
GNUNET_CORE_connection_done ()
{
  unsigned int i;
  BufferEntry *be;
  struct SendCallbackList *scl;

  ENTRY ();
  GNUNET_GC_detach_change_listener (cfg, &connectionConfigChangeCallback,
                                    NULL);
  GNUNET_cron_del_job (cron, &cronDecreaseLiveness, CDL_FREQUENCY, NULL);
  for (i = 0; i < CONNECTION_MAX_HOSTS_; i++)
    {
      BufferEntry *prev;

      prev = NULL;
      be = CONNECTION_buffer_[i];
      while (be != NULL)
        {
#if DEBUG_CONNECTION
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "Closing connection: shutdown\n");
#endif
          shutdownConnection (be);
          prev = be;
          be = be->overflowChain;
          CONNECTION_buffer_[i] = be;
          GNUNET_free (prev);
        }
    }
  GNUNET_free_non_null (CONNECTION_buffer_);
  CONNECTION_buffer_ = NULL;
  CONNECTION_MAX_HOSTS_ = 0;
  while (scl_head != NULL)
    {
      scl = scl_head;
      scl_head = scl->next;
      GNUNET_free (scl);
    }
  transport->stop ();
  GNUNET_CORE_release_service (transport);
  transport = NULL;
  GNUNET_CORE_release_service (identity);
  identity = NULL;
  GNUNET_CORE_release_service (session);
  session = NULL;
  GNUNET_CORE_release_service (fragmentation);
  fragmentation = NULL;
  GNUNET_CORE_release_service (topology);
  topology = NULL;
  GNUNET_CORE_release_service (stats);
  stats = NULL;
#if DEBUG_COLLECT_PRIO
  if (prioFile != NULL)
    {
      fclose (prioFile);
      prioFile = NULL;
    }
#endif
  ectx = NULL;
  cfg = NULL;
  load_monitor = NULL;
  EXIT ();
}


/**
 * Wrapper around forAllConnectedHosts.  Calls a given
 * method for each connected host.
 *
 * @param method method to call for each connected peer
 * @param arg second argument to method
 * @return number of connected nodes
 */
int
GNUNET_CORE_connection_iterate_peers (GNUNET_NodeIteratorCallback method,
                                      void *arg)
{
  struct fENHWrap wrap;
  int ret;

  ENTRY ();
  wrap.method = method;
  wrap.arg = arg;
  GNUNET_mutex_lock (lock);
  ret = forAllConnectedHosts (&fENHCallback, &wrap);
  GNUNET_mutex_unlock (lock);
  EXIT ();
  return ret;
}

/**
 * Print the contents of the connection buffer (for debugging).
 */
void
GNUNET_CORE_connection_print_buffer ()
{
  unsigned int i;
  BufferEntry *tmp;
  GNUNET_EncName hostName;
  GNUNET_EncName skey_local;
  GNUNET_EncName skey_remote;
  unsigned int ttype;

  GNUNET_mutex_lock (lock);
  ENTRY ();
  for (i = 0; i < CONNECTION_MAX_HOSTS_; i++)
    {
      tmp = CONNECTION_buffer_[i];
      while (tmp != NULL)
        {
          if (tmp->status != STAT_DOWN)
            {
              GNUNET_hash_to_enc (&tmp->session.sender.hashPubKey, &hostName);
              GNUNET_hash_to_enc ((GNUNET_HashCode *) & tmp->skey_local,
                                  &skey_local);
              GNUNET_hash_to_enc ((GNUNET_HashCode *) & tmp->skey_remote,
                                  &skey_remote);
              hostName.encoding[4] = '\0';
              skey_local.encoding[4] = '\0';
              skey_remote.encoding[4] = '\0';
              ttype = 0;
              if (tmp->session.tsession != NULL)
                ttype = tmp->session.tsession->ttype;
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_INFO | GNUNET_GE_REQUEST |
                             GNUNET_GE_USER,
                             "CONNECTION-TABLE: %3d-%1d-%2d-%4ds"
                             " (of %ds) BPM %4llu %8ut-%3u: %s-%s-%s\n", i,
                             tmp->status, ttype,
                             (int) ((GNUNET_get_time () -
                                     tmp->isAlive) / GNUNET_CRON_SECONDS),
                             SECONDS_INACTIVE_DROP, tmp->recently_received,
                             tmp->idealized_limit, tmp->sendBufferSize,
                             &hostName, &skey_local, &skey_remote);
            }
          tmp = tmp->overflowChain;
        }
    }
  GNUNET_mutex_unlock (lock);
}

/**
 * Register a callback method that should be invoked whenever a
 * message is about to be send that has more than minimumPadding bytes
 * left before maxing out the MTU.  The callback method can then be
 * used to add additional content to the message (instead of the
 * random noise that is added by otherwise). Note that if the MTU is 0
 * (for streams), the callback method will always be called with
 * padding set to the maximum number of bytes left in the buffer
 * allocated for the send.
 *
 * @param minimumPadding how large must the padding be in order
 *   to call this method?
 * @param priority the higher the priority, the higher preference
 *        will be given to polling this callback (compared to
 *        other callbacks).  Note that polling will always
 *        only be done after all push requests (ciphertext_send) have
 *        been considered
 * @param callback the method to invoke. The receiver is the
 *   receiver of the message, position is the reference to the
 *   first unused position in the buffer where GNUnet is building
 *   the message, padding is the number of bytes left in that buffer.
 *   The callback method must return the number of bytes written to
 *   that buffer (must be a positive number).
 * @return GNUNET_OK if the handler was registered, GNUNET_SYSERR on error
 */
int
GNUNET_CORE_connection_register_send_callback (unsigned int
                                               minimumPadding,
                                               unsigned int priority,
                                               GNUNET_BufferFillCallback
                                               callback)
{
  struct SendCallbackList *scl;
  struct SendCallbackList *pos;
  struct SendCallbackList *prev;

  ENTRY ();
  scl = GNUNET_malloc (sizeof (struct SendCallbackList));
  scl->minimumPadding = minimumPadding;
  scl->callback = callback;
  scl->priority = priority;
  GNUNET_mutex_lock (lock);
  pos = scl_head;
  prev = NULL;
  while ((pos != NULL) && (pos->priority > priority))
    {
      prev = pos;
      pos = pos->next;
    }
  scl->next = pos;
  if (prev == NULL)
    scl_head = scl;
  else
    prev->next = scl;
  GNUNET_mutex_unlock (lock);
  EXIT ();
  return GNUNET_OK;
}

/**
 * Unregister a handler that was registered with GNUNET_CORE_connection_register_send_callback.
 *
 * @param minimumPadding how large must the padding be in order
 *   to call this method?
 * @param callback the method to invoke. The receiver is the
 *   receiver of the message, position is the reference to the
 *   first unused position in the buffer where GNUnet is building
 *   the message, padding is the number of bytes left in that buffer.
 *   The callback method must return the number of bytes written to
 *   that buffer (must be a positive number).
 * @return GNUNET_OK if the handler was removed, GNUNET_SYSERR on error
 */
int
GNUNET_CORE_connection_unregister_send_callback (unsigned int
                                                 minimumPadding,
                                                 GNUNET_BufferFillCallback
                                                 callback)
{
  struct SendCallbackList *pos;
  struct SendCallbackList *prev;

  ENTRY ();
  prev = NULL;
  GNUNET_mutex_lock (lock);
  pos = scl_head;
  while (pos != NULL)
    {
      if ((pos->callback == callback) &&
          (pos->minimumPadding == minimumPadding))
        {
          if (prev == NULL)
            scl_head = pos->next;
          else
            prev->next = pos->next;
          GNUNET_free (pos);
          GNUNET_mutex_unlock (lock);
          EXIT ();
          return GNUNET_OK;
        }
      prev = pos;
      pos = pos->next;
    }
  GNUNET_mutex_unlock (lock);
  EXIT ();
  return GNUNET_SYSERR;
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
 * @param msg the message to transmit, should contain MESSAGE_HEADERs
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure, GNUNET_NO on temporary failure
 */
int
GNUNET_CORE_connection_send_plaintext (GNUNET_TSession * tsession,
                                       const char *msg, unsigned int size)
{
  char *buf;
  int ret;
  GNUNET_TransportPacket_HEADER *hdr;

  ENTRY ();
  GNUNET_GE_ASSERT (ectx, tsession != NULL);
  if ((transport->mtu_get (tsession->ttype) > 0) &&
      (transport->mtu_get (tsession->ttype) <
       size + sizeof (GNUNET_TransportPacket_HEADER)))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  buf = GNUNET_malloc (size + sizeof (GNUNET_TransportPacket_HEADER));
  hdr = (GNUNET_TransportPacket_HEADER *) buf;
  hdr->sequenceNumber = 0;
  hdr->timeStamp = 0;
  hdr->bandwidth = 0;
  memcpy (&buf[sizeof (GNUNET_TransportPacket_HEADER)], msg, size);
  GNUNET_hash (&hdr->sequenceNumber,
               size + sizeof (GNUNET_TransportPacket_HEADER) -
               sizeof (GNUNET_HashCode), &hdr->hash);
  ret =
    transport->send (tsession, buf,
                     size + sizeof (GNUNET_TransportPacket_HEADER),
                     GNUNET_YES);
  GNUNET_free (buf);
  EXIT ();
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
void
GNUNET_CORE_connection_send_using_callback (const GNUNET_PeerIdentity *
                                            hostId,
                                            GNUNET_BuildMessageCallback
                                            callback, void *closure,
                                            unsigned short len,
                                            unsigned int importance,
                                            unsigned int maxdelay)
{
  BufferEntry *be;
  SendEntry *entry;

  ENTRY ();
  GNUNET_mutex_lock (lock);
  be = addHost (hostId, GNUNET_YES);
  if ((be != NULL) && (be->status != STAT_DOWN))
    {
      entry = GNUNET_malloc (sizeof (SendEntry));
      entry->len = len;
      entry->flags = SE_FLAG_NONE;
      entry->pri = importance;
      entry->transmissionTime = GNUNET_get_time () + maxdelay;
      entry->callback = callback;
      entry->closure = closure;
      entry->knapsackSolution = GNUNET_NO;
      appendToBuffer (be, entry);
    }
  else
    {
      GNUNET_free_non_null (closure);
    }
  GNUNET_mutex_unlock (lock);
  EXIT ();
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
void
GNUNET_CORE_connection_unicast (const GNUNET_PeerIdentity * receiver,
                                const GNUNET_MessageHeader * msg,
                                unsigned int importance,
                                unsigned int maxdelay)
{
  char *closure;
  unsigned short len;

  ENTRY ();
  if (GNUNET_CORE_connection_get_bandwidth_assigned_to_peer
      (receiver, NULL, NULL) != GNUNET_OK)
    session->tryConnect (receiver);
  if (msg == NULL)
    {
      EXIT ();
      return;
    }
  len = ntohs (msg->size);
  if (len == 0)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_DEVELOPER,
                     "Empty message send (hopefully used to initiate connection attempt)\n");
      EXIT ();
      return;
    }
  closure = GNUNET_malloc (len);
  memcpy (closure, msg, len);
  GNUNET_CORE_connection_send_using_callback (receiver, NULL, closure, len,
                                              importance, maxdelay);
  EXIT ();
}

/**
 * Compute the hashtable index of a host id.
 *
 * @param hostId the ID of a peer
 * @return the index for this peer in the connection table
 */
unsigned int
GNUNET_CORE_connection_compute_index_of_peer (const GNUNET_PeerIdentity *
                                              hostId)
{
  unsigned int res;

  ENTRY ();
  res = (((unsigned int) hostId->hashPubKey.bits[0]) &
         ((unsigned int) (CONNECTION_MAX_HOSTS_ - 1)));
  GNUNET_GE_ASSERT (ectx, res < CONNECTION_MAX_HOSTS_);
  return res;
}

/**
 * Obtain the lock for the connection module
 *
 * @return the lock
 */
struct GNUNET_Mutex *
GNUNET_CORE_connection_get_lock ()
{
  GNUNET_GE_ASSERT (NULL, lock != NULL);
  return lock;
}

int
GNUNET_CORE_connection_get_bandwidth_assigned_to_peer (const
                                                       GNUNET_PeerIdentity *
                                                       node,
                                                       unsigned int *bpm,
                                                       GNUNET_CronTime *
                                                       last_seen)
{
  BufferEntry *be;
  unsigned int ret;

  ENTRY ();
  GNUNET_mutex_lock (lock);
  be = lookForHost (node);
  if ((be != NULL) && (be->status == STAT_UP))
    {
      if (bpm != NULL)
        *bpm = be->idealized_limit;
      if (last_seen != NULL)
        *last_seen = be->isAlive;
      ret = GNUNET_OK;
    }
  else
    {
      ret = GNUNET_SYSERR;
    }
  GNUNET_mutex_unlock (lock);
  EXIT ();
  return ret;
}

/**
 * Increase the preference for traffic from some other peer.
 * @param node the identity of the other peer
 * @param preference how much should the traffic preference be increased?
 */
void
GNUNET_CORE_connection_update_traffic_preference_for_peer (const
                                                           GNUNET_PeerIdentity
                                                           * node,
                                                           double preference)
{
  BufferEntry *be;

  ENTRY ();
  GNUNET_mutex_lock (lock);
  be = lookForHost (node);
  if (be != NULL)
    be->current_connection_value += preference;
  GNUNET_mutex_unlock (lock);
  EXIT ();
}

/**
 * Disconnect a particular peer.  Sends a HANGUP message to the other
 * side and mark the sessionkey as dead.
 *
 * @param peer the peer to disconnect
 */
void
GNUNET_CORE_connection_disconnect_from_peer (const GNUNET_PeerIdentity * node)
{
  BufferEntry *be;

  ENTRY ();
  GNUNET_mutex_lock (lock);
  be = lookForHost (node);
  if (be != NULL)
    {
#if DEBUG_CONNECTION
      GNUNET_EncName enc;

      IF_GELOG (ectx,
                GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                GNUNET_hash_to_enc (&node->hashPubKey, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                     GNUNET_GE_DEVELOPER,
                     "Closing connection to `%s' as requested by application.\n",
                     &enc);
#endif
      /* do not try to reconnect any time soon! */
      identity->blacklistHost (&be->session.sender,
                               SECONDS_BLACKLIST_AFTER_DISCONNECT,
                               GNUNET_YES);
      shutdownConnection (be);
    }
  GNUNET_mutex_unlock (lock);
  EXIT ();
}

/**
 * Register a handler that is to be called for each
 * message that leaves the peer.
 *
 * @param callback the method to call for each
 *        P2P message part that is transmitted
 * @return GNUNET_OK on success, GNUNET_SYSERR if there is a problem
 */
int
  GNUNET_CORE_connection_register_send_notification_callback
  (GNUNET_P2PRequestHandler callback)
{
  if (callback == NULL)
    return GNUNET_SYSERR;
  ENTRY ();
  GNUNET_mutex_lock (lock);
  GNUNET_array_grow (rsns, rsnSize, rsnSize + 1);
  rsns[rsnSize - 1] = callback;
  GNUNET_mutex_unlock (lock);
  EXIT ();
  return GNUNET_OK;
}

/**
 * Unregister a handler that is to be called for each
 * message that leaves the peer.
 *
 * @param callback the method to call for each
 *        P2P message part that is transmitted
 * @return GNUNET_OK on success, GNUNET_SYSERR if there is a problem
 */
int
  GNUNET_CORE_connection_unregister_send_notification_callback
  (GNUNET_P2PRequestHandler callback)
{
  int i;

  if (callback == NULL)
    return GNUNET_OK;
  ENTRY ();
  GNUNET_mutex_lock (lock);
  for (i = 0; i < rsnSize; i++)
    {
      if (rsns[i] == callback)
        {
          rsns[i] = rsns[rsnSize - 1];
          GNUNET_array_grow (rsns, rsnSize, rsnSize - 1);
          GNUNET_mutex_unlock (lock);
          return GNUNET_OK;
        }
    }
  GNUNET_mutex_unlock (lock);
  EXIT ();
  return GNUNET_SYSERR;
}



/**
 * Verify that the given session handle is not in use.
 * @return GNUNET_OK if that is true, GNUNET_SYSERR if not.
 */
int
GNUNET_CORE_connection_assert_tsession_unused (GNUNET_TSession * tsession)
{
  int i;
  BufferEntry *root;

  ENTRY ();
  GNUNET_mutex_lock (lock);
  for (i = 0; i < CONNECTION_MAX_HOSTS_; i++)
    {
      root = CONNECTION_buffer_[i];
      while (NULL != root)
        {
          if (root->session.tsession == tsession)
            {
              GNUNET_GE_BREAK (ectx, 0);
              GNUNET_mutex_unlock (lock);
              EXIT ();
              return GNUNET_SYSERR;
            }
          root = root->overflowChain;
        }
    }
  GNUNET_mutex_unlock (lock);
  EXIT ();
  return GNUNET_OK;
}



/**
 * Call the given function whenever we get
 * disconnected from a particular peer.
 *
 * @return GNUNET_OK
 */
int
  GNUNET_CORE_connection_register_notify_peer_disconnect
  (GNUNET_NodeIteratorCallback callback, void *cls)
{
  struct DisconnectNotificationList *l;

  l = GNUNET_malloc (sizeof (struct DisconnectNotificationList));
  l->callback = callback;
  l->cls = cls;
  GNUNET_mutex_lock (lock);
  l->next = disconnect_notification_list;
  disconnect_notification_list = l;
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

/**
 * Stop calling the given function whenever we get
 * disconnected from a particular peer.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR
 *         if this callback is not registered
 */
int
  GNUNET_CORE_connection_unregister_notify_peer_disconnect
  (GNUNET_NodeIteratorCallback callback, void *cls)
{
  struct DisconnectNotificationList *pos;
  struct DisconnectNotificationList *prev;

  prev = NULL;
  GNUNET_mutex_lock (lock);
  pos = disconnect_notification_list;
  while (pos != NULL)
    {
      if ((pos->callback == callback) && (pos->cls == cls))
        {
          if (prev == NULL)
            disconnect_notification_list = pos->next;
          else
            prev->next = pos->next;
          GNUNET_free (pos);
          GNUNET_mutex_unlock (lock);
          return GNUNET_OK;
        }
      prev = pos;
      pos = pos->next;
    }
  GNUNET_mutex_unlock (lock);
  return GNUNET_SYSERR;

}

/**
 * Try to reserve downstream bandwidth for a particular peer.
 *
 * @param peer with whom should bandwidth be reserved?
 * @param amount how many bytes should we expect to receive?
 *        (negative amounts can be used to undo a (recent)
 *        reservation request
 * @return amount that could actually be reserved
 */
int
GNUNET_CORE_connection_reserve_downstream_bandwidth (const GNUNET_PeerIdentity
                                                     * peer, int amount)
{
  BufferEntry *be;
  unsigned long long available;
  GNUNET_CronTime now;
  GNUNET_CronTime delta;

  GNUNET_mutex_lock (lock);
  be = lookForHost (peer);
  if ((be == NULL) || (be->status != STAT_UP))
    {
      GNUNET_mutex_unlock (lock);
      return 0;                 /* not connected */
    }
  now = GNUNET_get_time ();
  delta = now - be->last_reservation_update;
  available =
    be->available_downstream +
    be->idealized_limit * delta / GNUNET_CRON_MINUTES;
  if (amount < 0)
    available -= amount;
  if (available > be->idealized_limit * MAX_BUF_FACT)
    available = be->idealized_limit * MAX_BUF_FACT;
  if ((amount > 0) && (available < amount))
    amount = (int) available;
  if (amount > 0)
    available -= amount;
  be->last_reservation_update = now;
  be->available_downstream = available;
  GNUNET_mutex_unlock (lock);
  return available;
}

void __attribute__ ((constructor)) GNUNET_CORE_connection_ltdl_init ()
{
  lock = GNUNET_mutex_create (GNUNET_YES);
}

void __attribute__ ((destructor)) GNUNET_CORE_connection_ltdl_fini ()
{
  GNUNET_mutex_destroy (lock);
}



/* end of connection.c */
