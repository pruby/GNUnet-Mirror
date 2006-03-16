/*
      This file is part of GNUnet
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
      Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
      Boston, MA 02110-1301, USA.
 */

/**
 * @file gap/gap.h
 * @brief protocol that performs anonymous routing
 * @author Christian Grothoff
 *
 * This file just contains the constants and types.
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_core.h"
#include "gnunet_protocols.h"
#include "gnunet_gap_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_stats_service.h"
#include "gnunet_traffic_service.h"
#include "gnunet_topology_service.h"

#define DEBUG_GAP NO

#define EXTRA_CHECKS YES


/* ***************** policy constants **************** */

/**
 * Until which load do we consider the peer idle and do not
 * charge at all?
 */
#define IDLE_LOAD_THRESHOLD 50

/**
 * For how many different hosts can we have a query pending (at most).
 * If this threshold is crossed, the hosts waiting list is reset.
 */
#define MAX_HOSTS_WAITING 16

/**
 * How many seen values do we keep at most for any given query before
 * we kill it (or at least start to do a probabilistic drop).
 */
#define MAX_SEEN_VALUES 32

/**
 * By which amount do we decrement the TTL for simple forwarding /
 * indirection of the query; in milli-seconds.  Set somewhat in
 * accordance to your network latency (above the time it'll take you
 * to send a packet and get a reply).
 */
#define TTL_DECREMENT 5 * cronSECONDS

/**
 * Send answer if local files match
 */
#define QUERY_ANSWER   0x00020000

/**
 * Forward the query, priority is encoded in QUERY_PRIORITY_BITMASK
 */
#define QUERY_FORWARD  0x00040000

/**
 * Indirect the query (use this as the originating node)
 */
#define QUERY_INDIRECT 0x00080000

/**
 * Drop the query if & with this bitmask is 0
 */
#define QUERY_DROPMASK (QUERY_ANSWER|QUERY_FORWARD|QUERY_INDIRECT)

/**
 * Bandwidth value of an (effectively) 0-priority query.
 */
#define QUERY_BANDWIDTH_VALUE 0.001

/**
 * Bandwidth value of a 0-priority content (must be
 * fairly high compared to query since content is
 * typically significantly larger -- and more valueable
 * since it can take many queries to get one piece of
 * content).
 */
#define CONTENT_BANDWIDTH_VALUE 0.8

/**
 * Default size of the bitmap that we use for marking to which
 * peers a query has already been sent to.  16 byte = 128 bits
 */
#define BITMAP_SIZE 16

/**
 * Of how many outbound queries do we simultaneously keep track?
 */
#define QUERY_RECORD_COUNT 512

/**
 * How much is a query worth 'in general' (even
 * if there is no trust relationship between
 * the peers!).  Multiplied by the number of queries
 * in the request.  20 is for '20 bytes / hash',
 * so this is kind of the base unit.
 */
#define BASE_QUERY_PRIORITY 20

/**
 * How much is a response worth 'in general'.  Since replies are
 * roughly 1k and should be much (factor of 4) preferred over queries
 * (which have a base priority of 20, which yields a base unit of
 * roughly 1 per byte).  Thus if we set this value to 4092 we'd rather
 * send a reply instead of a query unless the queries have (on
 * average) a priority that is more than double the reply priority
 * (note that querymanager multiplies the query priority with 2 to
 * compute the scheduling priority).
 */
#define BASE_REPLY_PRIORITY 4092

/**
 * minimum indirection table size, defaults to 8192 entries, reduce if
 * you have very little memory, enlarge if you start to overflow often
 * and have memory available.<p>
 *
 * If the average query lives for say 1 minute (10 hops), and you have
 * a 56k connection (= 420 kb/minute, or approximately 8000
 * queries/minute) the maximum reasonable routing table size would
 * thus be 8192 entries.  Every entry takes about 68 bytes.<p>
 *
 * The larger the value is that you pick here, the greater your
 * anonymity can become.  It also can improve your download speed.<p>
 *
 * Memory consumption:
 * <ul>
 * <li>8192 => 560k indirection table => approx. 6 MB gnunetd</li>
 * <li>65536 => 4456k indirection table => approx. 10 MB gnuentd</li>
 * </ul>
 * <p>
 * THE VALUE YOU PICK MUST BE A POWER OF 2, for example:
 * 128, 256, 512, 1024, 2048, 4092, 8192, 16384, 32768, 65536
 */
#define MIN_INDIRECTION_TABLE_SIZE 1024
/* #define MIN_INDIRECTION_TABLE_SIZE 8 */

/**
 * Under certain cirumstances, two peers can interlock in their
 * routing such that both have a slot that is blocked exactly until
 * the other peer will make that slot available.  This is the
 * probability that one will give in.  And yes, it's a hack.  It
 * may not be needed anymore once we add collision-resistance to
 * the routing hash table.
 */
#define TIE_BREAKER_CHANCE 4

/**
 * For how many _local_ requests do we track the current, non-zero
 * request priorities for rewarding peers that send replies?  If this
 * number is too low, we will 'forget' to reward peers for good
 * replies (and our routing will degrade).  If it is too high, we'll
 * scan though a large array for each content message and waste
 * memory.<p>
 *
 * A good value reflects the number of concurrent, local queries that
 * we expect to see.
 */
#define MAX_REWARD_TRACKS 128

/**
 * ITE modes for addToSlot.
 */
#define ITE_REPLACE 0
#define ITE_GROW 1


/* **************** Types ****************** */

/**
 * Type of the results of the polciy module
 */
typedef unsigned int QUERY_POLICY;

/**
 * Request for content. The number of queries can
 * be determined from the header size.
 */
typedef struct {
  P2P_MESSAGE_HEADER header;

  /**
   * Type of the query (block type).
   */
  unsigned int type;

  /**
   * How important is this request (network byte order)
   */
  unsigned int priority;

  /**
   * Relative time to live in cronMILLIS (network byte order)
   */
  int ttl;

  /**
   * To whom to return results?
   */
  PeerIdentity returnTo;

  /**
   * Hashcodes of the file(s) we're looking for.
   * Details depend on the query type.
   */
  HashCode512 queries[1];

} P2P_gap_query_MESSAGE;

/**
 * Return message for search result.
 */
typedef struct {
  P2P_MESSAGE_HEADER header;

  HashCode512 primaryKey;

} P2P_gap_reply_MESSAGE;

/**
 * In this struct, we store information about a
 * query that is being send from the local node to
 * optimize the sending strategy.
 */
typedef struct {

  /**
   * How often did we send this query so far?
   */
  unsigned int sendCount;

  /**
   * How many nodes were connected when we initated sending this
   * query?
   */
  unsigned int activeConnections;

  /**
   * What is the total distance of the query to the connected nodes?
   */
  unsigned long long totalDistance;

  /**
   * The message that we are sending.
   */
  P2P_gap_query_MESSAGE * msg;

  /**
   * How important would it be to send the message to all peers in
   * this bucket?
   */
  int * rankings;

  /**
   * When do we stop forwarding (!) this query?
   */
  cron_t expires;

  /**
   * To which peer will we never send this message?
   */
  PeerIdentity noTarget;

  /**
   * Bit-map marking the hostIndices (computeIndex) of nodes that have
   * received this query already.  Note that the bit-map has a maximum
   * size, if the index is out-of-bounds, it is hashed into the
   * smaller size of the bitmap. There may thus be nodes with
   * identical indices, in that case, only one of the nodes will
   * receive the query.
   */
  unsigned char bitmap[BITMAP_SIZE];

  /**
   * To how many peers has / will this query be transmitted?
   */
  unsigned int transmissionCount;

} QueryRecord;

/**
 * Indirection table entry. Lists what we're looking for,
 * where to forward it, and how long to keep looking for it.
 * Keep this struct as small as possible -- an array of these
 * takes 80% of GNUnet's memory.
 */
typedef struct {
  /**
   * What are we waiting for?
   */
  HashCode512 primaryKey;

  /**
   * For what type of reply are we waiting?
   */
  unsigned int type;

  /**
   * How much is this query worth to us, that is, how much would
   * this node be willing to "pay" for an answer that matches the
   * hash stored in this ITE? (This is NOT the inbound priority,
   * it is the trust-adjusted inbound priority.)
   */
  unsigned int priority;

  /**
   * When can we forget about this entry?
   */
  cron_t ttl;

  /**
   * Which replies have we already seen?
   */
  unsigned int seenIndex;

  int seenReplyWasUnique; /* YES/NO, only valid if seenIndex == 1 */

  /**
   * Hashcodes of the encrypted (!) replies that we have forwarded so far
   */
  HashCode512 * seen;

  /**
   * Who are these hosts?
   */
  PeerIdentity * destination;

  /**
   * How many hosts are waiting for an answer to this query (length of
   * destination array)
   */
  unsigned int hostsWaiting;

  /**
   * Do we currently have a response in the delay loop (delays are
   * introduced to make traffic analysis harder and thus enable
   * anonymity)?  This marker is set to avoid looking up content again
   * before the first content exits the delay loop.  Since this *not*
   * looking up content again is not externally visible, it is ok to
   * do this optimization to reduce disk accesses (see Mantis bug
   * #407).
   */
  int successful_local_lookup_in_delay_loop;

} IndirectionTableEntry;


/**
 * @brief structure to keep track of which peers send responses
 *  to queries from a certain peer at the moment
 * Linked list of peer ids with number of replies received.
 */
typedef struct RL_ {
  struct RL_ * next;
  PeerIdentity responder;
  unsigned int responseCount;
} ResponseList;

/**
 * Structure for tracking from which peer we got valueable replies for
 * which clients / other peers.
 */
typedef struct RTD_ {

  /**
   * This is a linked list.
   */
  struct RTD_ * next;

  /**
   * For which client does this entry track replies?
   */
  PeerIdentity queryOrigin;

  /**
   * Linked list of peers that responded, with
   * number of responses.
   */
  ResponseList * responseList;

  /**
   * Time at which we received the last reply
   * for this client.  Used to discard old entries
   * eventually.
   */
  TIME_T lastReplyReceived;
} ReplyTrackData;

/**
 * Tracking of just reward data (how much trust a peer
 * can gain for a particular reply).
 */
typedef struct {
  HashCode512 query;
  unsigned int prio;
} RewardEntry;



