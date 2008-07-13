/*
     This file is part of GNUnet
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/module/fs.h
 * @brief FS Client-Server and P2P message formats
 * @author Christian Grothoff
 *
 * Applications should use the FSLIB, ECRS or FSUI libraries.
 * Only code in src/applications/fs/ should refer to this file!
 */
#ifndef FS_H
#define FS_H

#include "gnunet_util.h"

/**
 * Client to server: search for content.  Variable
 * size message, there is at least one query, but
 * there maybe more than one (the semantics depend
 * on the type).
 */
typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * Should be zero.
   */
  int reserved;

  /**
   * Type of the content that we're looking for.
   * 0 for any.
   */
  unsigned int type;

  /**
   * What are the anonymity requirements for this content?
   * Use 0 if anonymity is not required (enables direct
   * sharing / DHT routing).
   */
  unsigned int anonymity_level;

  /**
   * Identity of the peer that is known to have the
   * response.  Set to all-zeros if target is not
   * known.
   */
  GNUNET_PeerIdentity target;

  /**
   * What are the queries?
   */
  GNUNET_HashCode query[1];

} CS_fs_request_search_MESSAGE;

/**
 * Server to client: content (in response to a CS_fs_request_search_MESSAGE).  The
 * header is followed by the variable size data of a GNUNET_EC_DBlock (as
 * defined in ecrs_core.h).
 */
typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * Anonymity level for the content, maybe
   * 0 if not known.
   */
  unsigned int anonymity_level;

  /**
   * Expiration time of the response (relative to now).
   */
  GNUNET_CronTime expiration_time;

} CS_fs_reply_content_MESSAGE;


/**
 * Client to server: insert content.
 * This struct is followed by a variable
 * number of bytes of content (a GNUNET_EC_DBlock).
 */
typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * Reserved (should be zero).  For alignment.
   */
  int reserved;

  /**
   * Priority for the on-demand encoded entry.
   */
  unsigned int priority;

  /**
   * What are the anonymity requirements for this content?
   * Use 0 if anonymity is not required (enables direct
   * sharing / DHT routing).
   */
  unsigned int anonymity_level;

  /**
   * At what time does the entry expire?
   */
  GNUNET_CronTime expiration;

} CS_fs_request_insert_MESSAGE;

/**
 * Client to server: initialize to index content
 * (for on-demand encoding).  This struct is followed
 * by the filename to index.
 */
typedef struct
{
  GNUNET_MessageHeader header;

  unsigned int reserved;

  /**
   * What is the GNUNET_hash of the file that contains
   * this block?
   */
  GNUNET_HashCode fileId;

} CS_fs_request_init_index_MESSAGE;

/**
 * Client to server: index content (for on-demand
 * encoding).  This struct is followed by a variable
 * number of bytes of content.
 */
typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * Reserved (should be zero).  For alignment.
   */
  int reserved;

  /**
   * Priority for the on-demand encoded entry.
   */
  unsigned int priority;

  /**
   * What are the anonymity requirements for this content?
   * Use 0 if anonymity is not required (enables direct
   * sharing / DHT routing).
   */
  unsigned int anonymity_level;

  /**
   * At what time does the entry expire?
   */
  GNUNET_CronTime expiration;

  /**
   * At what offset in the plaintext file is
   * this content stored?
   */
  unsigned long long fileOffset;

  /**
   * What is the GNUNET_hash of the file that contains
   * this block?  Used by gnunetd for the name
   * of the file in the on-demand datastore.
   */
  GNUNET_HashCode fileId;

} CS_fs_request_index_MESSAGE;

/**
 * Client to server: delete content.  This struct is followed by
 * the GNUNET_EC_DBlock (of variable size) of the content that is to be deleted.
 */
typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * Reserved (should be zero).  For alignment.
   */
  int reserved;

} CS_fs_request_delete_MESSAGE;

/**
 * Client to server: unindex file.
 */
typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * Size of each block of the file.
   */
  unsigned int blocksize;

  /**
   * What is the GNUNET_hash of the file that should be
   * unindexed?
   */
  GNUNET_HashCode fileId;

} CS_fs_request_unindex_MESSAGE;

/**
 * Client to server: test if file is indexed
 */
typedef struct
{
  GNUNET_MessageHeader header;

  unsigned int reserved;

  /**
   * What is the GNUNET_hash of the file that should be
   * unindexed?
   */
  GNUNET_HashCode fileId;

} CS_fs_request_test_index_MESSAGE;


/**
 * Request for content. The number of queries can
 * be determined from the header.  This struct
 * maybe followed by a bloom filter (size determined
 * by the header) which includes hashes of responses
 * that should NOT be returned.  If there is no
 * bloom filter, the filter_mutator
 * should be zero.
 */
typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * Type of the query (block type).
   */
  unsigned int type;

  /**
   * How important is this request (network byte order)
   */
  unsigned int priority;

  /**
   * Relative time to live in GNUNET_CRON_MILLISECONDS (network byte order)
   */
  int ttl;

  /**
   * The content hash should be mutated using this value
   * before checking against the bloomfilter (used to
   * get many different filters for the same hash codes).
   */
  int filter_mutator;

  /**
   * How many queries do we have (should be
   * greater than zero).
   */
  unsigned int number_of_queries;

  /**
   * To whom to return results?
   */
  GNUNET_PeerIdentity returnTo;

  /**
   * Hashcodes of the file(s) we're looking for.
   * Details depend on the query type.
   */
  GNUNET_HashCode queries[1];

} P2P_gap_query_MESSAGE;

/**
 * Return message for search result.  This struct
 * is always followed by a GNUNET_EC_DBlock (see ecrs_core.h)
 * which contains the GNUNET_ECRS_BLOCKTYPE followed
 * by the actual (encrypted) data.
 */
typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * Always zero (for now).
   */
  unsigned int reserved;        /* for 64-bit alignment */

  /**
   * When does this result expire?  The given time
   * is relative (and in big-endian).  
   */
  unsigned long long expiration;

} P2P_gap_reply_MESSAGE;


/* ***************** policy constants **************** */

/* The constants here are used all over FS.  The
   primary location where the constant is used
   gives it its prefix */

/**
 * Bandwidth value of an (effectively) 0-priority query.
 */
#define GNUNET_GAP_QUERY_BANDWIDTH_VALUE 0.001

/**
 * Bandwidth value of a 0-priority content (must be
 * fairly high compared to query since content is
 * typically significantly larger -- and more valueable
 * since it can take many queries to get one piece of
 * content).
 */
#define GNUNET_GAP_CONTENT_BANDWIDTH_VALUE 0.8

/**
 * By which amount do we decrement the TTL for simple forwarding /
 * indirection of the query; in milli-seconds.  Set somewhat in
 * accordance to your network latency (above the time it'll take you
 * to send a packet and get a reply).
 */
#define GNUNET_GAP_TTL_DECREMENT (5 * GNUNET_CRON_SECONDS)

/**
 * Until which load do we consider the peer idle and do not
 * charge at all? (should be larger than GNUNET_IDLE_LOAD_THRESHOLD used
 * by the rest of the code)!
 */
#define GNUNET_GAP_IDLE_LOAD_THRESHOLD ((100 + GNUNET_IDLE_LOAD_THRESHOLD) / 2)

/**
 * How many bits should we have per entry in the
 * bloomfilter?
 */
#define GNUNET_GAP_BLOOMFILTER_K 16

/**
 * Minimum size of the GAP routing table.
 */
#define GNUNET_GAP_MIN_INDIRECTION_TABLE_SIZE 4


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
#define GNUNET_GAP_BASE_REPLY_PRIORITY 4092

/**
 * What is the maximum time that any peer
 * should delay forwarding a response (when
 * waiting for bandwidth).
 */
#define GNUNET_GAP_MAX_GAP_DELAY (60 * GNUNET_CRON_SECONDS)


/**
 * How long should DHT requests live?
 */
#define GNUNET_GAP_MAX_DHT_DELAY (60 * GNUNET_CRON_SECONDS)


/**
 * What is the maximum expiration time for migrated content?
 *
 * This is a non-trivial issue.  If we have a ceiling for migration
 * time, it would violate anonymity if we send out content with an
 * expiration time above that ceiling (since it would expose the
 * content to originate from this peer).  But we want to store a
 * higher expiration time for our content in the DB.
 *
 * A first idea would be to pick a random time smaller than the limit
 * for outgoing content; that does not _quite_ work since that could
 * also expose us as the originator: only for our own content the
 * expiration time would randomly go up and down.
 *
 * The current best solution is to first bound the expiration time by
 * this ceiling (for inbound and outbound ETs, not for the database
 * entries locally) using modulo (to, in practice, get a constant
 * bound for the local content just like for the migrated content).
 * Then that number is randomized for _all_ outgoing content.  This
 * way, the time left changes for all entries, but statistically
 * always decreases on average as time progresses (also for all
 * entries).
 *
 * Now, for local content eventually modulo will rebound to the MAX
 * (whereas for migrated content it will hit 0 and disappear).  But
 * that is GNUNET_OK: the adversary cannot distinguish the modulo wraparound
 * from content migration (refresh with higher lifetime) which could
 * plausibly happen from the original node (and in fact would happen
 * around the same time!).  This design also achieves the design goal
 * that if the original node disappears, the migrated content will
 * eventually time-out (which is good since we don't want dangling
 * search results to stay around).
 *
 * However, this does NOT mean that migrated content cannot live
 * longer than 1 month -- remember, GNUnet peers discard expired
 * content _if they run out of space_.  So it is perfectly plausible
 * that content stays around longer.  Finally, clients (UI) may want
 * to filter / rank / display search results with their current
 * expiration to give the user some indication about availability.
 *
 */
#define GNUNET_GAP_MAX_MIGRATION_EXP (1L * GNUNET_CRON_MONTHS)

/**
 * Same as MIGRATION_EXP except for KSK blocks.
 */
#define GNUNET_GAP_MAX_MIGRATION_EXP_KSK (6L * GNUNET_CRON_HOURS)

/**
 * Estimated size of most blocks transported with
 * the GAP protocol.  32k DBlocks are the norm.
 */
#define GNUNET_GAP_ESTIMATED_DATA_SIZE (32 * 1024)

/**
 * If, after finding local results, we abort a GET
 * iteration, we increment "have_more" by this value.
 */
#define GNUNET_GAP_HAVE_MORE_INCREMENT 16

/**
 * What is the maximum number of local results
 * that we are willing to return synchronously?
 */
#define GNUNET_GAP_MAX_SYNC_PROCESSED 8

/**
 * What is the maximum number of local results
 * that we are willing to return asynchronously?
 */
#define GNUNET_GAP_MAX_ASYNC_PROCESSED 32


/**
 * Pick a multiple of 2 here to achive 8-byte alignment!
 * We also probably want DBlocks to have (roughly) the
 * same size as IBlocks.  With SHA-512, the optimal
 * value is 32768 byte / 128 byte = 256
 * (128 byte = 2 * 512 bits).  DO NOT CHANGE!
 */
#define GNUNET_ECRS_CHK_PER_INODE 256

/**
 * Size of a DBLOCK.  DO NOT CHANGE!
 */
#define GNUNET_ECRS_DBLOCK_SIZE (32 * 1024)

/**
 * You cannot change this one (directly).  Ideally
 * CHK_PER_INODE is chosen such that
 * IBLOCK_SIZE == DBLOCK_SIZE.
 */
#define GNUNET_ECRS_IBLOCK_SIZE (GNUNET_ECRS_CHK_PER_INODE * sizeof(GNUNET_EC_ContentHashKey))


#endif
