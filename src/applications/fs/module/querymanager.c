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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file applications/fs/module/querymanager.c
 * @brief forwarding of queries
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_stats_service.h"
#include "gnunet_protocols.h"
#include "gnunet_core.h"
#include "fs.h"
#include "querymanager.h"


#define DEBUG_QUERYMANAGER GNUNET_NO

typedef struct
{
  GNUNET_HashCode query;
  unsigned int type;
  struct GNUNET_ClientHandle *client;
} TrackRecord;


/**
 * Stats service.
 */
static GNUNET_Stats_ServiceAPI *stats;

static int stat_queries_tracked;

static int stat_replies_transmitted;

/**
 * Array of the queries we are currently sending out.
 */
static TrackRecord **trackers;

static unsigned int trackerCount;

static unsigned int trackerSize;

/**
 * Mutex for all query manager structures.
 */
static struct GNUNET_Mutex *queryManagerLock;

static GNUNET_CoreAPIForPlugins *coreAPI;

static struct GNUNET_GE_Context *ectx;

static void
removeEntry (unsigned int off)
{
  GNUNET_GE_ASSERT (ectx, off < trackerCount);
  GNUNET_free (trackers[off]);
  if (stats != NULL)
    stats->change (stat_queries_tracked, -1);
  trackers[off] = trackers[--trackerCount];
  trackers[trackerCount] = NULL;
  if ((trackerSize > 64) && (trackerSize > 2 * trackerCount))
    GNUNET_array_grow (trackers, trackerSize, trackerSize / 2);
}

static void
ceh (struct GNUNET_ClientHandle *client)
{
  int i;
  GNUNET_mutex_lock (queryManagerLock);
  for (i = trackerCount - 1; i >= 0; i--)
    if (trackers[i]->client == client)
      removeEntry (i);
  GNUNET_mutex_unlock (queryManagerLock);
}

/**
 * Keep track of a query.  If a matching response
 * shows up, transmit the response to the client.
 *
 * @param msg the query
 * @param client where did the query come from?
 */
void
trackQuery (const GNUNET_HashCode * query,
            unsigned int type, struct GNUNET_ClientHandle *client)
{
  GNUNET_GE_ASSERT (ectx, client != NULL);
  GNUNET_mutex_lock (queryManagerLock);
  if (trackerSize == trackerCount)
    GNUNET_array_grow (trackers, trackerSize, trackerSize * 2);
  trackers[trackerCount] = GNUNET_malloc (sizeof (TrackRecord));
  trackers[trackerCount]->query = *query;
  trackers[trackerCount]->type = type;
  trackers[trackerCount]->client = client;
  trackerCount++;
  if (stats != NULL)
    stats->change (stat_queries_tracked, 1);
  GNUNET_mutex_unlock (queryManagerLock);
}

/**
 * Stop keeping track of a query.
 *
 * @param msg the query
 * @param client where did the query come from?
 */
void
untrackQuery (const GNUNET_HashCode * query,
              struct GNUNET_ClientHandle *client)
{
  int i;

  GNUNET_mutex_lock (queryManagerLock);
  for (i = trackerCount - 1; i >= 0; i--)
    if ((trackers[i]->client == client) &&
        (0 == memcmp (&trackers[i]->query, query, sizeof (GNUNET_HashCode))))
      {
        removeEntry (i);
        GNUNET_mutex_unlock (queryManagerLock);
        return;
      }
  GNUNET_mutex_unlock (queryManagerLock);
}

/**
 * We received a reply.
 * Forward to client (if appropriate).
 *
 * @param value the response
 */
void
processResponse (const GNUNET_HashCode * key,
                 const GNUNET_DatastoreValue * value)
{
  int i;
  CS_fs_reply_content_MESSAGE *rc;
  unsigned int matchCount;
#if DEBUG_QUERYMANAGER
  GNUNET_EncName enc;
#endif

  GNUNET_GE_ASSERT (ectx,
                    ntohl (value->size) > sizeof (GNUNET_DatastoreValue));
  if ((GNUNET_ntohll (value->expirationTime) < GNUNET_get_time ())
      && (ntohl (value->type) != GNUNET_ECRS_BLOCKTYPE_DATA))
    return;                     /* ignore expired, non-data responses! */

  matchCount = 0;
#if DEBUG_QUERYMANAGER
  IF_GELOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (key, &enc));
#endif
  GNUNET_mutex_lock (queryManagerLock);
  for (i = trackerCount - 1; i >= 0; i--)
    {
      if ((0 == memcmp (&trackers[i]->query,
                        key, sizeof (GNUNET_HashCode))) &&
          ((trackers[i]->type == GNUNET_ECRS_BLOCKTYPE_ANY) ||
           (trackers[i]->type == ntohl (value->type))))
        {
          matchCount++;
          rc = GNUNET_malloc (sizeof (CS_fs_reply_content_MESSAGE) +
                              ntohl (value->size) -
                              sizeof (GNUNET_DatastoreValue));
          rc->header.size =
            htons (sizeof (CS_fs_reply_content_MESSAGE) +
                   ntohl (value->size) - sizeof (GNUNET_DatastoreValue));
          rc->header.type = htons (GNUNET_CS_PROTO_GAP_RESULT);
          rc->anonymityLevel = value->anonymityLevel;
          rc->expirationTime = value->expirationTime;
          memcpy (&rc[1],
                  &value[1],
                  ntohl (value->size) - sizeof (GNUNET_DatastoreValue));
#if DEBUG_QUERYMANAGER
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "Sending reply for `%s' to client waiting in slot %u.\n",
                         &enc, i);
#endif
          if (stats != NULL)
            stats->change (stat_replies_transmitted, 1);
          coreAPI->cs_send_to_client (trackers[i]->client,
                                      &rc->header, GNUNET_NO);
          GNUNET_free (rc);
        }
    }
#if DEBUG_QUERYMANAGER && 0
  if (matchCount == 0)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Reply `%s' did not match any request.\n", &enc);
    }
#endif
  GNUNET_mutex_unlock (queryManagerLock);
}

/**
 * Initialize the query management.
 */
int
initQueryManager (GNUNET_CoreAPIForPlugins * capi)
{
  coreAPI = capi;
  ectx = capi->ectx;
  capi->cs_exit_handler_register (&ceh);
  GNUNET_array_grow (trackers, trackerSize, 64);
  queryManagerLock = GNUNET_mutex_create (GNUNET_NO);
  stats = capi->request_service ("stats");
  if (stats != NULL)
    {
      stat_queries_tracked
        =
        stats->
        create (gettext_noop ("# FS currently tracked queries from clients"));
      stat_replies_transmitted =
        stats->create (gettext_noop ("# FS replies passed to clients"));
    }
  return GNUNET_OK;
}

void
doneQueryManager ()
{
  int i;

  for (i = trackerCount - 1; i >= 0; i--)
    GNUNET_free (trackers[i]);

  GNUNET_array_grow (trackers, trackerSize, 0);
  trackerCount = 0;
  if (stats != NULL)
    {
      stats->set (stat_queries_tracked, 0);
      coreAPI->release_service (stats);
      stats = NULL;
    }

  coreAPI->cs_exit_handler_unregister (&ceh);
  GNUNET_mutex_destroy (queryManagerLock);
  queryManagerLock = NULL;
  coreAPI = NULL;
  ectx = NULL;
}

/* end of querymanager.c */
