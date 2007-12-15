/*
     This file is part of GNUnet.
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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file applications/fs/ecrs/search.c
 * @brief Helper functions for searching.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_fs_lib.h"
#include "gnunet_ecrs_lib.h"
#include "ecrs_core.h"
#include "ecrs.h"

#define DEBUG_SEARCH GNUNET_NO

typedef struct
{

  /**
   * The handle for the query.
   */
  struct GNUNET_FS_SearchHandle *handle;

  /**
   * The keys (for the search).
   */
  GNUNET_HashCode *keys;

  /**
   * When does this query time-out (we may want
   * to refresh it at that point).
   */
  GNUNET_CronTime timeout;

  /**
   * What was the last time we transmitted
   * this query?
   */
  GNUNET_CronTime lastTransmission;

  /**
   * The key (for decryption)
   */
  GNUNET_HashCode decryptKey;

  /**
   * With which priority does the query run?
   */
  unsigned int priority;

  /**
   * What type of query is it?
   */
  unsigned int type;

  /**
   * How many keys are there?
   */
  unsigned int keyCount;

} PendingSearch;

/**
 * Context of the sendQueries cron-job.
 */
typedef struct
{
  /**
   * Time when the cron-job was first started.
   */
  GNUNET_CronTime start;

  /**
   * What is the global timeout?
   */
  GNUNET_CronTime timeout;

  /**
   * Search context
   */
  struct GNUNET_FS_SearchContext *sctx;

  /**
   * queryCount pending searches.
   */
  PendingSearch **queries;

  GNUNET_ECRS_SearchResultProcessor spcb;

  void *spcbClosure;

  struct GNUNET_Mutex *lock;

  struct GNUNET_GE_Context *ectx;

  struct GNUNET_GC_Configuration *cfg;

  int aborted;

  /**
   * Number of queries running at the moment.
   */
  unsigned int queryCount;

} SendQueriesContext;

/**
 * Add a query to the SQC.
 */
static void
addPS (unsigned int type,
       unsigned int keyCount,
       const GNUNET_HashCode * keys,
       const GNUNET_HashCode * dkey, SendQueriesContext * sqc)
{
  PendingSearch *ps;

  ps = GNUNET_malloc (sizeof (PendingSearch));
  ps->timeout = 0;
  ps->lastTransmission = 0;
  ps->priority = 5 + GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 20);
  ps->type = type;
  ps->keyCount = keyCount;
  ps->keys = GNUNET_malloc (sizeof (GNUNET_HashCode) * keyCount);
  memcpy (ps->keys, keys, sizeof (GNUNET_HashCode) * keyCount);
  ps->decryptKey = *dkey;
  ps->handle = NULL;
  GNUNET_mutex_lock (sqc->lock);
  GNUNET_array_grow (sqc->queries, sqc->queryCount, sqc->queryCount + 1);
  sqc->queries[sqc->queryCount - 1] = ps;
  GNUNET_mutex_unlock (sqc->lock);
}

/**
 * Add the query that corresponds to the given URI
 * to the SQC.
 */
static void
addQueryForURI (const struct GNUNET_ECRS_URI *uri, SendQueriesContext * sqc)
{
  struct GNUNET_GE_Context *ectx = sqc->ectx;

  switch (uri->type)
    {
    case chk:
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("CHK URI not allowed for search.\n"));
      break;
    case sks:
      {
        GNUNET_HashCode keys[2];
        GNUNET_HashCode hk;     /* hk = GNUNET_hash(identifier) */

        GNUNET_hash (&uri->data.sks.identifier, sizeof (GNUNET_HashCode),
                     &hk);
        GNUNET_hash_xor (&hk, &uri->data.sks.namespace, &keys[0]);      /* compute routing key r = H(identifier) ^ namespace */
        keys[1] = uri->data.sks.namespace;
        addPS (GNUNET_ECRS_BLOCKTYPE_SIGNED, 2, &keys[0], &uri->data.sks.identifier,    /* identifier = decryption key */
               sqc);
        break;
      }
    case ksk:
      {
        GNUNET_HashCode hc;
        GNUNET_HashCode query;
        struct GNUNET_RSA_PrivateKey *pk;
        GNUNET_RSA_PublicKey pub;
        int i;

#if DEBUG_SEARCH
        GNUNET_GE_LOG (ectx,
                       GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                       "Computing queries (this may take a while).\n");
#endif
        for (i = 0; i < uri->data.ksk.keywordCount; i++)
          {
            GNUNET_hash (uri->data.ksk.keywords[i],
                         strlen (uri->data.ksk.keywords[i]), &hc);
            pk = GNUNET_RSA_create_key_from_hash (&hc);
            GNUNET_RSA_get_public_key (pk, &pub);
            GNUNET_hash (&pub, sizeof (GNUNET_RSA_PublicKey), &query);
            addPS (GNUNET_ECRS_BLOCKTYPE_ANY,   /* GNUNET_ECRS_BLOCKTYPE_KEYWORD, GNUNET_ECRS_BLOCKTYPE_NAMESPACE or GNUNET_ECRS_BLOCKTYPE_KEYWORD_FOR_NAMESPACE ok */
                   1, &query, &hc, sqc);
            GNUNET_RSA_free_key (pk);
          }
#if DEBUG_SEARCH
        GNUNET_GE_LOG (ectx,
                       GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                       "Queries ready.\n");
#endif
        break;
      }
    case loc:
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("LOC URI not allowed for search.\n"));
      break;
    default:
      GNUNET_GE_BREAK (ectx, 0);
      /* unknown URI type */
      break;
    }
}

/**
 * Compute the "current" ID of an updateable SBlock.  Will set the ID
 * of the sblock itself for non-updateable content, the ID of the next
 * identifier for sporadically updated SBlocks and the ID computed from
 * the timing function for periodically updated SBlocks.
 *
 * @param sb the SBlock (must be in plaintext)
 * @param now the time for which the ID should be computed
 * @param c the resulting current ID (set)
 */
static int
computeIdAtTime (const SBlock * sb, GNUNET_Int32Time now, GNUNET_HashCode * c)
{
  GNUNET_Int32Time pos;
  GNUNET_HashCode tmp;
  unsigned int iter;

  if (ntohl (sb->updateInterval) == SBLOCK_UPDATE_SPORADIC)
    {
      memcpy (c, &sb->nextIdentifier, sizeof (GNUNET_HashCode));
      return GNUNET_OK;
    }
  if (ntohl (sb->updateInterval) == SBLOCK_UPDATE_NONE)
    {
      /* H(N-I)^S is the current routing key, so N-I = k */
      GNUNET_hash_difference (&sb->identifierIncrement, &sb->nextIdentifier,
                              c);
      return GNUNET_OK;
    }
  GNUNET_GE_ASSERT (NULL, ntohl (sb->updateInterval) != 0);
  pos = ntohl (sb->creationTime);
  GNUNET_hash_difference (&sb->identifierIncrement, &sb->nextIdentifier, c);

  iter =
    (now - (pos + ntohl (sb->updateInterval))) / ntohl (sb->updateInterval);
  if (iter > 0xFFFF)
    /* too many iterators, signal error! */
    return GNUNET_SYSERR;
  while (pos + ntohl (sb->updateInterval) < now)
    {
      pos += ntohl (sb->updateInterval);
      GNUNET_hash_sum (c, &sb->identifierIncrement, &tmp);
      *c = tmp;
    }
  return GNUNET_OK;
}

/**
 * We found an NBlock.  Decode the meta-data and call the callback of
 * the SQC with the root-URI for the namespace, together with the
 * namespace advertisement.
 */
static int
processNBlock (const NBlock * nb,
               const GNUNET_HashCode * key,
               unsigned int size, SendQueriesContext * sqc)
{
  struct GNUNET_GE_Context *ectx = sqc->ectx;
  GNUNET_ECRS_FileInfo fi;
  struct GNUNET_ECRS_URI uri;
  int ret;

  fi.meta = GNUNET_ECRS_meta_data_deserialize (ectx,
                                               (const char *) &nb[1],
                                               size - sizeof (NBlock));
  if (fi.meta == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);        /* nblock malformed */
      return GNUNET_SYSERR;
    }
  fi.uri = &uri;
  uri.type = sks;
  uri.data.sks.namespace = nb->namespace;
  uri.data.sks.identifier = nb->rootEntry;
  if (sqc->spcb != NULL)
    {
      ret = sqc->spcb (&fi, key, GNUNET_YES, sqc->spcbClosure);
      if (ret == GNUNET_SYSERR)
        sqc->aborted = GNUNET_YES;
    }
  else
    ret = GNUNET_OK;
  GNUNET_ECRS_meta_data_destroy (fi.meta);
  return ret;
}

/**
 * Process replies received in response to our
 * queries.  Verifies, decrypts and passes valid
 * replies to the callback.
 *
 * @return GNUNET_SYSERR if the entry is malformed
 */
static int
receiveReplies (const GNUNET_HashCode * key,
                const GNUNET_DatastoreValue * value, SendQueriesContext * sqc)
{
  struct GNUNET_GE_Context *ectx = sqc->ectx;
  unsigned int type;
  GNUNET_ECRS_FileInfo fi;
  int i;
  unsigned int size;
  PendingSearch *ps;
  int ret;
  GNUNET_HashCode query;

  type = ntohl (value->type);
  size = ntohl (value->size) - sizeof (GNUNET_DatastoreValue);
#if DEBUG_SEARCH
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Search received reply of type %u and size %u.\n", type,
                 size);
#endif
  if (GNUNET_OK !=
      GNUNET_EC_file_block_check_and_get_query (size,
                                                (const DBlock *) &value[1],
                                                GNUNET_YES, &query))
    return GNUNET_SYSERR;
  for (i = 0; i < sqc->queryCount; i++)
    {
      ps = sqc->queries[i];
      if ((0 == memcmp (&query,
                        &ps->keys[0], sizeof (GNUNET_HashCode))) &&
          ((ps->type == type) ||
           (ps->type == GNUNET_ECRS_BLOCKTYPE_ANY)) &&
          (GNUNET_YES == GNUNET_EC_is_block_applicable_for_query (type,
                                                                  size,
                                                                  (const
                                                                   DBlock *)
                                                                  &value[1],
                                                                  &query,
                                                                  ps->
                                                                  keyCount,
                                                                  ps->keys)))
        {
          switch (type)
            {
            case GNUNET_ECRS_BLOCKTYPE_KEYWORD:
              {
                KBlock *kb;
                const char *dstURI;
#if DEBUG_SEARCH
                GNUNET_EncName enc;
#endif
                int j;

                if (size < sizeof (KBlock))
                  return GNUNET_SYSERR;
                kb = GNUNET_malloc (size);
                memcpy (kb, &value[1], size);
#if DEBUG_SEARCH
                IF_GELOG (ectx,
                          GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                          GNUNET_GE_USER, GNUNET_hash_to_enc (&ps->decryptKey,
                                                              &enc));
                GNUNET_GE_LOG (ectx,
                               GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                               GNUNET_GE_USER,
                               "Decrypting KBlock with key %s.\n", &enc);
#endif
                GNUNET_ECRS_decryptInPlace (&ps->decryptKey,
                                            &kb[1], size - sizeof (KBlock));
                j = sizeof (KBlock);
                while ((j < size) && (((const char *) kb)[j] != '\0'))
                  j++;
                if (j == size)
                  {
                    GNUNET_GE_BREAK (ectx, 0);  /* kblock malformed */
                    GNUNET_free (kb);
                    return GNUNET_SYSERR;
                  }
                dstURI = (const char *) &kb[1];
                j++;
                fi.meta = GNUNET_ECRS_meta_data_deserialize (ectx,
                                                             &((const char *)
                                                               kb)[j],
                                                             size - j);
                if (fi.meta == NULL)
                  {
                    GNUNET_GE_BREAK (ectx, 0);  /* kblock malformed */
                    GNUNET_free (kb);
                    return GNUNET_SYSERR;
                  }
                fi.uri = GNUNET_ECRS_string_to_uri (ectx, dstURI);
                if (fi.uri == NULL)
                  {
                    GNUNET_GE_BREAK (ectx, 0);  /* kblock malformed */
                    GNUNET_ECRS_meta_data_destroy (fi.meta);
                    GNUNET_free (kb);
                    return GNUNET_SYSERR;
                  }
                if (sqc->spcb != NULL)
                  {
                    ret = sqc->spcb (&fi,
                                     &ps->decryptKey, GNUNET_NO,
                                     sqc->spcbClosure);
                    if (ret == GNUNET_SYSERR)
                      sqc->aborted = GNUNET_YES;
                  }
                else
                  ret = GNUNET_OK;
                GNUNET_ECRS_uri_destroy (fi.uri);
                GNUNET_ECRS_meta_data_destroy (fi.meta);
                GNUNET_free (kb);
                return ret;
              }
            case GNUNET_ECRS_BLOCKTYPE_NAMESPACE:
              {
                const NBlock *nb;

                if (size < sizeof (NBlock))
                  return GNUNET_SYSERR;
                nb = (const NBlock *) &value[1];
                return processNBlock (nb, NULL, size, sqc);
              }
            case GNUNET_ECRS_BLOCKTYPE_KEYWORD_FOR_NAMESPACE:
              {
                KNBlock *kb;
                int ret;

                if (size < sizeof (KNBlock))
                  return GNUNET_SYSERR;
                kb = GNUNET_malloc (size);
                memcpy (kb, &value[1], size);
                GNUNET_ECRS_decryptInPlace (&ps->decryptKey,
                                            &kb->nblock,
                                            size - sizeof (KBlock) -
                                            sizeof (unsigned int));
                ret =
                  processNBlock (&kb->nblock, &ps->decryptKey,
                                 size - sizeof (KNBlock) + sizeof (NBlock),
                                 sqc);
                GNUNET_free (kb);
                return ret;
              }
            case GNUNET_ECRS_BLOCKTYPE_SIGNED:
              {
                SBlock *sb;
                const char *dstURI;
                int j;
                GNUNET_Int32Time now;
                GNUNET_HashCode updateId;
                URI updateURI;

                if (size < sizeof (SBlock))
                  return GNUNET_SYSERR;
                sb = GNUNET_malloc (size);
                memcpy (sb, &value[1], size);
                GNUNET_ECRS_decryptInPlace (&ps->decryptKey,
                                            &sb->creationTime,
                                            size
                                            - sizeof (unsigned int)
                                            - sizeof (GNUNET_RSA_Signature)
                                            - sizeof (GNUNET_RSA_PublicKey)
                                            - sizeof (GNUNET_HashCode));
                j = 0;
                dstURI = (const char *) &sb[1];
                while ((j < size - sizeof (SBlock)) && (dstURI[j] != '\0'))
                  j++;
                if (j == size - sizeof (SBlock))
                  {
                    GNUNET_GE_BREAK (ectx, 0);  /* sblock malformed */
                    GNUNET_free (sb);
                    return GNUNET_SYSERR;
                  }
                j++;
                /* j == strlen(dstURI) + 1 */
                fi.meta = GNUNET_ECRS_meta_data_deserialize (ectx,
                                                             &dstURI[j],
                                                             size - j -
                                                             sizeof (SBlock));
                if (fi.meta == NULL)
                  {
                    GNUNET_GE_BREAK (ectx, 0);  /* sblock malformed */
                    GNUNET_free (sb);
                    return GNUNET_SYSERR;
                  }
                fi.uri = GNUNET_ECRS_string_to_uri (ectx, dstURI);
                if (fi.uri == NULL)
                  {
                    GNUNET_GE_BREAK (ectx, 0);  /* sblock malformed */
                    GNUNET_ECRS_meta_data_destroy (fi.meta);
                    GNUNET_free (sb);
                    return GNUNET_SYSERR;
                  }
                if (sqc->spcb != NULL)
                  {
                    ret = sqc->spcb (&fi, NULL, GNUNET_NO, sqc->spcbClosure);
                    if (ret == GNUNET_SYSERR)
                      sqc->aborted = GNUNET_YES;
                  }
                else
                  ret = GNUNET_OK;
                GNUNET_ECRS_uri_destroy (fi.uri);
                GNUNET_ECRS_meta_data_destroy (fi.meta);

                /* compute current/NEXT URI (if updateable SBlock) and issue
                   respective query automatically! */
                GNUNET_get_time_int32 (&now);
                if (GNUNET_OK != computeIdAtTime (sb, now, &updateId))
                  {
                    GNUNET_free (sb);
                    return GNUNET_SYSERR;
                  }
                if (0 ==
                    memcmp (&updateId, &ps->decryptKey,
                            sizeof (GNUNET_HashCode)))
                  {
                    GNUNET_free (sb);
                    return ret; /* have latest version */
                  }
                if (ps->keyCount != 2)
                  {
                    GNUNET_GE_BREAK (ectx, 0);
                    GNUNET_free (sb);
                    return GNUNET_SYSERR;
                  }

                updateURI.type = sks;
                updateURI.data.sks.namespace = ps->keys[1];
                updateURI.data.sks.identifier = updateId;
                addQueryForURI (&updateURI, sqc);
                GNUNET_free (sb);
                return ret;
              }
            default:
              GNUNET_GE_BREAK (ectx, 0);
              break;
            }                   /* end switch */
        }                       /* for all matches */
    }                           /* for all pending queries */
  return GNUNET_OK;
}


/**
 * Search for content.
 *
 * @param timeout how long to wait (relative)
 * @param uri specifies the search parameters
 * @param uri set to the URI of the uploaded file
 */
int
GNUNET_ECRS_search (struct GNUNET_GE_Context *ectx,
                    struct GNUNET_GC_Configuration *cfg,
                    const struct GNUNET_ECRS_URI *uri,
                    unsigned int anonymityLevel,
                    GNUNET_CronTime timeout,
                    GNUNET_ECRS_SearchResultProcessor spcb,
                    void *spcbClosure, GNUNET_ECRS_TestTerminate tt,
                    void *ttClosure)
{
  SendQueriesContext ctx;
  PendingSearch *ps;
  int i;
  GNUNET_CronTime now;
  GNUNET_CronTime remTime;
  GNUNET_CronTime new_ttl;
  unsigned int new_priority;

  ctx.start = GNUNET_get_time ();
  now = GNUNET_get_time ();
  timeout += now;
  ctx.ectx = ectx;
  ctx.cfg = cfg;
  ctx.timeout = timeout;
  ctx.queryCount = 0;
  ctx.queries = NULL;
  ctx.spcb = spcb;
  ctx.spcbClosure = spcbClosure;
  ctx.aborted = GNUNET_NO;
  ctx.lock = GNUNET_mutex_create (GNUNET_YES);
  ctx.sctx = GNUNET_FS_create_search_context (ectx, cfg, ctx.lock);
  addQueryForURI (uri, &ctx);
  while (((NULL == tt) ||
          (GNUNET_OK == tt (ttClosure))) &&
         (GNUNET_NO == GNUNET_shutdown_test ()) &&
         (timeout > now) && (ctx.aborted == GNUNET_NO))
    {
      remTime = timeout - now;

      GNUNET_mutex_lock (ctx.lock);
      for (i = 0; i < ctx.queryCount; i++)
        {
          ps = ctx.queries[i];
          if ((now < ps->timeout) && (ps->timeout != 0))
            continue;
          if (ps->handle != NULL)
            GNUNET_FS_stop_search (ctx.sctx, ps->handle);
          /* increase ttl/priority */
          new_ttl = ps->timeout - ps->lastTransmission;
          if (new_ttl < 4 * 5 * GNUNET_CRON_SECONDS)
            new_ttl =
              4 * 5 * GNUNET_CRON_SECONDS +
              GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                                 5 * GNUNET_CRON_SECONDS);
          new_ttl =
            new_ttl + GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                                         5 * GNUNET_CRON_SECONDS +
                                         2 * new_ttl);
          if (new_ttl > 0xFFFFFF)
            new_ttl = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 0xFFFFFF); /* if we get to large, reduce! */
          if (remTime < new_ttl)
            new_ttl = remTime;
          ps->timeout = new_ttl + now;
          new_priority = ps->priority;
          new_priority =
            new_priority + GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                                              4 + 2 * new_priority);
          if (new_priority > 0xFFFFFF)
            new_priority = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 0xFFFFFF);    /* if we get to large, reduce! */
          ps->priority = new_priority;
          ps->lastTransmission = now;
#if DEBUG_SEARCH
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "ECRS initiating FS search with timeout %llus and priority %u.\n",
                         (ps->timeout - now) / GNUNET_CRON_SECONDS,
                         ps->priority);
#endif
          ps->handle
            = GNUNET_FS_start_search (ctx.sctx,
                                      NULL,
                                      ps->type,
                                      ps->keyCount,
                                      ps->keys,
                                      anonymityLevel,
                                      ps->priority,
                                      ps->timeout,
                                      (GNUNET_DatastoreValueIterator) &
                                      receiveReplies, &ctx);
        }
      GNUNET_mutex_unlock (ctx.lock);
      if (((NULL != tt) &&
           (GNUNET_OK != tt (ttClosure))) || (timeout <= now)
          || (ctx.aborted != GNUNET_NO))
        break;
      GNUNET_thread_sleep (100 * GNUNET_CRON_MILLISECONDS);
      now = GNUNET_get_time ();
    }
  for (i = 0; i < ctx.queryCount; i++)
    {
      if (ctx.queries[i]->handle != NULL)
        GNUNET_FS_stop_search (ctx.sctx, ctx.queries[i]->handle);
      GNUNET_free (ctx.queries[i]->keys);
      GNUNET_free (ctx.queries[i]);
    }
  GNUNET_array_grow (ctx.queries, ctx.queryCount, 0);
  GNUNET_FS_destroy_search_context (ctx.sctx);
  GNUNET_mutex_destroy (ctx.lock);
  return GNUNET_OK;
}


/* end of search.c */
