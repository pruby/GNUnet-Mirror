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

/**
 * This struct is followed by keyCount keys of
 * type "GNUNET_HashCode".
 */
struct PendingSearch
{
  struct PendingSearch *next;

  struct GNUNET_ECRS_SearchContext *context;

  /**
   * The key (for decryption)
   */
  GNUNET_HashCode decryptKey;

  /**
   * What type of query is it?
   */
  unsigned int type;

  /**
   * How many keys are there?
   */
  unsigned int keyCount;

};

/**
 * Context for search operation.
 */
struct GNUNET_ECRS_SearchContext
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
   * Active searches.
   */
  struct PendingSearch *queries;

  GNUNET_ECRS_SearchResultProcessor spcb;

  void *spcbClosure;

  struct GNUNET_Mutex *lock;

  struct GNUNET_GE_Context *ectx;

  struct GNUNET_GC_Configuration *cfg;

  int aborted;

  unsigned int anonymityLevel;

};

static int
receive_response_callback (const GNUNET_HashCode * key,
                           const GNUNET_DatastoreValue * value, void *cls);

/**
 * Add a query to the SQC.
 */
static void
add_search (unsigned int type,
            unsigned int keyCount,
            const GNUNET_HashCode * keys,
            const GNUNET_HashCode * dkey,
            struct GNUNET_ECRS_SearchContext *sqc)
{
  struct PendingSearch *ps;

  ps =
    GNUNET_malloc (sizeof (struct PendingSearch) +
                   sizeof (GNUNET_HashCode) * keyCount);
  ps->type = type;
  ps->keyCount = keyCount;
  memcpy (&ps[1], keys, sizeof (GNUNET_HashCode) * keyCount);
  ps->decryptKey = *dkey;
  ps->context = sqc;
  GNUNET_mutex_lock (sqc->lock);
  ps->next = sqc->queries;
  sqc->queries = ps;
  GNUNET_mutex_unlock (sqc->lock);
  GNUNET_FS_start_search (sqc->sctx,
                          NULL,
                          type,
                          keyCount,
                          keys,
                          sqc->anonymityLevel,
                          (GNUNET_DatastoreValueIterator) &
                          receive_response_callback, ps);
}

/**
 * Add the query that corresponds to the given URI
 * to the SQC.
 */
static void
add_search_for_uri (const struct GNUNET_ECRS_URI *uri,
                    struct GNUNET_ECRS_SearchContext *sqc)
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
        add_search (GNUNET_ECRS_BLOCKTYPE_SIGNED, 2, &keys[0], &uri->data.sks.identifier,       /* identifier = decryption key */
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
            add_search (GNUNET_ECRS_BLOCKTYPE_ANY,      /* GNUNET_ECRS_BLOCKTYPE_KEYWORD, GNUNET_ECRS_BLOCKTYPE_NAMESPACE or GNUNET_ECRS_BLOCKTYPE_KEYWORD_FOR_NAMESPACE ok */
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
compute_id_at_time (const SBlock * sb, GNUNET_Int32Time now,
                    GNUNET_HashCode * c)
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
process_nblock_result (const NBlock * nb,
                       const GNUNET_HashCode * key,
                       unsigned int size,
                       struct GNUNET_ECRS_SearchContext *sqc)
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
receive_response_callback (const GNUNET_HashCode * key,
                           const GNUNET_DatastoreValue * value, void *cls)
{
  struct PendingSearch *ps = cls;
  struct GNUNET_ECRS_SearchContext *sqc = ps->context;
  struct GNUNET_GE_Context *ectx = sqc->ectx;
  unsigned int type;
  GNUNET_ECRS_FileInfo fi;
  unsigned int size;
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
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  if (!((0 == memcmp (&query,
                      (GNUNET_HashCode *) & ps[1], sizeof (GNUNET_HashCode)))
        && ((ps->type == type) || (ps->type == GNUNET_ECRS_BLOCKTYPE_ANY))
        && (GNUNET_YES ==
            GNUNET_EC_is_block_applicable_for_query (type, size,
                                                     (const DBlock *)
                                                     &value[1], &query,
                                                     ps->keyCount,
                                                     (GNUNET_HashCode *) &
                                                     ps[1]))))
    {
      return GNUNET_OK;         /* not a match */
    }

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
          {
            GNUNET_GE_BREAK (NULL, 0);
            return GNUNET_SYSERR;
          }
        kb = GNUNET_malloc (size);
        memcpy (kb, &value[1], size);
#if DEBUG_SEARCH
        IF_GELOG (ectx,
                  GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                  GNUNET_GE_USER, GNUNET_hash_to_enc (&ps->decryptKey, &enc));
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
                                                       kb)[j], size - j);
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
                             &ps->decryptKey, GNUNET_NO, sqc->spcbClosure);
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
        return process_nblock_result (nb, NULL, size, sqc);
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
          process_nblock_result (&kb->nblock, &ps->decryptKey,
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
        if (GNUNET_OK != compute_id_at_time (sb, now, &updateId))
          {
            GNUNET_free (sb);
            return GNUNET_SYSERR;
          }
        if (0 ==
            memcmp (&updateId, &ps->decryptKey, sizeof (GNUNET_HashCode)))
          {
            GNUNET_free (sb);
            return ret;         /* have latest version */
          }
        if (ps->keyCount != 2)
          {
            GNUNET_GE_BREAK (ectx, 0);
            GNUNET_free (sb);
            return GNUNET_SYSERR;
          }

        updateURI.type = sks;
        updateURI.data.sks.namespace = ((GNUNET_HashCode *) & ps[1])[1];
        updateURI.data.sks.identifier = updateId;
        add_search_for_uri (&updateURI, sqc);
        GNUNET_free (sb);
        return ret;
      }
    default:
      GNUNET_GE_BREAK (ectx, 0);
      break;
    }                           /* end switch */
  return GNUNET_OK;
}

/**
 * Start search for content.
 *
 * @param uri specifies the search parameters
 * @param uri set to the URI of the uploaded file
 */
struct GNUNET_ECRS_SearchContext *
GNUNET_ECRS_search_start (struct GNUNET_GE_Context *ectx,
                          struct GNUNET_GC_Configuration *cfg,
                          const struct GNUNET_ECRS_URI *uri,
                          unsigned int anonymityLevel,
                          GNUNET_ECRS_SearchResultProcessor spcb,
                          void *spcbClosure)
{
  struct GNUNET_ECRS_SearchContext *ctx;

  ctx = GNUNET_malloc (sizeof (struct GNUNET_ECRS_SearchContext));
  ctx->start = GNUNET_get_time ();
  ctx->anonymityLevel = anonymityLevel;
  ctx->ectx = ectx;
  ctx->cfg = cfg;
  ctx->queries = NULL;
  ctx->spcb = spcb;
  ctx->spcbClosure = spcbClosure;
  ctx->aborted = GNUNET_NO;
  ctx->lock = GNUNET_mutex_create (GNUNET_YES);
  ctx->sctx = GNUNET_FS_create_search_context (ectx, cfg, ctx->lock);
  add_search_for_uri (uri, ctx);
  return ctx;
}

/**
 * Stop search for content.
 *
 * @param uri specifies the search parameters
 * @param uri set to the URI of the uploaded file
 */
void
GNUNET_ECRS_search_stop (struct GNUNET_ECRS_SearchContext *ctx)
{
  struct PendingSearch *pos;
  GNUNET_FS_destroy_search_context (ctx->sctx);
  while (ctx->queries != NULL)
    {
      pos = ctx->queries;
      ctx->queries = pos->next;
      GNUNET_free (pos);
    }
  GNUNET_mutex_destroy (ctx->lock);
  GNUNET_free (ctx);
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
                    GNUNET_ECRS_SearchResultProcessor spcb,
                    void *spcbClosure, GNUNET_ECRS_TestTerminate tt,
                    void *ttClosure)
{
  struct GNUNET_ECRS_SearchContext *ctx;

  ctx =
    GNUNET_ECRS_search_start (ectx, cfg, uri, anonymityLevel, spcb,
                              spcbClosure);
  while (((NULL == tt) || (GNUNET_OK == tt (ttClosure)))
         && (GNUNET_NO == GNUNET_shutdown_test ())
         && (ctx->aborted == GNUNET_NO))
    GNUNET_thread_sleep (100 * GNUNET_CRON_MILLISECONDS);
  GNUNET_ECRS_search_stop (ctx);
  return GNUNET_OK;
}


/* end of search.c */
