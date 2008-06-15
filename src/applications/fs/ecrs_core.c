/*
     This file is part of GNUnet
     (C) 2001, 2002, 2003, 2004, 2005, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/module/ecrs_core.c
 * @brief support for ECRS encoding of files
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "ecrs_core.h"

/**
 * Perform on-demand content encoding.
 *
 * @param data the data to encode
 * @param len the length of the data
 * @param query the query that was used to query
 *  for the content (verified that it matches
 *  data)
 * @param value the encoded data (set);
 *        the anonymity_level is to be set to 0
 *        (caller should have checked before calling
 *        this method).
 * @return GNUNET_OK on success, GNUNET_SYSERR if data does not
 *  match the query
 */
int
GNUNET_EC_file_block_encode (const GNUNET_EC_DBlock * data,
                             unsigned int len,
                             const GNUNET_HashCode * query,
                             GNUNET_DatastoreValue ** value)
{
  GNUNET_HashCode hc;
  GNUNET_AES_SessionKey skey;
  GNUNET_AES_InitializationVector iv;   /* initial value */
  GNUNET_DatastoreValue *val;
  GNUNET_EC_DBlock *db;

  GNUNET_GE_ASSERT (NULL, len >= sizeof (GNUNET_EC_DBlock));
  GNUNET_GE_ASSERT (NULL, (data != NULL) && (query != NULL));
  GNUNET_hash (&data[1], len - sizeof (GNUNET_EC_DBlock), &hc);
  GNUNET_hash_to_AES_key (&hc, &skey, &iv);
  val = GNUNET_malloc (sizeof (GNUNET_DatastoreValue) + len);
  val->size = htonl (sizeof (GNUNET_DatastoreValue) + len);
  val->type = htonl (GNUNET_ECRS_BLOCKTYPE_DATA);
  val->priority = htonl (0);
  val->anonymity_level = htonl (0);
  val->expiration_time = GNUNET_htonll (0);
  db = (GNUNET_EC_DBlock *) & val[1];
  db->type = htonl (GNUNET_ECRS_BLOCKTYPE_DATA);
  GNUNET_GE_ASSERT (NULL,
                    len - sizeof (GNUNET_EC_DBlock) < GNUNET_MAX_BUFFER_SIZE);
  GNUNET_GE_ASSERT (NULL,
                    len - sizeof (GNUNET_EC_DBlock) ==
                    GNUNET_AES_encrypt (&data[1],
                                        len - sizeof (GNUNET_EC_DBlock),
                                        &skey, &iv, &db[1]));
  GNUNET_hash (&db[1], len - sizeof (GNUNET_EC_DBlock), &hc);
  if (0 != memcmp (query, &hc, sizeof (GNUNET_HashCode)))
    {
      GNUNET_free (val);
      *value = NULL;
      return GNUNET_SYSERR;
    }
  *value = val;
  return GNUNET_OK;
}

/**
 * Get the key that will be used to decrypt
 * a certain block of data.
 */
void
GNUNET_EC_file_block_get_key (const GNUNET_EC_DBlock * data, unsigned int len,
                              GNUNET_HashCode * key)
{
  GNUNET_GE_ASSERT (NULL, len >= sizeof (GNUNET_EC_DBlock));
  GNUNET_hash (&data[1], len - sizeof (GNUNET_EC_DBlock), key);
}

/**
 * Get the query that will be used to query for
 * a certain block of data.
 *
 * @param db the block in plaintext
 */
void
GNUNET_EC_file_block_get_query (const GNUNET_EC_DBlock * db, unsigned int len,
                                GNUNET_HashCode * query)
{
  char *tmp;
  const char *data;
  GNUNET_HashCode hc;
  GNUNET_AES_SessionKey skey;
  GNUNET_AES_InitializationVector iv;

  GNUNET_GE_ASSERT (NULL, len >= sizeof (GNUNET_EC_DBlock));
  data = (const char *) &db[1];
  len -= sizeof (GNUNET_EC_DBlock);
  GNUNET_GE_ASSERT (NULL, len < GNUNET_MAX_BUFFER_SIZE);
  GNUNET_hash (data, len, &hc);
  GNUNET_hash_to_AES_key (&hc, &skey, &iv);
  tmp = GNUNET_malloc (len);
  GNUNET_GE_ASSERT (NULL,
                    len == GNUNET_AES_encrypt (data, len, &skey, &iv, tmp));
  GNUNET_hash (tmp, len, query);
  GNUNET_free (tmp);
}

unsigned int
GNUNET_EC_file_block_get_type (unsigned int size,
                               const GNUNET_EC_DBlock * data)
{
  if (size <= 4)
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_ECRS_BLOCKTYPE_ANY; /* signal error */
    }
  return ntohl (*((const unsigned int *) data));
}

/**
 * What is the main query (the one that is used in routing and for the
 * DB lookup) for the given content and block type?
 *
 * @param data the content (encoded)
 * @param query set to the query for the content
 * @return GNUNET_SYSERR if the content is invalid or
 *   the content type is not known
 */
int
GNUNET_EC_file_block_check_and_get_query (unsigned int size,
                                          const GNUNET_EC_DBlock * data,
                                          int verify, GNUNET_HashCode * query)
{
  unsigned int type;

  type = GNUNET_EC_file_block_get_type (size, data);
  if (type == GNUNET_ECRS_BLOCKTYPE_ANY)
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  switch (type)
    {
    case GNUNET_ECRS_BLOCKTYPE_DATA:
      /* GNUNET_EC_ContentHashKey: GNUNET_hash of content == query */
      GNUNET_hash (&data[1], size - sizeof (GNUNET_EC_DBlock), query);
      return GNUNET_OK;
    case GNUNET_ECRS_BLOCKTYPE_SIGNED:
      {
        const GNUNET_EC_SBlock *sb;
        if (size < sizeof (GNUNET_EC_SBlock))
          {
            GNUNET_GE_BREAK (NULL, 0);
            return GNUNET_SYSERR;
          }
        sb = (const GNUNET_EC_SBlock *) data;
        if ((verify == GNUNET_YES) &&
            (GNUNET_OK != GNUNET_RSA_verify (&sb->identifier,
                                             size
                                             - sizeof (GNUNET_RSA_Signature)
                                             - sizeof (GNUNET_RSA_PublicKey)
                                             - sizeof (unsigned int),
                                             &sb->signature, &sb->subspace)))
          {
            GNUNET_GE_BREAK (NULL, 0);
            return GNUNET_SYSERR;
          }
        *query = sb->identifier;
        return GNUNET_OK;
      }
    case GNUNET_ECRS_BLOCKTYPE_KEYWORD:
      {
        const GNUNET_EC_KBlock *kb;
        if (size < sizeof (GNUNET_EC_KBlock))
          {
            GNUNET_GE_BREAK (NULL, 0);
            return GNUNET_SYSERR;
          }
        kb = (const GNUNET_EC_KBlock *) data;
        if ((verify == GNUNET_YES) &&
            ((GNUNET_OK != GNUNET_RSA_verify (&kb[1],
                                              size -
                                              sizeof (GNUNET_EC_KBlock),
                                              &kb->signature,
                                              &kb->keyspace))))
          {
            GNUNET_GE_BREAK (NULL, 0);
            return GNUNET_SYSERR;
          }
        GNUNET_hash (&kb->keyspace, sizeof (GNUNET_RSA_PublicKey), query);
        return GNUNET_OK;
      }
    case GNUNET_ECRS_BLOCKTYPE_KEYWORD_SIGNED:
      {
        const GNUNET_EC_KSBlock *ks;
        if (size < sizeof (GNUNET_EC_KSBlock))
          {
            GNUNET_GE_BREAK (NULL, 0);
            return GNUNET_SYSERR;
          }
        ks = (const GNUNET_EC_KSBlock *) data;
        if ((verify == GNUNET_YES) &&
            ((GNUNET_OK != GNUNET_RSA_verify (&ks->sblock,
                                              size
                                              - sizeof (GNUNET_EC_KBlock)
                                              - sizeof (unsigned int),
                                              &ks->kblock.signature,
                                              &ks->kblock.keyspace))))
          {
            GNUNET_GE_BREAK (NULL, 0);
            return GNUNET_SYSERR;
          }
        GNUNET_hash (&ks->kblock.keyspace, sizeof (GNUNET_RSA_PublicKey),
                     query);
        return GNUNET_OK;
      }
    case GNUNET_ECRS_BLOCKTYPE_ONDEMAND:
      {
        GNUNET_GE_BREAK_OP (NULL, 0);   /* should never be used here! */
        return GNUNET_SYSERR;
      }
    default:
      {
        GNUNET_GE_BREAK_OP (NULL, 0);   /* unknown block type */
        return GNUNET_SYSERR;
      }
    }                           /* end switch */
}


/**
 * Verify that the given Datum is a valid response
 * to a given query.
 *
 * @param type the type of the query
 * @param size the size of the data
 * @param data the encoded data
 * @param hc result of GNUNET_EC_file_block_check_and_get_query
 * @param keyCount the number of keys in the query,
 *        use 0 to match only primary key
 * @param keys the keys of the query
 * @return GNUNET_YES if this data matches the query, otherwise
 *         GNUNET_NO; GNUNET_SYSERR if the keyCount does not match the
 *         query type
 */
int
GNUNET_EC_is_block_applicable_for_query (unsigned int type,
                                         unsigned int size,
                                         const GNUNET_EC_DBlock * data,
                                         const GNUNET_HashCode * hc,
                                         unsigned int keyCount,
                                         const GNUNET_HashCode * keys)
{
  GNUNET_HashCode h;

  if (type != GNUNET_EC_file_block_get_type (size, data))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;     /* type mismatch */
    }
  if (0 != memcmp (hc, &keys[0], sizeof (GNUNET_HashCode)))
    {
      GNUNET_GE_BREAK (NULL, 0);        /* mismatch between primary queries,
                                           we should not even see those here. */
      return GNUNET_SYSERR;
    }
  if (keyCount == 0)
    return GNUNET_YES;          /* request was to match only primary key */
  switch (type)
    {
    case GNUNET_ECRS_BLOCKTYPE_SIGNED:
      if (keyCount != 2)
        return GNUNET_SYSERR;   /* no match */
      GNUNET_hash (&((const GNUNET_EC_SBlock *) data)->subspace,
                   sizeof (GNUNET_RSA_PublicKey), &h);
      if (0 == memcmp (&keys[1], &h, sizeof (GNUNET_HashCode)))
        return GNUNET_OK;
      return GNUNET_SYSERR;
    case GNUNET_ECRS_BLOCKTYPE_DATA:
    case GNUNET_ECRS_BLOCKTYPE_KEYWORD:
    case GNUNET_ECRS_BLOCKTYPE_KEYWORD_SIGNED:
      if (keyCount != 1)
        GNUNET_GE_BREAK (NULL, 0);      /* keyCount should be 1 */
      return GNUNET_OK;         /* if query matches, everything matches! */
    case GNUNET_ECRS_BLOCKTYPE_ANY:
      GNUNET_GE_BREAK (NULL, 0);        /* block type should be known */
      return GNUNET_SYSERR;
    default:
      GNUNET_GE_BREAK (NULL, 0);        /* unknown block type */
      return GNUNET_SYSERR;
    }
}

/* end of ecrs_core.c */
