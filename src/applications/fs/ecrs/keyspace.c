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
 * @file applications/fs/ecrs/upload.c
 * @brief publish a URI in the keyword space
 * @see http://gnunet.org/encoding.php3
 * @author Krista Bennett
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_fs_lib.h"
#include "gnunet_protocols.h"
#include "ecrs.h"

#define DEBUG_KEYSPACE GNUNET_NO

/**
 * What is the maximum size that we allow for a kblock
 * before we start dropping meta-data? (128x128 thumbnails
 * with 24-bit color can take 49152 bytes, so we pick
 * something slightly higher -- we're limited by 64k).
 */
#define MAX_KBLOCK_SIZE 60000

#if EXTRA_CHECKS

/**
 * Process replies received in response to our
 * queries.  Verifies, decrypts and passes valid
 * replies to the callback.
 *
 * @return GNUNET_SYSERR if the entry is malformed
 */
static int
verifyKBlock (struct GE_Context *ectx,
              const GNUNET_HashCode * key, Datastore_Value * value)
{
  unsigned int type;
  ECRS_FileInfo fi;
  unsigned int size;
  GNUNET_HashCode query;
  KBlock *kb;
  const char *dstURI;
  int j;

  type = ntohl (value->type);
  size = ntohl (value->size) - sizeof (Datastore_Value);
  if (GNUNET_OK !=
      getQueryFor (size, (DBlock *) & value[1], GNUNET_YES, &query))
    return GNUNET_SYSERR;
  GE_ASSERT (ectx, type == K_BLOCK);

  if (size < sizeof (KBlock))
    return GNUNET_SYSERR;
  kb = (KBlock *) & value[1];
  ECRS_decryptInPlace (key, &kb[1], size - sizeof (KBlock));
  j = sizeof (KBlock);
  while ((j < size) && (((const char *) kb)[j] != '\0'))
    j++;
  if (j == size)
    {
      GE_BREAK (NULL, 0);       /* kblock malformed */
      return GNUNET_SYSERR;
    }
  dstURI = (const char *) &kb[1];
  j++;
  fi.meta = ECRS_deserializeMetaData (ectx,
                                      &((const char *) kb)[j], size - j);
  if (fi.meta == NULL)
    {
      GE_BREAK (ectx, 0);       /* kblock malformed */
      return GNUNET_SYSERR;
    }
  fi.uri = ECRS_stringToUri (ectx, dstURI);
  if (fi.uri == NULL)
    {
      GE_BREAK (ectx, 0);       /* kblock malformed */
      ECRS_freeMetaData (fi.meta);
      return GNUNET_SYSERR;
    }
  ECRS_freeUri (fi.uri);
  ECRS_freeMetaData (fi.meta);
  return GNUNET_OK;
}

#endif


/**
 * Add an entry into the K-space (keyword space).
 *
 * @param uri what is the URI under which the entry
 *        should be published (must be a keyword URI)
 * @param dst to which URI should the entry refer?
 * @param md what meta-data should be associated with the
 *        entry?
 */
int
ECRS_addToKeyspace (struct GE_Context *ectx,
                    struct GC_Configuration *cfg,
                    const struct ECRS_URI *uri,
                    unsigned int anonymityLevel,
                    unsigned int priority,
                    GNUNET_CronTime expirationTime,
                    const struct ECRS_URI *dst,
                    const struct ECRS_MetaData *md)
{
  struct GNUNET_ClientServerConnection *sock;
  Datastore_Value *value;
  int ret;
  unsigned int size;
  unsigned int mdsize;
  struct GNUNET_RSA_PrivateKey *pk;
  char *dstURI;
  KBlock *kb;
  char **keywords;
  unsigned int keywordCount;
  int i;
#if DEBUG_KEYSPACE
  GNUNET_EncName enc;
#endif
#if EXTRA_CHECKS
  GNUNET_HashCode hc;
#endif
  GNUNET_HashCode key;
  char *cpy;                    /* copy of the encrypted portion */
  struct ECRS_URI *xuri;

  if (!ECRS_isKeywordUri (uri))
    {
      GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  mdsize = ECRS_sizeofMetaData (md, ECRS_SERIALIZE_PART);
  dstURI = ECRS_uriToString (dst);
  size = mdsize + sizeof (KBlock) + strlen (dstURI) + 1;
  if (size > MAX_KBLOCK_SIZE)
    {
      size = MAX_KBLOCK_SIZE;
      value = GNUNET_malloc (sizeof (Datastore_Value) + size);
      kb = (KBlock *) & value[1];
      kb->type = htonl (K_BLOCK);
      memcpy (&kb[1], dstURI, strlen (dstURI) + 1);
      mdsize = size - sizeof (KBlock) - strlen (dstURI) - 1;
      mdsize = ECRS_serializeMetaData (ectx,
                                       md,
                                       &((char *) &kb[1])[strlen (dstURI) +
                                                          1], mdsize,
                                       ECRS_SERIALIZE_PART);
      if (mdsize == -1)
        {
          GE_BREAK (ectx, 0);
          GNUNET_free (dstURI);
          return GNUNET_SYSERR;
        }
      size = sizeof (KBlock) + strlen (dstURI) + 1 + mdsize;
    }
  else
    {
      value = GNUNET_malloc (sizeof (Datastore_Value) + size);
      kb = (KBlock *) & value[1];
      kb->type = htonl (K_BLOCK);
      memcpy (&kb[1], dstURI, strlen (dstURI) + 1);
      GE_ASSERT (ectx,
                 mdsize ==
                 ECRS_serializeMetaData (ectx,
                                         md,
                                         &((char *) &kb[1])[strlen (dstURI) +
                                                            1], mdsize,
                                         ECRS_SERIALIZE_FULL));
    }
  value->size = htonl (sizeof (Datastore_Value) + size);
  value->type = htonl (K_BLOCK);
  value->prio = htonl (priority);
  value->anonymityLevel = htonl (anonymityLevel);
  value->expirationTime = GNUNET_htonll (expirationTime);
  sock = GNUNET_client_connection_create (ectx, cfg);
  ret = GNUNET_OK;

  if (GC_get_configuration_value_yesno (cfg,
                                        "FS",
                                        "DISABLE-CREATION-TIME",
                                        GNUNET_NO) == GNUNET_YES)
    xuri = ECRS_dupUri (uri);
  else
    xuri = ECRS_dateExpandKeywordUri (uri);
  keywords = xuri->data.ksk.keywords;
  keywordCount = xuri->data.ksk.keywordCount;
  cpy = GNUNET_malloc (mdsize + strlen (dstURI) + 1);
  memcpy (cpy, &kb[1], mdsize + strlen (dstURI) + 1);
  for (i = 0; i < keywordCount; i++)
    {
      memcpy (&kb[1], cpy, mdsize + strlen (dstURI) + 1);
      GNUNET_hash (keywords[i], strlen (keywords[i]), &key);
#if DEBUG_KEYSPACE
      IF_GELOG (ectx, GE_DEBUG | GE_REQUEST | GE_USER,
                GNUNET_hash_to_enc (&key, &enc));
      GE_LOG (ectx, GE_DEBUG | GE_REQUEST | GE_USER,
              "Encrypting KBlock with key %s.\n", &enc);
#endif
      ECRS_encryptInPlace (&key, &kb[1], mdsize + strlen (dstURI) + 1);
      pk = GNUNET_RSA_create_key_from_hash (&key);
      GNUNET_RSA_get_public_key (pk, &kb->keyspace);
      GE_ASSERT (ectx,
                 GNUNET_OK == GNUNET_RSA_sign (pk,
                                               mdsize + strlen (dstURI) + 1,
                                               &kb[1], &kb->signature));
#if EXTRA_CHECKS
      /* extra check: verify sig */
      GE_ASSERT (ectx,
                 GNUNET_OK == getQueryFor (size, (DBlock *) kb, GNUNET_YES,
                                           &hc));
#endif
      GNUNET_RSA_free_key (pk);
      if (GNUNET_OK != FS_insert (sock, value))
        ret = GNUNET_SYSERR;
#if EXTRA_CHECKS
      GE_ASSERT (ectx, GNUNET_OK == verifyKBlock (ectx, &key, value))
#endif
    }
  ECRS_freeUri (xuri);
  GNUNET_free (cpy);
  GNUNET_free (dstURI);
  GNUNET_client_connection_destroy (sock);
  GNUNET_free (value);
  return ret;
}

/* end of keyspace.c */
