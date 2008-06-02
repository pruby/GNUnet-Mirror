/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/namespace.c
 * @brief creation, deletion and advertising of namespaces
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_protocols.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_fs_lib.h"
#include "ecrs_core.h"
#include "ecrs.h"

#define PSEUDODIR "data/namespace/keys/"
#define INITVALUE "GNUnet!!"
#define MAX_NBLOCK_SIZE 32000
#define MAX_SBLOCK_SIZE 32000

static char *
getPseudonymFileName (struct GNUNET_GE_Context *ectx,
                      struct GNUNET_GC_Configuration *cfg,
                      const GNUNET_HashCode * pid)
{
  char *gnHome;
  char *fileName;
  GNUNET_EncName enc;

  GNUNET_GC_get_configuration_value_filename (cfg,
                                              "GNUNET",
                                              "GNUNET_HOME",
                                              GNUNET_DEFAULT_HOME_DIRECTORY,
                                              &fileName);
  gnHome = GNUNET_expand_file_name (ectx, fileName);
  GNUNET_free (fileName);
  fileName =
    GNUNET_malloc (strlen (gnHome) + strlen (PSEUDODIR) +
                   sizeof (GNUNET_EncName) + 2);
  strcpy (fileName, gnHome);
  GNUNET_free (gnHome);
  strcat (fileName, DIR_SEPARATOR_STR);
  strcat (fileName, PSEUDODIR);
  GNUNET_disk_directory_create (ectx, fileName);
  if (pid != NULL)
    {
      GNUNET_hash_to_enc (pid, &enc);
      strcat (fileName, (char *) &enc);
    }
  return fileName;
}


/**
 * Check if the given namespace exists (locally).
 *
 * @return GNUNET_OK if the namespace exists, GNUNET_SYSERR if not
 */
int
GNUNET_ECRS_namespace_test_exists (struct GNUNET_GE_Context *ectx,
                                   struct GNUNET_GC_Configuration *cfg,
                                   const GNUNET_HashCode * pid)
{
  char *fileName;
  int ret;

  fileName = getPseudonymFileName (ectx, cfg, pid);
  ret = GNUNET_disk_file_test (ectx, fileName);
  GNUNET_free (fileName);
  return ret;
}

/**
 * Delete a local namespace.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_ECRS_namespace_delete (struct GNUNET_GE_Context *ectx,
                              struct GNUNET_GC_Configuration *cfg,
                              const GNUNET_HashCode * pid)
{
  char *fileName;

  fileName = getPseudonymFileName (ectx, cfg, pid);
  if (GNUNET_YES != GNUNET_disk_file_test (ectx, fileName))
    {
      GNUNET_free (fileName);
      return GNUNET_SYSERR;     /* no such namespace */
    }
  if (0 != UNLINK (fileName))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_USER |
                                   GNUNET_GE_BULK, "unlink", fileName);
      GNUNET_free (fileName);
      return GNUNET_SYSERR;
    }
  GNUNET_free (fileName);
  return GNUNET_OK;
}

/**
 * Create a new namespace (and publish an advertismement).
 * This publishes both an GNUNET_EC_NBlock in the namespace itself
 * as well as KNBlocks under all keywords specified in
 * the advertisementURI.
 *
 * @param name the name for the namespace
 * @param anonymity_level for the namespace advertismement
 * @param priority for the namespace advertisement
 * @param expiration for the namespace advertisement
 * @param advertisementURI the keyword (!) URI to advertise the
 *        namespace under (GNUNET_EC_KNBlock)
 * @param meta meta-data for the namespace advertisement
 * @param rootEntry name of the root entry in the namespace (for
 *        the namespace advertisement)
 * @param rootURI set to the URI of the namespace, NULL if
 *        no advertisement was created
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error (namespace already exists)
 */
struct GNUNET_ECRS_URI *
GNUNET_ECRS_namespace_create (struct GNUNET_GE_Context *ectx,
                              struct GNUNET_GC_Configuration *cfg,
                              const struct GNUNET_ECRS_MetaData *meta,
                              unsigned int anonymityLevel,
                              unsigned int priority,
                              GNUNET_CronTime expiration,
                              const struct GNUNET_ECRS_URI *advertisementURI,
                              const GNUNET_HashCode * rootEntry)
{
  struct GNUNET_ECRS_URI *rootURI;
  char *fileName;
  struct GNUNET_RSA_PrivateKey *hk;
  GNUNET_RSA_PrivateKeyEncoded *hke;
  char *dst;
  unsigned short len;
  GNUNET_HashCode hc;
  struct GNUNET_ClientServerConnection *sock;
  GNUNET_DatastoreValue *value;
  GNUNET_DatastoreValue *knvalue;
  unsigned int size;
  unsigned int mdsize;
  struct GNUNET_RSA_PrivateKey *pk;
  GNUNET_RSA_PublicKey pubk;
  GNUNET_HashCode pid;
  GNUNET_EC_NBlock *nb;
  GNUNET_EC_KNBlock *knb;
  char **keywords;
  const char *keyword;
  unsigned int keywordCount;
  int i;
  char *cpy;

  if ((advertisementURI != NULL)
      && (!GNUNET_ECRS_uri_test_ksk (advertisementURI)))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return NULL;
    }
  hk = GNUNET_RSA_create_key ();
  GNUNET_RSA_get_public_key (hk, &pubk);
  GNUNET_hash (&pubk, sizeof (GNUNET_RSA_PublicKey), &pid);
  fileName = getPseudonymFileName (ectx, cfg, &pid);
  if (GNUNET_YES == GNUNET_disk_file_test (ectx, fileName))
    {
      GNUNET_GE_BREAK (NULL, 0);        /* hash collision!? */
      GNUNET_free (fileName);
      return NULL;
    }
  hke = GNUNET_RSA_encode_key (hk);
  len = ntohs (hke->len);
  dst = (char *) hke;
  GNUNET_disk_file_write (ectx, fileName, dst, len, "600");
  GNUNET_free (fileName);
  GNUNET_free (dst);

  /* create advertisements */
  mdsize =
    GNUNET_ECRS_meta_data_get_serialized_size (meta,
                                               GNUNET_ECRS_SERIALIZE_PART);
  size = mdsize + sizeof (GNUNET_EC_NBlock);
  if (size > MAX_NBLOCK_SIZE)
    {
      size = MAX_NBLOCK_SIZE;
      value = GNUNET_malloc (sizeof (GNUNET_DatastoreValue) + size);
      nb = (GNUNET_EC_NBlock *) & value[1];
      nb->type = htonl (GNUNET_ECRS_BLOCKTYPE_NAMESPACE);
      mdsize = size - sizeof (GNUNET_EC_NBlock);
      mdsize = GNUNET_ECRS_meta_data_serialize (ectx,
                                                meta,
                                                (char *) &nb[1],
                                                mdsize,
                                                GNUNET_ECRS_SERIALIZE_PART);
      if (mdsize == -1)
        {
          GNUNET_GE_BREAK (ectx, 0);
          GNUNET_ECRS_namespace_delete (ectx, cfg, &pid);
          GNUNET_RSA_free_key (hk);
          return NULL;
        }
      size = sizeof (GNUNET_EC_NBlock) + mdsize;
    }
  else
    {
      value = GNUNET_malloc (sizeof (GNUNET_DatastoreValue) + size);
      nb = (GNUNET_EC_NBlock *) & value[1];
      nb->type = htonl (GNUNET_ECRS_BLOCKTYPE_NAMESPACE);
      GNUNET_ECRS_meta_data_serialize (ectx,
                                       meta,
                                       (char *) &nb[1], mdsize,
                                       GNUNET_ECRS_SERIALIZE_FULL);
    }
  value->size = htonl (sizeof (GNUNET_DatastoreValue) + size);
  value->type = htonl (GNUNET_ECRS_BLOCKTYPE_NAMESPACE);
  value->priority = htonl (priority);
  value->anonymity_level = htonl (anonymityLevel);
  value->expiration_time = GNUNET_htonll (expiration);
  sock = GNUNET_client_connection_create (ectx, cfg);

  /* publish GNUNET_EC_NBlock */
  memset (&nb->identifier, 0, sizeof (GNUNET_HashCode));
  GNUNET_RSA_get_public_key (hk, &nb->subspace);
  GNUNET_hash (&nb->subspace, sizeof (GNUNET_RSA_PublicKey), &nb->namespace);
  rootURI = GNUNET_malloc (sizeof (URI));
  rootURI->type = sks;
  rootURI->data.sks.namespace = nb->namespace;
  rootURI->data.sks.identifier = *rootEntry;

  nb->rootEntry = *rootEntry;

  GNUNET_GE_ASSERT (ectx,
                    GNUNET_OK == GNUNET_RSA_sign (hk,
                                                  mdsize +
                                                  3 *
                                                  sizeof (GNUNET_HashCode),
                                                  &nb->identifier,
                                                  &nb->signature));
  if (GNUNET_OK != GNUNET_FS_insert (sock, value))
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_free (rootURI);
      GNUNET_free (value);
      GNUNET_client_connection_destroy (sock);
      GNUNET_RSA_free_key (hk);
      GNUNET_ECRS_namespace_delete (ectx, cfg, &pid);
      return NULL;
    }


  /* publish KNBlocks */
  size += sizeof (GNUNET_EC_KNBlock) - sizeof (GNUNET_EC_NBlock);
  knvalue = GNUNET_malloc (sizeof (GNUNET_DatastoreValue) + size);
  *knvalue = *value;
  knvalue->type = htonl (GNUNET_ECRS_BLOCKTYPE_KEYWORD_FOR_NAMESPACE);
  knvalue->size = htonl (sizeof (GNUNET_DatastoreValue) + size);
  knb = (GNUNET_EC_KNBlock *) & knvalue[1];
  knb->type = htonl (GNUNET_ECRS_BLOCKTYPE_KEYWORD_FOR_NAMESPACE);
  memcpy (&knb->nblock, nb, sizeof (GNUNET_EC_NBlock) + mdsize);

  if (advertisementURI != NULL)
    {
      keywords = advertisementURI->data.ksk.keywords;
      keywordCount = advertisementURI->data.ksk.keywordCount;
      cpy =
        GNUNET_malloc (size - sizeof (GNUNET_EC_KBlock) -
                       sizeof (unsigned int));
      memcpy (cpy, &knb->nblock,
              size - sizeof (GNUNET_EC_KBlock) - sizeof (unsigned int));
      for (i = 0; i < keywordCount; i++)
        {
          keyword = keywords[i];
          /* first character of keyword indicates
             mandatory or not -- ignore for hashing! */
          GNUNET_hash (&keyword[1], strlen (&keyword[1]), &hc);
          pk = GNUNET_RSA_create_key_from_hash (&hc);
          GNUNET_RSA_get_public_key (pk, &knb->kblock.keyspace);
          GNUNET_GE_ASSERT (ectx,
                            size - sizeof (GNUNET_EC_KBlock) -
                            sizeof (unsigned int) ==
                            sizeof (GNUNET_EC_NBlock) + mdsize);
          GNUNET_ECRS_encryptInPlace (&hc, &knb->nblock,
                                      size - sizeof (GNUNET_EC_KBlock) -
                                      sizeof (unsigned int));

          GNUNET_GE_ASSERT (ectx,
                            GNUNET_OK == GNUNET_RSA_sign (pk,
                                                          sizeof
                                                          (GNUNET_EC_NBlock) +
                                                          mdsize,
                                                          &knb->nblock,
                                                          &knb->kblock.
                                                          signature));
          /* extra check: verify sig */
          GNUNET_RSA_free_key (pk);
          if (GNUNET_OK != GNUNET_FS_insert (sock, knvalue))
            {
              GNUNET_GE_BREAK (ectx, 0);
              GNUNET_free (rootURI);
              GNUNET_ECRS_namespace_delete (ectx, cfg, &pid);
              GNUNET_free (cpy);
              GNUNET_free (knvalue);
              GNUNET_free (value);
              GNUNET_client_connection_destroy (sock);
              GNUNET_RSA_free_key (hk);
              return NULL;
            }
          /* restore nblock to avoid re-encryption! */
          memcpy (&knb->nblock,
                  cpy,
                  size - sizeof (GNUNET_EC_KBlock) - sizeof (unsigned int));
        }
      GNUNET_free (cpy);
    }
  GNUNET_free (knvalue);
  GNUNET_free (value);
  GNUNET_client_connection_destroy (sock);
  GNUNET_RSA_free_key (hk);

  return rootURI;
}

/**
 * Add an entry into a namespace.
 *
 * @param name in which namespace to publish, use just the
 *        nickname of the namespace
 * @param dst to which URI should the namespace entry refer?
 * @param md what meta-data should be associated with the
 *        entry?
 * @return URI on success, NULL on error
 */
struct GNUNET_ECRS_URI *
GNUNET_ECRS_namespace_add_content (struct GNUNET_GE_Context *ectx,
                                   struct GNUNET_GC_Configuration *cfg,
                                   const GNUNET_HashCode * pid,
                                   unsigned int anonymityLevel,
                                   unsigned int priority,
                                   GNUNET_CronTime expiration,
                                   GNUNET_Int32Time creationTime,
                                   GNUNET_Int32Time updateInterval,
                                   const GNUNET_HashCode * thisId,
                                   const GNUNET_HashCode * nextId,
                                   const struct GNUNET_ECRS_URI *dstU,
                                   const struct GNUNET_ECRS_MetaData *md)
{
  struct GNUNET_ECRS_URI *uri;
  struct GNUNET_ClientServerConnection *sock;
  GNUNET_DatastoreValue *value;
  unsigned int size;
  unsigned int mdsize;
  struct GNUNET_RSA_PrivateKey *hk;
  GNUNET_EC_SBlock *sb;
  GNUNET_HashCode namespace;
  char *dstURI;
  char *destPos;
  char *fileName;
  GNUNET_RSA_PrivateKeyEncoded *hke;
  char *dst;
  unsigned long long len;
  GNUNET_HashCode hc;
  int ret;

  /* FIRST: read pseudonym! */
  fileName = getPseudonymFileName (ectx, cfg, pid);
  if (GNUNET_OK != GNUNET_disk_file_size (ectx, fileName, &len, GNUNET_YES))
    {
      GNUNET_free (fileName);
      return NULL;
    }
  if (len < 2)
    {
      GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("File `%s' does not contain a pseudonym.\n"),
                     fileName);
      GNUNET_free (fileName);
      return NULL;
    }
  dst = GNUNET_malloc (len);
  len = GNUNET_disk_file_read (ectx, fileName, len, dst);
  hke = (GNUNET_RSA_PrivateKeyEncoded *) dst;
  if (ntohs (hke->len) != len)
    {
      GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Format of pseudonym `%s' is invalid.\n"), fileName);
      GNUNET_free (fileName);
      GNUNET_free (hke);
      return NULL;
    }
  GNUNET_free (fileName);
  hk = GNUNET_RSA_decode_key (hke);
  GNUNET_free (hke);
  if (hk == NULL)
    return NULL;

  /* THEN: construct GNUNET_EC_SBlock */
  dstURI = GNUNET_ECRS_uri_to_string (dstU);
  mdsize =
    GNUNET_ECRS_meta_data_get_serialized_size (md,
                                               GNUNET_ECRS_SERIALIZE_PART);
  size = mdsize + sizeof (GNUNET_EC_SBlock) + strlen (dstURI) + 1;
  if (size > MAX_SBLOCK_SIZE)
    {
      size = MAX_SBLOCK_SIZE;
      value = GNUNET_malloc (sizeof (GNUNET_DatastoreValue) + size);
      sb = (GNUNET_EC_SBlock *) & value[1];
      sb->type = htonl (GNUNET_ECRS_BLOCKTYPE_SIGNED);
      destPos = (char *) &sb[1];
      memcpy (destPos, dstURI, strlen (dstURI) + 1);
      mdsize = size - sizeof (GNUNET_EC_SBlock) - strlen (dstURI) - 1;
      mdsize = GNUNET_ECRS_meta_data_serialize (ectx,
                                                md,
                                                &destPos[strlen (dstURI) + 1],
                                                mdsize,
                                                GNUNET_ECRS_SERIALIZE_PART);
      if (mdsize == -1)
        {
          GNUNET_GE_BREAK (ectx, 0);
          GNUNET_free (dstURI);
          GNUNET_RSA_free_key (hk);
          GNUNET_free (value);
          return NULL;
        }
      size = sizeof (GNUNET_EC_SBlock) + mdsize + strlen (dstURI) + 1;
    }
  else
    {
      value = GNUNET_malloc (sizeof (GNUNET_DatastoreValue) + size);
      sb = (GNUNET_EC_SBlock *) & value[1];
      sb->type = htonl (GNUNET_ECRS_BLOCKTYPE_SIGNED);
      destPos = (char *) &sb[1];
      memcpy (destPos, dstURI, strlen (dstURI) + 1);
      GNUNET_ECRS_meta_data_serialize (ectx,
                                       md,
                                       &destPos[strlen (dstURI) + 1],
                                       mdsize, GNUNET_ECRS_SERIALIZE_FULL);
    }
  value->size = htonl (sizeof (GNUNET_DatastoreValue) + size);
  value->type = htonl (GNUNET_ECRS_BLOCKTYPE_SIGNED);
  value->priority = htonl (priority);
  value->anonymity_level = htonl (anonymityLevel);
  value->expiration_time = GNUNET_htonll (expiration);

  /* update GNUNET_EC_SBlock specific data */
  sb->creationTime = htonl (creationTime);
  sb->updateInterval = htonl (updateInterval);
  sb->nextIdentifier = *nextId;

  GNUNET_hash_difference (thisId, nextId, &sb->identifierIncrement);
  GNUNET_hash (thisId, sizeof (GNUNET_HashCode), &hc);
  GNUNET_RSA_get_public_key (hk, &sb->subspace);
  GNUNET_hash (&sb->subspace, sizeof (GNUNET_RSA_PublicKey), &namespace);
  GNUNET_hash_xor (&hc, &namespace, &sb->identifier);   /* sb->identifier = primary key in query! */

  uri = GNUNET_malloc (sizeof (URI));
  uri->type = sks;
  uri->data.sks.namespace = namespace;
  uri->data.sks.identifier = *thisId;

  GNUNET_ECRS_encryptInPlace (thisId,
                              &sb->creationTime,
                              size
                              - sizeof (unsigned int)
                              - sizeof (GNUNET_RSA_Signature)
                              - sizeof (GNUNET_RSA_PublicKey) -
                              sizeof (GNUNET_HashCode));
  /* FINALLY: GNUNET_RSA_sign & publish GNUNET_EC_SBlock */
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_OK == GNUNET_RSA_sign (hk,
                                                  size
                                                  -
                                                  sizeof
                                                  (GNUNET_RSA_Signature) -
                                                  sizeof
                                                  (GNUNET_RSA_PublicKey) -
                                                  sizeof (unsigned int),
                                                  &sb->identifier,
                                                  &sb->signature));
  GNUNET_RSA_free_key (hk);

  sock = GNUNET_client_connection_create (ectx, cfg);
  ret = GNUNET_FS_insert (sock, value);
  if (ret != GNUNET_OK)
    {
      GNUNET_free (uri);
      uri = NULL;
    }
  GNUNET_client_connection_destroy (sock);
  GNUNET_free (value);
  GNUNET_free (dstURI);

  return uri;
}

struct lNCLS
{
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GC_Configuration *cfg;
  GNUNET_ECRS_NamespaceInfoProcessor cb;
  void *cls;
  int cnt;
};

static int
processFile_ (const char *name, const char *dirName, void *cls)
{
  struct lNCLS *c = cls;
  struct GNUNET_RSA_PrivateKey *hk;
  char *fileName;
  GNUNET_RSA_PrivateKeyEncoded *hke;
  char *dst;
  unsigned long long len;
  GNUNET_HashCode namespace;
  GNUNET_RSA_PublicKey pk;
  GNUNET_HashCode pid;

  if (GNUNET_OK != GNUNET_enc_to_hash (name, &pid))
    return GNUNET_OK;           /* ignore */
  fileName = getPseudonymFileName (c->ectx, c->cfg, &pid);
  if (GNUNET_OK !=
      GNUNET_disk_file_size (c->ectx, fileName, &len, GNUNET_YES))
    {
      GNUNET_free (fileName);
      return GNUNET_OK;
    }
  if (len < 2)
    {
      GNUNET_GE_LOG (c->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("File `%s' does not contain a pseudonym, trying to remove.\n"),
                     fileName);
      UNLINK (fileName);
      GNUNET_free (fileName);
      return GNUNET_OK;
    }
  dst = GNUNET_malloc (len);
  len = GNUNET_disk_file_read (c->ectx, fileName, len, dst);
  hke = (GNUNET_RSA_PrivateKeyEncoded *) dst;
  if (ntohs (hke->len) != len)
    {
      GNUNET_GE_LOG (c->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Format of file `%s' is invalid.\n"), fileName);
      GNUNET_free (hke);
      GNUNET_free (fileName);
      return GNUNET_OK;
    }
  hk = GNUNET_RSA_decode_key (hke);
  GNUNET_free (hke);
  if (hk == NULL)
    {
      GNUNET_GE_LOG (c->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Format of file `%s' is invalid, trying to remove.\n"),
                     fileName);
      UNLINK (fileName);
      GNUNET_free (fileName);
      GNUNET_GE_BREAK (c->ectx, 0);
      return GNUNET_SYSERR;
    }
  GNUNET_free (fileName);
  GNUNET_RSA_get_public_key (hk, &pk);
  GNUNET_RSA_free_key (hk);
  GNUNET_hash (&pk, sizeof (GNUNET_RSA_PublicKey), &namespace);
  if (NULL != c->cb)
    {
      if (GNUNET_OK == c->cb (&namespace, name, c->cls))
        c->cnt++;
      else
        c->cnt = GNUNET_SYSERR;
    }
  else
    c->cnt++;
  return GNUNET_OK;
}

/**
 * Build a list of all available namespaces
 *
 * @param list where to store the names (is allocated, caller frees)
 * @return GNUNET_SYSERR on error, otherwise the number of pseudonyms in list
 */
int
GNUNET_ECRS_get_namespaces (struct GNUNET_GE_Context *ectx,
                            struct GNUNET_GC_Configuration *cfg,
                            GNUNET_ECRS_NamespaceInfoProcessor cb, void *cls)
{
  char *dirName;
  struct lNCLS myCLS;

  myCLS.cls = cls;
  myCLS.cb = cb;
  myCLS.cnt = 0;
  myCLS.ectx = ectx;
  myCLS.cfg = cfg;
  dirName = getPseudonymFileName (ectx, cfg, NULL);
  GNUNET_disk_directory_scan (ectx, dirName, &processFile_, &myCLS);
  GNUNET_free (dirName);
  return myCLS.cnt;
}



/* end of namespace.c */
