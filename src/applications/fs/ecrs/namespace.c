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

#define PSEUDODIR "data/pseudonyms/"
#define INITVALUE "GNUnet!!"
#define MAX_NBLOCK_SIZE 32000
#define MAX_SBLOCK_SIZE 32000

static char *
getPseudonymFileName (struct GE_Context *ectx,
                      struct GC_Configuration *cfg, const char *name)
{
  char *gnHome;
  char *fileName;

  GC_get_configuration_value_filename (cfg,
                                       "GNUNET",
                                       "GNUNET_HOME",
                                       GNUNET_HOME_DIRECTORY, &fileName);
  gnHome = GNUNET_expand_file_name (ectx, fileName);
  GNUNET_free (fileName);
  fileName =
    GNUNET_malloc (strlen (gnHome) + strlen (PSEUDODIR) + strlen (name) + 2);
  strcpy (fileName, gnHome);
  GNUNET_free (gnHome);
  strcat (fileName, DIR_SEPARATOR_STR);
  strcat (fileName, PSEUDODIR);
  GNUNET_disk_directory_create (ectx, fileName);
  strcat (fileName, name);
  return fileName;
}

/**
 * Delete a local namespace.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
ECRS_deleteNamespace (struct GE_Context *ectx,
                      struct GC_Configuration *cfg, const char *name)
{
  char *fileName;

  fileName = getPseudonymFileName (ectx, cfg, name);
  if (GNUNET_YES != GNUNET_disk_file_test (ectx, fileName))
    {
      GNUNET_free (fileName);
      return GNUNET_SYSERR;     /* no such namespace */
    }
  if (0 != UNLINK (fileName))
    {
      GE_LOG_STRERROR_FILE (ectx,
                            GE_WARNING | GE_USER | GE_BULK,
                            "unlink", fileName);
      GNUNET_free (fileName);
      return GNUNET_SYSERR;
    }
  GNUNET_free (fileName);
  return GNUNET_OK;
}

/**
 * Create a new namespace (and publish an advertismement).
 * This publishes both an NBlock in the namespace itself
 * as well as KNBlocks under all keywords specified in
 * the advertisementURI.
 *
 * @param name the name for the namespace
 * @param anonymityLevel for the namespace advertismement
 * @param priority for the namespace advertisement
 * @param expiration for the namespace advertisement
 * @param advertisementURI the keyword (!) URI to advertise the
 *        namespace under (KNBlock)
 * @param meta meta-data for the namespace advertisement
 * @param rootEntry name of the root entry in the namespace (for
 *        the namespace advertisement)
 * @param rootURI set to the URI of the namespace, NULL if
 *        no advertisement was created
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error (namespace already exists)
 */
struct ECRS_URI *
ECRS_createNamespace (struct GE_Context *ectx,
                      struct GC_Configuration *cfg,
                      const char *name,
                      const struct ECRS_MetaData *meta,
                      unsigned int anonymityLevel,
                      unsigned int priority,
                      GNUNET_CronTime expiration,
                      const struct ECRS_URI *advertisementURI,
                      const GNUNET_HashCode * rootEntry)
{
  struct ECRS_URI *rootURI;
  char *fileName;
  struct GNUNET_RSA_PrivateKey *hk;
  GNUNET_RSA_PrivateKeyEncoded *hke;
  char *dst;
  unsigned short len;
  GNUNET_HashCode hc;
  struct GNUNET_ClientServerConnection *sock;
  Datastore_Value *value;
  Datastore_Value *knvalue;
  unsigned int size;
  unsigned int mdsize;
  struct GNUNET_RSA_PrivateKey *pk;
  NBlock *nb;
  KNBlock *knb;
  char **keywords;
  unsigned int keywordCount;
  int i;
  char *cpy;

  if ((advertisementURI != NULL) && (!ECRS_isKeywordUri (advertisementURI)))
    {
      GE_BREAK (ectx, 0);
      return NULL;
    }
  fileName = getPseudonymFileName (ectx, cfg, name);
  if (GNUNET_YES == GNUNET_disk_file_test (ectx, fileName))
    {
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("Cannot create pseudonym `%s', file `%s' exists.\n"),
              name, fileName);
      GNUNET_free (fileName);
      return NULL;
    }
  hk = GNUNET_RSA_create_key ();
  hke = GNUNET_RSA_encode_key (hk);
  len = ntohs (hke->len);
  dst = (char *) hke;
  GNUNET_disk_file_write (ectx, fileName, dst, len, "600");
  GNUNET_free (fileName);
  GNUNET_free (dst);

  /* create advertisements */

  mdsize = ECRS_sizeofMetaData (meta, ECRS_SERIALIZE_PART);
  size = mdsize + sizeof (NBlock);
  if (size > MAX_NBLOCK_SIZE)
    {
      size = MAX_NBLOCK_SIZE;
      value = GNUNET_malloc (sizeof (Datastore_Value) + size);
      nb = (NBlock *) & value[1];
      nb->type = htonl (N_BLOCK);
      mdsize = size - sizeof (NBlock);
      mdsize = ECRS_serializeMetaData (ectx,
                                       meta,
                                       (char *) &nb[1],
                                       mdsize, ECRS_SERIALIZE_PART);
      if (mdsize == -1)
        {
          GE_BREAK (ectx, 0);
          ECRS_deleteNamespace (ectx, cfg, name);
          GNUNET_RSA_free_key (hk);
          return NULL;
        }
      size = sizeof (NBlock) + mdsize;
    }
  else
    {
      value = GNUNET_malloc (sizeof (Datastore_Value) + size);
      nb = (NBlock *) & value[1];
      nb->type = htonl (N_BLOCK);
      ECRS_serializeMetaData (ectx,
                              meta,
                              (char *) &nb[1], mdsize, ECRS_SERIALIZE_FULL);
    }
  value->size = htonl (sizeof (Datastore_Value) + size);
  value->type = htonl (N_BLOCK);
  value->prio = htonl (priority);
  value->anonymityLevel = htonl (anonymityLevel);
  value->expirationTime = GNUNET_htonll (expiration);
  sock = GNUNET_client_connection_create (ectx, cfg);

  /* publish NBlock */
  memset (&nb->identifier, 0, sizeof (GNUNET_HashCode));
  GNUNET_RSA_get_public_key (hk, &nb->subspace);
  GNUNET_hash (&nb->subspace, sizeof (GNUNET_RSA_PublicKey), &nb->namespace);
  rootURI = GNUNET_malloc (sizeof (URI));
  rootURI->type = sks;
  rootURI->data.sks.namespace = nb->namespace;
  rootURI->data.sks.identifier = *rootEntry;

  nb->rootEntry = *rootEntry;

  GE_ASSERT (ectx,
             GNUNET_OK == GNUNET_RSA_sign (hk,
                                           mdsize +
                                           3 * sizeof (GNUNET_HashCode),
                                           &nb->identifier, &nb->signature));
  if (GNUNET_OK != FS_insert (sock, value))
    {
      GE_BREAK (ectx, 0);
      GNUNET_free (rootURI);
      GNUNET_free (value);
      GNUNET_client_connection_destroy (sock);
      GNUNET_RSA_free_key (hk);
      ECRS_deleteNamespace (ectx, cfg, name);
      return NULL;
    }


  /* publish KNBlocks */
  size += sizeof (KNBlock) - sizeof (NBlock);
  knvalue = GNUNET_malloc (sizeof (Datastore_Value) + size);
  *knvalue = *value;
  knvalue->type = htonl (KN_BLOCK);
  knvalue->size = htonl (sizeof (Datastore_Value) + size);
  knb = (KNBlock *) & knvalue[1];
  knb->type = htonl (KN_BLOCK);
  memcpy (&knb->nblock, nb, sizeof (NBlock) + mdsize);

  if (advertisementURI != NULL)
    {
      keywords = advertisementURI->data.ksk.keywords;
      keywordCount = advertisementURI->data.ksk.keywordCount;
      cpy = GNUNET_malloc (size - sizeof (KBlock) - sizeof (unsigned int));
      memcpy (cpy,
              &knb->nblock, size - sizeof (KBlock) - sizeof (unsigned int));
      for (i = 0; i < keywordCount; i++)
        {
          GNUNET_hash (keywords[i], strlen (keywords[i]), &hc);
          pk = GNUNET_RSA_create_key_from_hash (&hc);
          GNUNET_RSA_get_public_key (pk, &knb->kblock.keyspace);
          GE_ASSERT (ectx, size - sizeof (KBlock) - sizeof (unsigned int)
                     == sizeof (NBlock) + mdsize);
          ECRS_encryptInPlace (&hc,
                               &knb->nblock,
                               size - sizeof (KBlock) -
                               sizeof (unsigned int));

          GE_ASSERT (ectx,
                     GNUNET_OK == GNUNET_RSA_sign (pk,
                                                   sizeof (NBlock) + mdsize,
                                                   &knb->nblock,
                                                   &knb->kblock.signature));
          /* extra check: verify sig */
          GNUNET_RSA_free_key (pk);
          if (GNUNET_OK != FS_insert (sock, knvalue))
            {
              GE_BREAK (ectx, 0);
              GNUNET_free (rootURI);
              ECRS_deleteNamespace (ectx, cfg, name);
              GNUNET_free (cpy);
              GNUNET_free (knvalue);
              GNUNET_free (value);
              GNUNET_client_connection_destroy (sock);
              GNUNET_RSA_free_key (hk);
              return NULL;
            }
          /* restore nblock to avoid re-encryption! */
          memcpy (&knb->nblock,
                  cpy, size - sizeof (KBlock) - sizeof (unsigned int));
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
 * Check if the given namespace exists (locally).
 * @param hc if non-null, also check that this is the
 *   hc of the public key
 * @return GNUNET_OK if the namespace exists, GNUNET_SYSERR if not
 */
int
ECRS_testNamespaceExists (struct GE_Context *ectx,
                          struct GC_Configuration *cfg,
                          const char *name, const GNUNET_HashCode * hc)
{
  struct GNUNET_RSA_PrivateKey *hk;
  char *fileName;
  GNUNET_RSA_PrivateKeyEncoded *hke;
  char *dst;
  unsigned long long len;
  GNUNET_HashCode namespace;
  GNUNET_RSA_PublicKey pk;

  /* FIRST: read and decrypt pseudonym! */
  fileName = getPseudonymFileName (ectx, cfg, name);
  if (GNUNET_OK != GNUNET_disk_file_size (ectx, fileName, &len, GNUNET_YES))
    {
      GNUNET_free (fileName);
      return GNUNET_SYSERR;
    }
  if (len < 2)
    {
      GE_LOG (ectx, GE_ERROR | GE_BULK | GE_USER,
              _("File `%s' does not contain a pseudonym.\n"), fileName);
      GNUNET_free (fileName);
      return GNUNET_SYSERR;
    }
  dst = GNUNET_malloc (len);
  len = GNUNET_disk_file_read (ectx, fileName, len, dst);
  GNUNET_free (fileName);
  hke = (GNUNET_RSA_PrivateKeyEncoded *) dst;
  if (ntohs (hke->len) != len)
    {
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("Format of pseudonym `%s' is invalid.\n"), name);
      GNUNET_free (hke);
      return GNUNET_SYSERR;
    }
  hk = GNUNET_RSA_decode_key (hke);
  GNUNET_free (hke);
  if (hk == NULL)
    return GNUNET_SYSERR;
  GNUNET_RSA_get_public_key (hk, &pk);
  GNUNET_RSA_free_key (hk);
  GNUNET_hash (&pk, sizeof (GNUNET_RSA_PublicKey), &namespace);
  if ((hc == NULL)
      || (0 == memcmp (hc, &namespace, sizeof (GNUNET_HashCode))))
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
}

/**
 * Add an entry into a namespace.
 *
 * @param uri what is the URI under which the entry
 *        should be published (must be a namespace URI)
 * @param dstU to which URI should the namespace entry refer?
 * @param md what meta-data should be associated with the
 *        entry?
 */
struct ECRS_URI *
ECRS_addToNamespace (struct GE_Context *ectx,
                     struct GC_Configuration *cfg,
                     const char *name,
                     unsigned int anonymityLevel,
                     unsigned int priority,
                     GNUNET_CronTime expiration,
                     GNUNET_Int32Time creationTime,
                     GNUNET_Int32Time updateInterval,
                     const GNUNET_HashCode * thisId,
                     const GNUNET_HashCode * nextId,
                     const struct ECRS_URI *dstU,
                     const struct ECRS_MetaData *md)
{
  struct ECRS_URI *uri;
  struct GNUNET_ClientServerConnection *sock;
  Datastore_Value *value;
  unsigned int size;
  unsigned int mdsize;
  struct GNUNET_RSA_PrivateKey *hk;
  SBlock *sb;
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
  fileName = getPseudonymFileName (ectx, cfg, name);
  if (GNUNET_OK != GNUNET_disk_file_size (ectx, fileName, &len, GNUNET_YES))
    {
      GNUNET_free (fileName);
      return NULL;
    }
  if (len < 2)
    {
      GE_LOG (ectx, GE_ERROR | GE_BULK | GE_USER,
              _("File `%s' does not contain a pseudonym.\n"), fileName);
      GNUNET_free (fileName);
      return NULL;
    }
  dst = GNUNET_malloc (len);
  len = GNUNET_disk_file_read (ectx, fileName, len, dst);
  GNUNET_free (fileName);
  hke = (GNUNET_RSA_PrivateKeyEncoded *) dst;
  if (ntohs (hke->len) != len)
    {
      GE_LOG (ectx, GE_ERROR | GE_BULK | GE_USER,
              _("Format of pseudonym `%s' is invalid.\n"), name);
      GNUNET_free (hke);
      return NULL;
    }
  hk = GNUNET_RSA_decode_key (hke);
  GNUNET_free (hke);
  if (hk == NULL)
    return NULL;

  /* THEN: construct SBlock */
  dstURI = ECRS_uriToString (dstU);
  mdsize = ECRS_sizeofMetaData (md, ECRS_SERIALIZE_PART);
  size = mdsize + sizeof (SBlock) + strlen (dstURI) + 1;
  if (size > MAX_SBLOCK_SIZE)
    {
      size = MAX_SBLOCK_SIZE;
      value = GNUNET_malloc (sizeof (Datastore_Value) + size);
      sb = (SBlock *) & value[1];
      sb->type = htonl (S_BLOCK);
      destPos = (char *) &sb[1];
      memcpy (destPos, dstURI, strlen (dstURI) + 1);
      mdsize = size - sizeof (SBlock) - strlen (dstURI) - 1;
      mdsize = ECRS_serializeMetaData (ectx,
                                       md,
                                       &destPos[strlen (dstURI) + 1],
                                       mdsize, ECRS_SERIALIZE_PART);
      if (mdsize == -1)
        {
          GE_BREAK (ectx, 0);
          GNUNET_free (dstURI);
          GNUNET_RSA_free_key (hk);
          return NULL;
        }
      size = sizeof (SBlock) + mdsize + strlen (dstURI) + 1;
    }
  else
    {
      value = GNUNET_malloc (sizeof (Datastore_Value) + size);
      sb = (SBlock *) & value[1];
      sb->type = htonl (S_BLOCK);
      destPos = (char *) &sb[1];
      memcpy (destPos, dstURI, strlen (dstURI) + 1);
      ECRS_serializeMetaData (ectx,
                              md,
                              &destPos[strlen (dstURI) + 1],
                              mdsize, ECRS_SERIALIZE_FULL);
    }
  value->size = htonl (sizeof (Datastore_Value) + size);
  value->type = htonl (S_BLOCK);
  value->prio = htonl (priority);
  value->anonymityLevel = htonl (anonymityLevel);
  value->expirationTime = GNUNET_htonll (expiration);

  /* update SBlock specific data */
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

  ECRS_encryptInPlace (thisId,
                       &sb->creationTime,
                       size
                       - sizeof (unsigned int)
                       - sizeof (GNUNET_RSA_Signature)
                       - sizeof (GNUNET_RSA_PublicKey) -
                       sizeof (GNUNET_HashCode));
  /* FINALLY: GNUNET_RSA_sign & publish SBlock */
  GE_ASSERT (ectx,
             GNUNET_OK == GNUNET_RSA_sign (hk,
                                           size
                                           - sizeof (GNUNET_RSA_Signature)
                                           - sizeof (GNUNET_RSA_PublicKey)
                                           - sizeof (unsigned int),
                                           &sb->identifier, &sb->signature));
  GNUNET_RSA_free_key (hk);

  sock = GNUNET_client_connection_create (ectx, cfg);
  ret = FS_insert (sock, value);
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
  struct GE_Context *ectx;
  struct GC_Configuration *cfg;
  ECRS_NamespaceInfoCallback cb;
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

  fileName = getPseudonymFileName (c->ectx, c->cfg, name);
  if (GNUNET_OK !=
      GNUNET_disk_file_size (c->ectx, fileName, &len, GNUNET_YES))
    {
      GNUNET_free (fileName);
      return GNUNET_OK;
    }
  if (len < 2)
    {
      GE_LOG (c->ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("File `%s' does not contain a pseudonym.\n"), fileName);
      GNUNET_free (fileName);
      return GNUNET_OK;
    }
  dst = GNUNET_malloc (len);
  len = GNUNET_disk_file_read (c->ectx, fileName, len, dst);
  hke = (GNUNET_RSA_PrivateKeyEncoded *) dst;
  if (ntohs (hke->len) != len)
    {
      GE_LOG (c->ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("Format of file `%s' is invalid.\n"), fileName);
      GNUNET_free (hke);
      GNUNET_free (fileName);
      return GNUNET_OK;
    }
  hk = GNUNET_RSA_decode_key (hke);
  GNUNET_free (hke);
  if (hk == NULL)
    {
      GE_LOG (c->ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("Format of file `%s' is invalid.\n"), fileName);
      GNUNET_free (fileName);
      GE_BREAK (c->ectx, 0);
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
ECRS_listNamespaces (struct GE_Context *ectx,
                     struct GC_Configuration *cfg,
                     ECRS_NamespaceInfoCallback cb, void *cls)
{
  char *dirName;
  struct lNCLS myCLS;

  myCLS.cls = cls;
  myCLS.cb = cb;
  myCLS.cnt = 0;
  myCLS.ectx = ectx;
  myCLS.cfg = cfg;
  dirName = getPseudonymFileName (ectx, cfg, "");
  GNUNET_disk_directory_scan (ectx, dirName, &processFile_, &myCLS);
  GNUNET_free (dirName);
  return myCLS.cnt;
}



/* end of namespace.c */
