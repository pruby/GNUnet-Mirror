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

static char * getPseudonymFileName(struct GE_Context * ectx,
				   struct GC_Configuration * cfg,
				   const char * name) {
  char * gnHome;
  char * fileName;

  GC_get_configuration_value_filename(cfg,
				      "GNUNET",
				      "GNUNET_HOME",
				      GNUNET_HOME_DIRECTORY,
				      &fileName);
  gnHome = string_expandFileName(ectx, fileName);
  FREE(fileName);
  fileName = MALLOC(strlen(gnHome) + strlen(PSEUDODIR) + strlen(name) + 2);
  strcpy(fileName, gnHome);
  FREE(gnHome);
  strcat(fileName, DIR_SEPARATOR_STR);
  strcat(fileName, PSEUDODIR);
  disk_directory_create(ectx,
			fileName);
  strcat(fileName, name);
  return fileName;
}

/**
 * Delete a local namespace.
 *
 * @return OK on success, SYSERR on error
 */
int ECRS_deleteNamespace(struct GE_Context * ectx,
			 struct GC_Configuration * cfg,
			 const char * name) {
  char * fileName;

  fileName = getPseudonymFileName(ectx, cfg, name);
  if (YES != disk_file_test(ectx,
			    fileName)) {
    FREE(fileName);
    return SYSERR; /* no such namespace */
  }
  if (0 != UNLINK(fileName)) {
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_USER | GE_BULK,
			 "unlink",
			 fileName);
    FREE(fileName);
    return SYSERR;
  }
  FREE(fileName);
  return OK;
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
 * @return OK on success, SYSERR on error (namespace already exists)
 */
struct ECRS_URI *
ECRS_createNamespace(struct GE_Context * ectx,
		     struct GC_Configuration * cfg,
		     const char * name,
		     const struct ECRS_MetaData * meta,
		     unsigned int anonymityLevel,
		     unsigned int priority,
		     cron_t expiration,
		     const struct ECRS_URI * advertisementURI,
		     const HashCode512 * rootEntry) {
  struct ECRS_URI * rootURI;
  char * fileName;
  struct PrivateKey * hk;
  PrivateKeyEncoded * hke;
  char * dst;
  unsigned short len;
  HashCode512 hc;
  struct ClientServerConnection * sock;
  Datastore_Value * value;
  Datastore_Value * knvalue;
  unsigned int size;
  unsigned int mdsize;
  struct PrivateKey * pk;
  NBlock * nb;
  KNBlock * knb;
  char ** keywords;
  unsigned int keywordCount;
  int i;
  char * cpy;

  if ( (advertisementURI != NULL) &&
       (! ECRS_isKeywordUri(advertisementURI)) ) {
    GE_BREAK(ectx, 0);
    return NULL;
  }
  fileName = getPseudonymFileName(ectx,
				  cfg,
				  name);
  if (YES == disk_file_test(ectx,
			    fileName)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("Cannot create pseudonym `%s', file `%s' exists.\n"),
	   name,
	   fileName);
    FREE(fileName);
    return NULL;
  }
  hk  = makePrivateKey();
  hke = encodePrivateKey(hk);
  len = ntohs(hke->len);
  dst = (char*) hke;
  disk_file_write(ectx,
		  fileName,
		  dst,
		  len,
		  "600");
  FREE(fileName);
  FREE(dst);

  /* create advertisements */

  mdsize = ECRS_sizeofMetaData(meta,
			       ECRS_SERIALIZE_PART);
  size = mdsize + sizeof(NBlock);
  if (size > MAX_NBLOCK_SIZE) {
    size = MAX_NBLOCK_SIZE;
    value = MALLOC(sizeof(Datastore_Value) +
		   size);
    nb = (NBlock*) &value[1];
    nb->type = htonl(N_BLOCK);
    mdsize = size - sizeof(NBlock);
    mdsize = ECRS_serializeMetaData(ectx,
				    meta,
				    (char*)&nb[1],
				    mdsize,
				    ECRS_SERIALIZE_PART);
    if (mdsize == -1) {
      GE_BREAK(ectx, 0);
      ECRS_deleteNamespace(ectx,
			   cfg,
			   name);
      freePrivateKey(hk);
      return NULL;
    }
    size = sizeof(NBlock) + mdsize;
  } else {
    value = MALLOC(sizeof(Datastore_Value) +
		   size);
    nb = (NBlock*) &value[1];
    nb->type = htonl(N_BLOCK);
    ECRS_serializeMetaData(ectx,
			   meta,
			   (char*)&nb[1],
			   mdsize,
			   ECRS_SERIALIZE_FULL);
  }
  value->size = htonl(sizeof(Datastore_Value) + size);
  value->type = htonl(N_BLOCK);
  value->prio = htonl(priority);
  value->anonymityLevel = htonl(anonymityLevel);
  value->expirationTime = htonll(expiration);
  sock = client_connection_create(ectx, cfg);

  /* publish NBlock */
  memset(&nb->identifier, 0, sizeof(HashCode512));
  getPublicKey(hk,
	       &nb->subspace);
  hash(&nb->subspace,
       sizeof(PublicKey),
       &nb->namespace);
  rootURI = MALLOC(sizeof(URI));
  rootURI->type = sks;
  rootURI->data.sks.namespace = nb->namespace;
  rootURI->data.sks.identifier = *rootEntry;

  nb->rootEntry = *rootEntry;

  GE_ASSERT(ectx,
	    OK == sign(hk,
		       mdsize + 3 * sizeof(HashCode512),
		       &nb->identifier,
		       &nb->signature));
  if (OK != FS_insert(sock, value)) {
    GE_BREAK(ectx, 0);
    FREE(rootURI);
    FREE(value);
    connection_destroy(sock);
    freePrivateKey(hk);
    ECRS_deleteNamespace(ectx, cfg, name);
    return NULL;
  }


  /* publish KNBlocks */
  size += sizeof(KNBlock) - sizeof(NBlock);
  knvalue = MALLOC(sizeof(Datastore_Value) + size);
  *knvalue = *value;
  knvalue->type = htonl(KN_BLOCK);
  knvalue->size = htonl(sizeof(Datastore_Value) + size);
  knb = (KNBlock*) &knvalue[1];
  knb->type = htonl(KN_BLOCK);
  memcpy(&knb->nblock,
	 nb,
	 sizeof(NBlock) + mdsize);

  if (advertisementURI != NULL) {
    keywords = advertisementURI->data.ksk.keywords;
    keywordCount = advertisementURI->data.ksk.keywordCount;
    cpy = MALLOC(size - sizeof(KBlock) - sizeof(unsigned int));
    memcpy(cpy,
	   &knb->nblock,
	   size - sizeof(KBlock) - sizeof(unsigned int));
    for (i=0;i<keywordCount;i++) {
      hash(keywords[i],
	   strlen(keywords[i]),
	   &hc);
      pk = makeKblockKey(&hc);
      getPublicKey(pk,
		   &knb->kblock.keyspace);
      GE_ASSERT(ectx, size - sizeof(KBlock) - sizeof(unsigned int)
		    == sizeof(NBlock) + mdsize);
      ECRS_encryptInPlace(&hc,
			  &knb->nblock,
			  size - sizeof(KBlock) - sizeof(unsigned int));

      GE_ASSERT(ectx, 
		OK == sign(pk,
			   sizeof(NBlock) + mdsize,
			   &knb->nblock,
			   &knb->kblock.signature));
      /* extra check: verify sig */
      freePrivateKey(pk);
      if (OK != FS_insert(sock, knvalue)) {
	GE_BREAK(ectx, 0);
	FREE(rootURI);
	ECRS_deleteNamespace(ectx, cfg, name);
	FREE(cpy);
	FREE(knvalue);
	FREE(value);
	connection_destroy(sock);
	freePrivateKey(hk);
	return NULL;
      }
      /* restore nblock to avoid re-encryption! */
      memcpy(&knb->nblock,
	     cpy, 	
	     size - sizeof(KBlock) - sizeof(unsigned int));
    }
    FREE(cpy);
  }
  FREE(knvalue);
  FREE(value);
  connection_destroy(sock);
  freePrivateKey(hk);

  return rootURI;
}


/**
 * Check if the given namespace exists (locally).
 * @param hc if non-null, also check that this is the
 *   hc of the public key
 * @return OK if the namespace exists, SYSERR if not
 */
int ECRS_testNamespaceExists(struct GE_Context * ectx,
			     struct GC_Configuration * cfg,
			     const char * name,
			     const HashCode512 * hc) {
  struct PrivateKey * hk;
  char * fileName;
  PrivateKeyEncoded * hke;
  char * dst;
  unsigned long long len;
  HashCode512 namespace;
  PublicKey pk;

  /* FIRST: read and decrypt pseudonym! */
  fileName = getPseudonymFileName(ectx,
				  cfg,
				  name);
  if (OK != disk_file_size(ectx,
			   fileName,
			   &len,
			   YES)) {
    FREE(fileName);
    return SYSERR;
  }
  if (len < 2) {
    GE_LOG(ectx, GE_ERROR | GE_BULK | GE_USER,
        _("File `%s' does not contain a pseudonym.\n"),
        fileName);
    FREE(fileName);
    return SYSERR;
  }
  dst = MALLOC(len);
  len = disk_file_read(ectx, fileName, len, dst);
  FREE(fileName);
  hke = (PrivateKeyEncoded*) dst;
  if ( ntohs(hke->len) != len ) {
    GE_LOG(ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("Format of pseudonym `%s' is invalid.\n"),
	   name);
    FREE(hke);
    return SYSERR;
  }
  hk = decodePrivateKey(hke);
  FREE(hke);
  if (hk == NULL)
    return SYSERR;
  getPublicKey(hk,
	       &pk);
  freePrivateKey(hk);
  hash(&pk, sizeof(PublicKey), &namespace);
  if ( (hc == NULL) ||
       (equalsHashCode512(hc,
			  &namespace)))
    return OK;
  else
    return SYSERR;
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
ECRS_addToNamespace(struct GE_Context * ectx,
		    struct GC_Configuration * cfg,
		    const char * name,
		    unsigned int anonymityLevel,
		    unsigned int priority,
		    cron_t expiration,
		    TIME_T creationTime,
		    TIME_T updateInterval,
		    const HashCode512 * thisId,
		    const HashCode512 * nextId,
		    const struct ECRS_URI * dstU,
		    const struct ECRS_MetaData * md) {
  struct ECRS_URI * uri;
  struct ClientServerConnection * sock;
  Datastore_Value * value;
  unsigned int size;
  unsigned int mdsize;
  struct PrivateKey * hk;
  SBlock * sb;
  HashCode512 namespace;
  char * dstURI;
  char * destPos;
  char * fileName;
  PrivateKeyEncoded * hke;
  char * dst;
  unsigned long long len;
  HashCode512 hc;
  int ret;

  /* FIRST: read pseudonym! */
  fileName = getPseudonymFileName(ectx, cfg, name);
  if (OK != disk_file_size(ectx,
			   fileName,
			   &len,
			   YES)) {
    FREE(fileName);
    return NULL;
  }
  if (len < 2) {
    GE_LOG(ectx, GE_ERROR | GE_BULK | GE_USER,
        _("File `%s' does not contain a pseudonym.\n"),
        fileName);
    FREE(fileName);
    return NULL;
  }
  dst = MALLOC(len);
  len = disk_file_read(ectx, fileName, len, dst);
  FREE(fileName);
  hke = (PrivateKeyEncoded*) dst;
  if ( ntohs(hke->len) != len ) {
    GE_LOG(ectx, GE_ERROR | GE_BULK | GE_USER,
        _("Format of pseudonym `%s' is invalid.\n"),
        name);
    FREE(hke);
    return NULL;
  }
  hk = decodePrivateKey(hke);
  FREE(hke);
  if (hk == NULL)
    return NULL;

  /* THEN: construct SBlock */
  dstURI = ECRS_uriToString(dstU);
  mdsize = ECRS_sizeofMetaData(md,
			       ECRS_SERIALIZE_PART);
  size = mdsize + sizeof(SBlock) + strlen(dstURI) + 1;  
  if (size > MAX_SBLOCK_SIZE) {
    size = MAX_SBLOCK_SIZE;
    value = MALLOC(sizeof(Datastore_Value) +
		   size);
    sb = (SBlock*) &value[1];
    sb->type = htonl(S_BLOCK);
    destPos = (char*) &sb[1];
    memcpy(destPos,
	   dstURI,
	   strlen(dstURI) + 1);
    mdsize = size - sizeof(SBlock) - strlen(dstURI) - 1;
    mdsize = ECRS_serializeMetaData(ectx,
				    md,
				    &destPos[strlen(dstURI)+1],
				    mdsize,
				    ECRS_SERIALIZE_PART);
    if (mdsize == -1) {
      GE_BREAK(ectx, 0);
      FREE(dstURI);
      freePrivateKey(hk);
      return NULL;
    }
    size = sizeof(SBlock) + mdsize + strlen(dstURI) + 1;
  } else {
    value = MALLOC(sizeof(Datastore_Value) +
		   size);
    sb = (SBlock*) &value[1];
    sb->type = htonl(S_BLOCK);
    destPos = (char*) &sb[1];
    memcpy(destPos,
	   dstURI,
	   strlen(dstURI) + 1);
    ECRS_serializeMetaData(ectx,
			   md,
			   &destPos[strlen(dstURI)+1],
			   mdsize,
			   ECRS_SERIALIZE_FULL);
  }
  value->size = htonl(sizeof(Datastore_Value) + size);
  value->type = htonl(S_BLOCK);
  value->prio = htonl(priority);
  value->anonymityLevel = htonl(anonymityLevel);
  value->expirationTime = htonll(expiration);

  /* update SBlock specific data */
  sb->creationTime = htonl(creationTime);
  sb->updateInterval = htonl(updateInterval);
  sb->nextIdentifier = *nextId;

  deltaId(thisId,
	  nextId,	
	  &sb->identifierIncrement);
  hash(thisId,
       sizeof(HashCode512),
       &hc);
  getPublicKey(hk,
	       &sb->subspace);
  hash(&sb->subspace,
       sizeof(PublicKey),
       &namespace);
  xorHashCodes(&hc,
	       &namespace,
	       &sb->identifier); /* sb->identifier = primary key in query! */

  uri = MALLOC(sizeof(URI));
  uri->type = sks;
  uri->data.sks.namespace = namespace;
  uri->data.sks.identifier = *thisId;

  ECRS_encryptInPlace(thisId,
		      &sb->creationTime,
		      size
		      - sizeof(unsigned int)
		      - sizeof(Signature)
		      - sizeof(PublicKey)
		      - sizeof(HashCode512));
  /* FINALLY: sign & publish SBlock */
  GE_ASSERT(ectx,
	    OK == sign(hk,
		       size
		       - sizeof(Signature)
		       - sizeof(PublicKey)
		       - sizeof(unsigned int),
		       &sb->identifier,
		       &sb->signature));
  freePrivateKey(hk);

  sock = client_connection_create(ectx, cfg);
  ret = FS_insert(sock, value);
  if (ret != OK) {
    FREE(uri);
    uri = NULL;
  }
  connection_destroy(sock);
  FREE(value);
  FREE(dstURI);

  return uri;
}

struct lNCLS {
  struct GE_Context * ectx;			
  struct GC_Configuration * cfg;
  ECRS_NamespaceInfoCallback cb;
  void * cls;
  int cnt;
};

static int processFile_(const char * name,
			const char * dirName,
			void * cls) {
  struct lNCLS * c = cls;
  struct PrivateKey * hk;
  char * fileName;
  PrivateKeyEncoded * hke;
  char * dst;
  unsigned long long len;
  HashCode512 namespace;
  PublicKey pk;

  fileName = getPseudonymFileName(c->ectx,
				  c->cfg,
				  name);
  if (OK != disk_file_size(c->ectx,
			   fileName,
			   &len,
			   YES)) {
    FREE(fileName);
    return OK;
  }
  if (len < 2) {
    GE_LOG(c->ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("File `%s' does not contain a pseudonym.\n"),
	   fileName);
    FREE(fileName);
    return OK;
  }
  dst = MALLOC(len);
  len = disk_file_read(c->ectx,
		       fileName,
		       len,
		       dst);
  hke = (PrivateKeyEncoded*) dst;
  if ( ntohs(hke->len) != len ) {
    GE_LOG(c->ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("Format of file `%s' is invalid.\n"),
	   fileName);
    FREE(hke);
    FREE(fileName);
    return OK;
  }
  hk = decodePrivateKey(hke);
  FREE(hke);
  if (hk == NULL) {
    GE_LOG(c->ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("Format of file `%s' is invalid.\n"),
	   fileName);
    FREE(fileName);
    GE_BREAK(c->ectx, 0);
    return SYSERR;
  }
  FREE(fileName);
  getPublicKey(hk,
	       &pk);
  freePrivateKey(hk);
  hash(&pk, sizeof(PublicKey), &namespace);
  if (NULL != c->cb) {
    if (OK == c->cb(&namespace,
		    name,
		    c->cls))
      c->cnt++;
    else
      c->cnt = SYSERR;
  } else
    c->cnt++;
  return OK;
}

/**
 * Build a list of all available namespaces
 *
 * @param list where to store the names (is allocated, caller frees)
 * @return SYSERR on error, otherwise the number of pseudonyms in list
 */
int ECRS_listNamespaces(struct GE_Context * ectx,
			struct GC_Configuration * cfg,
			ECRS_NamespaceInfoCallback cb,
			void * cls) {
  char * dirName;
  struct lNCLS myCLS;

  myCLS.cls = cls;
  myCLS.cb = cb;
  myCLS.cnt = 0;
  myCLS.ectx = ectx;
  myCLS.cfg = cfg;
  dirName = getPseudonymFileName(ectx, cfg, "");
  disk_directory_scan(ectx,
		      dirName,
		      &processFile_,
		      &myCLS);
  FREE(dirName);
  return myCLS.cnt;
}



/* end of namespace.c */
