/*
     This file is part of GNUnet.
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
 * @file applications/fs/fsui/collection.c
 * @brief Helper functions for building a collection
 * @author Christian Grothoff
 *
 * A collection is a special kind of namespace.  A collection is the
 * set of files provided by the same user, but unlike namespaces it is
 * automatically managed by the GNUnet UI.  A collection is a single
 * directory in a namespace that is automatically updated each time
 * the user updates or deletes a file.  That is, once the user starts
 * a collection the gnunet-tools will always keep the corresponding
 * directory and namespace entries up-to-date.
 *
 * A good way of thinking about a collection is a lazy user's
 * namespace.
 */

#include "platform.h"
#include "gnunet_blockstore.h"
#include "gnunet_collection_lib.h"
#include "gnunet_util_crypto.h"

/**
 * Entry in the state-DB that caches the current
 * collection.
 */
#define COLLECTION "collection"

/**
 * How long does a collection advertisement live?
 */
#define COLLECTION_ADV_LIFETIME (12 * cronMONTHS)

/**
 * @brief information about a collection
 */
typedef struct CollectionData {
  DataContainer hdr;
  /**
   * Has this collection changed since the last publication? (NBO)
   */
  int changed;
  /**
   * What is the last ID for the publication?
   */
  HashCode512 lastId;
  /**
   * What is the next ID for the publication?
   */
  HashCode512 nextId;
  /**
   * What is the update interval? (NBO!)
   */
  TIME_T updateInterval;
  /**
   * What is the update interval? (NBO!)
   */
  TIME_T lastPublication;
  /**
   * Anonymity level for the collection. (NBO)
   */
  unsigned int anonymityLevel;
  /**
   * Name of the collection
   */
  char name[1];
  /* the name is followed by a
     serialized ECRS directory */
} CollectionData;

static CollectionData * collectionData;

/**
 * Start collection.
 *
 * @param updateInterval of ECRS_SBLOCK_UPDATE_NONE
 *        means to update _immediately_ on any change,
 *        wherease ECRS_SBLOCK_UPDATE_SPORADIC means
 *        to publish updates when the CO_Context
 *        is destroyed (i.e. on exit from the UI).
 */
int CO_startCollection(struct GE_Context * ectx,
		       struct GC_Configuration * cfg,
		       unsigned int anonymityLevel,
		       unsigned int prio,
		       TIME_T updateInterval,
		       const char * name,
		       const struct ECRS_MetaData * meta) {
  struct ECRS_URI * advertisement;
  struct ECRS_URI * rootURI;
  HashCode512 nextId;
  TIME_T now;
  CollectionData * cd;
  unsigned long long dirLen;
  char * dirData;
  struct ECRS_MetaData * dirMeta;

  CO_stopCollection(ectx, cfg); /* cancel old collection */
  GE_ASSERT(ectx, name != NULL);
  advertisement = ECRS_parseCharKeywordURI(ectx,
					   COLLECTION);
  GE_ASSERT(ectx, advertisement != NULL);
  TIME(&now);
  makeRandomId(&nextId);
  rootURI = ECRS_createNamespace(ectx,
				 cfg,
				 name,
				 meta,
				 anonymityLevel,
				 prio,
				 now + COLLECTION_ADV_LIFETIME,
				 advertisement,
				 &nextId);
  if (rootURI == NULL) {
    ECRS_freeUri(advertisement);
    return SYSERR;
  }
  ECRS_freeUri(advertisement);
  ECRS_freeUri(rootURI);
  dirMeta = ECRS_dupMetaData(meta);
  GE_ASSERT(ectx, OK == ECRS_createDirectory(ectx,
					     &dirData,
					     &dirLen,
					     0,
					     NULL,
					     dirMeta));
  ECRS_freeMetaData(dirMeta);
  cd = MALLOC(sizeof(CollectionData) + strlen(name) + dirLen);
  collectionData = cd;
  cd->hdr.size = ntohl(sizeof(CollectionData) + strlen(name));
  makeRandomId(&cd->lastId);
  cd->nextId = nextId;
  cd->updateInterval = htonll(updateInterval);
  cd->anonymityLevel = htonl(anonymityLevel);
  cd->changed = htonl(NO);
  strcpy(cd->name, name);
  memcpy(&cd->name[strlen(name)+1],
	 dirData,
	 dirLen);
  FREE(dirData);
  return OK;
}

/**
 * Stop collection.
 *
 * @return OK on success, SYSERR if no collection is active
 */
int CO_stopCollection(struct GE_Context * ectx,
		      struct GC_Configuration * cfg) {
  if (collectionData == NULL)
    return SYSERR;
  ECRS_deleteNamespace(ectx,
		       cfg,
		       collectionData->name);
  FREE(collectionData);
  collectionData = NULL;
  return OK;
}

/**
 * Are we using a collection?
 *
 * @return NULL if there is no collection, otherwise its name
 */
const char * CO_getCollection(struct GE_Context * ectx,
			      struct GC_Configuration * cfg) {
  if (collectionData == NULL)
    return NULL;
  return &collectionData->name[0];
}

/**
 * Upload an update of the current collection information to the
 * network now.  The function has no effect if the collection has not
 * changed since the last publication.  If we are currently not
 * collecting, this function does nothing.
 *
 * Note that clients typically don't have to call this
 * function explicitly.  CO will call the function on
 * exit (for sporadically updated collections), on any
 * change to the collection (for immediately updated
 * content) or when the publication time has arrived
 * (for periodically updated collections).
 *
 * However, clients may want to call this function if
 * explicit publication of an update at another
 * time is desired.
 */
void CO_publishCollectionNow(struct GE_Context * ectx,
			     struct GC_Configuration * cfg,
			     unsigned int prio) {
  TIME_T now;
  struct ECRS_URI * uri;
  struct ECRS_URI * directoryURI;
  struct ECRS_MetaData *  metaData;
  unsigned long long dirLen;
  char * tmpName;
  int fd;

  if (collectionData == NULL)
    return;
  if (ntohl(collectionData->changed) == NO)
    return;

  TIME(&now);
  if ( (ntohl(collectionData->updateInterval) != ECRS_SBLOCK_UPDATE_NONE) &&
       (ntohl(collectionData->updateInterval) != ECRS_SBLOCK_UPDATE_SPORADIC) &&
       (ntohl(collectionData->lastPublication) + ntohl(collectionData->updateInterval) < now) )
    return;
  if ( (ntohl(collectionData->updateInterval) != ECRS_SBLOCK_UPDATE_NONE) &&
       (ntohl(collectionData->updateInterval) != ECRS_SBLOCK_UPDATE_SPORADIC) ) {
    HashCode512 delta;

    deltaId(&collectionData->nextId,
	    &collectionData->lastId,
	    &delta);
    collectionData->lastId = collectionData->nextId;
    addHashCodes(&collectionData->nextId,
		 &delta,
		 &collectionData->nextId);
  } else {
    collectionData->lastId = collectionData->nextId;
    makeRandomId(&collectionData->nextId);
  }
  tmpName = STRDUP("/tmp/gnunet-collectionXXXXXX");
  fd = mkstemp(tmpName);
  if (fd == -1) {
    GE_LOG_STRERROR(ectx,
		    GE_ERROR | GE_ADMIN | GE_BULK,
		    "mkstemp");
    FREE(tmpName);
    return;
  }
  dirLen = ntohl(collectionData->hdr.size) - sizeof(CollectionData) - strlen(collectionData->name);
  if (-1 == WRITE(fd, &collectionData->name[strlen(collectionData->name)+1], dirLen)) {
    GE_LOG_STRERROR(ectx,
		    GE_ERROR | GE_ADMIN | GE_BULK,
		    "write");
    FREE(tmpName);
    return;
  }
  CLOSE(fd);
  if (OK != ECRS_uploadFile(ectx,
			    cfg,
			    tmpName,
			    NO, /* indexing */
			    ntohl(collectionData->anonymityLevel),
			    prio,
			    now + COLLECTION_ADV_LIFETIME,
			    NULL,
			    NULL,
			    NULL,
			    NULL,
			    &directoryURI)) {
    UNLINK(tmpName);
    FREE(tmpName);
    return;
  }
  UNLINK(tmpName);
  FREE(tmpName);
  metaData = NULL;
  GE_ASSERT(ectx, OK == ECRS_listDirectory(ectx,
					   &collectionData->name[strlen(collectionData->name)+1],
					   dirLen,
					   &metaData,
					   NULL,
					   NULL));
  uri = ECRS_addToNamespace(ectx,
			    cfg,
			    collectionData->name,
			    ntohl(collectionData->anonymityLevel),
			    prio,
			    now + COLLECTION_ADV_LIFETIME,
			    now,
			    ntohl(collectionData->updateInterval),
			    &collectionData->lastId,
			    &collectionData->nextId,
			    directoryURI,
			    metaData);
  if (uri != NULL) {
    collectionData->lastPublication = htonl(now);
    collectionData->changed = htonl(NO);
    ECRS_freeUri(uri);
  }
  ECRS_freeMetaData(metaData);
}

struct CCcls {
  unsigned int count;
  ECRS_FileInfo * fis;
};

static int collectCallback(const ECRS_FileInfo * fi,
			   const HashCode512 * key,
			   int isRoot,
			   void * closure) {
  struct CCcls * cls = closure;
  GROW(cls->fis,
       cls->count,
       cls->count+1);
  cls->fis[cls->count-1].uri = ECRS_dupUri(fi->uri);
  cls->fis[cls->count-1].meta = ECRS_dupMetaData(fi->meta);
  return OK;
}

/**
 * If we are currently building a collection, publish
 * the given file information in that collection.
 * If we are currently not collecting, this function
 * does nothing.
 *
 * Note that clients typically don't have to call this
 * function explicitly -- by using the CO library it
 * should be called automatically by CO code whenever
 * needed.  However, the function maybe useful if you're
 * inserting files using libECRS directly or need other
 * ways to explicitly extend a collection.
 */
void CO_publishToCollection(struct GE_Context * ectx,
			    struct GC_Configuration * cfg,
			    const ECRS_FileInfo * fi,
			    unsigned int prio) {
  CollectionData * collectionData;
  unsigned long long dirLen;
  char * dirData;
  struct ECRS_MetaData * metaData;
  struct CCcls cls;
  int i;

  if (collectionData == NULL)
    return;
  if ((ECRS_isKeywordUri(fi->uri))) {
    GE_BREAK(ectx, 0);
    return;
  }
  dirLen = ntohl(collectionData->hdr.size) - strlen(collectionData->name) - sizeof(CollectionData);
  cls.count = 0;
  cls.fis = NULL;
  GE_ASSERT(ectx, OK ==
	    ECRS_listDirectory(ectx,
			       &collectionData->name[strlen(collectionData->name)+1],
			       dirLen,
			       &metaData,
			       &collectCallback,
			       &cls));
  collectCallback(fi,
		  NULL,
		  NO,
		  &cls);
  dirData = NULL;
  GE_ASSERT(ectx, OK ==
	    ECRS_createDirectory(ectx,
				 &dirData,
				 &dirLen,
				 cls.count,
				 cls.fis,
				 metaData));
  ECRS_freeMetaData(metaData);
  for (i=0;i<cls.count;i++) {
    ECRS_freeUri(cls.fis[i].uri);
    ECRS_freeMetaData(cls.fis[i].meta);
  }
  GROW(cls.fis,
       cls.count,
       0);
  REALLOC(collectionData,
	  sizeof(CollectionData) + strlen(collectionData->name) + dirLen);
  memcpy(&collectionData->name[strlen(collectionData->name)+1],
	 dirData,
	 dirLen);
  FREE(dirData);
  collectionData->changed = htonl(YES);
  if (ntohll(collectionData->updateInterval) == ECRS_SBLOCK_UPDATE_NONE)
    CO_publishCollectionNow(ectx, cfg, prio);
}



/* end of collection.c */
