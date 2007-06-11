/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/namespace/namespace_info.c
 * @brief keeping track of namespaces.  This module
 *  is supposed to keep track of other namespaces (and
 *  their advertisments), as well as of our own namespaces
 *  and the updateable content stored therein.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_namespace_lib.h"
#include "gnunet_util_crypto.h"

#define NS_DIR "data" DIR_SEPARATOR_STR "namespaces" DIR_SEPARATOR_STR
#define NS_UPDATE_DIR "data" DIR_SEPARATOR_STR "namespace-updates" DIR_SEPARATOR_STR
#define NS_ROOTS "data" DIR_SEPARATOR_STR "namespace-root" DIR_SEPARATOR_STR

struct DiscoveryCallback {
  struct DiscoveryCallback * next;
  NS_NamespaceIterator callback;
  void * closure;
};

static struct DiscoveryCallback * head;

static struct MUTEX * lock;

/**
 * Internal notification about new tracked URI.
 */
static void internal_notify(const char * name,
			    const HashCode512 * id,
			    const struct ECRS_MetaData * md,
			    int rating) {
  struct DiscoveryCallback * pos;

  MUTEX_LOCK(lock);
  pos = head;
  while (pos != NULL) {
    pos->callback(pos->closure,
		  name,
		  id,
		  md,
		  rating);
    pos = pos->next;
  }
  MUTEX_UNLOCK(lock);
}

static void writeNamespaceInfo(struct GE_Context * ectx,
			       struct GC_Configuration * cfg,
			       const char * namespaceName,
			       const struct ECRS_MetaData * meta,
			       int ranking) {
  unsigned int size;
  unsigned int tag;
  char * buf;
  char * fn;
  char * fnBase;


  GC_get_configuration_value_filename(cfg,
				      "GNUNET",
				      "GNUNET_HOME",
				      GNUNET_HOME_DIRECTORY,
				      &fnBase);
  fn = MALLOC(strlen(fnBase) +
	      strlen(NS_DIR) +
	      strlen(namespaceName) +
	      6);
  strcpy(fn, fnBase);
  strcat(fn, DIR_SEPARATOR_STR);
  strcat(fn, NS_DIR);
  disk_directory_create(ectx, fn);
  strcat(fn, DIR_SEPARATOR_STR);
  strcat(fn, namespaceName);
  FREE(fnBase);

  size = ECRS_sizeofMetaData(meta,
			     ECRS_SERIALIZE_FULL);
  tag = size + sizeof(int);
  buf = MALLOC(tag);
  ((int *) buf)[0] = htonl(ranking); /* ranking */
  GE_ASSERT(ectx,
	    size == ECRS_serializeMetaData(ectx,
					   meta,
					   &buf[sizeof(int)],
					   size,
					   ECRS_SERIALIZE_FULL));
  disk_file_write(ectx,
		  fn,
		  buf,
		  tag,
		  "660");
  FREE(fn);
  FREE(buf);
}

static int readNamespaceInfo(struct GE_Context * ectx,
			     struct GC_Configuration * cfg,
			     const char * namespaceName,
			     struct ECRS_MetaData ** meta,
			     int * ranking) {
  unsigned long long len;
  unsigned int size;
  char * buf;
  char * fn;
  char * fnBase;

  *meta = NULL;
  GC_get_configuration_value_filename(cfg,
				      "GNUNET",
				      "GNUNET_HOME",
				      GNUNET_HOME_DIRECTORY,
				      &fnBase);
  fn = MALLOC(strlen(fnBase) +
	      strlen(NS_DIR) +
	      strlen(namespaceName) +
	      6);
  strcpy(fn, fnBase);
  strcat(fn, DIR_SEPARATOR_STR);
  strcat(fn, NS_DIR);
  disk_directory_create(ectx,
			fn);
  strcat(fn, DIR_SEPARATOR_STR);
  strcat(fn, namespaceName);
  FREE(fnBase);

  if ( (OK != disk_file_test(ectx,
			     fn)  ||
	(OK != disk_file_size(ectx,
			      fn,
			      &len,
			      YES)) ) ) {
    FREE(fn);
    return SYSERR;
  }
  if (len <= sizeof(int)) {
    FREE(fn);
    return SYSERR;
  }
  if (len > 16 * 1024 * 1024) {
    /* too big, must be invalid! remove! */
    GE_BREAK(ectx, 0);
    UNLINK(fn);
    FREE(fn);
    return SYSERR;
  }
  buf = MALLOC(len);
  if (len != disk_file_read(ectx,
			    fn,
			    len,
			    buf)) {
    FREE(buf);
    FREE(fn);
    return SYSERR;
  }

  size = len - sizeof(int);
  *ranking = ntohl(((int *) buf)[0]);
  *meta = ECRS_deserializeMetaData(ectx,
				   &buf[sizeof(int)],
				   size);
  if ((*meta) == NULL) {
    /* invalid data! remove! */
    GE_BREAK(ectx, 0);
    UNLINK(fn);
    FREE(buf);
    FREE(fn);
    return SYSERR;
  }
  FREE(fn);
  FREE(buf);
  return OK;
}
					

/**
 * Create a new namespace (and publish an advertismement).
 * This function is synchronous, but may block the system
 * for a while since it must create a public-private key pair!
 *
 * @param meta meta-data about the namespace (maybe NULL)
 * @return namespace root URI on success, NULL on error (namespace already exists)
 */
struct ECRS_URI *
NS_createNamespace(struct GE_Context * ectx,
		   struct GC_Configuration * cfg,		
		   unsigned int anonymityLevel,
		   unsigned int insertPriority,
		   cron_t insertExpiration,
		   const char * namespaceName,
		   const struct ECRS_MetaData * meta,
		   const struct ECRS_URI * advertisementURI,
		   const HashCode512 * rootEntry) {
  struct ECRS_URI * ret;

  ret = ECRS_createNamespace(ectx,
			     cfg,
			     namespaceName,
			     meta,
			     anonymityLevel,
			     insertPriority,
			     insertExpiration,
			     advertisementURI,
			     rootEntry);
  /* store binding of namespaceName to 'meta' in state DB! */
  if (ret != NULL) {
    HashCode512 id;
    char * name;
 
    NS_setNamespaceRoot(ectx,
			cfg,
			ret);
    ECRS_getNamespaceId(ret,
			&id);
    name = ECRS_getNamespaceName(&id);
    writeNamespaceInfo(ectx,
		       cfg,
		       name,
		       meta,
		       0);
    internal_notify(namespaceName,
		    &id,
		    meta,
		    0);
    FREE(name);
  }
  return ret;
}


/**
 * Delete a local namespace.
 *
 * @return OK on success, SYSERR on error
 */
int NS_deleteNamespace(struct GE_Context * ectx,
		       struct GC_Configuration * cfg,
		       const char * namespaceName) {
  int ret;
  char * tmp;
  char * fn;

  ret = ECRS_deleteNamespace(ectx, cfg, namespaceName);
  GC_get_configuration_value_filename(cfg,
				      "GNUNET",
				      "GNUNET_HOME",
				      GNUNET_HOME_DIRECTORY,
				      &tmp);
  fn = MALLOC(strlen(tmp) + strlen(NS_UPDATE_DIR) +
	      strlen(namespaceName) + 20);
  strcpy(fn, tmp);
  FREE(tmp);
  strcat(fn, DIR_SEPARATOR_STR);
  strcat(fn, NS_UPDATE_DIR);
  strcat(fn, namespaceName);
  strcat(fn, DIR_SEPARATOR_STR);
  disk_directory_remove(ectx, fn);
  FREE(fn);
  return ret;
}



/**
 * Change the ranking of a (non-local) namespace.
 *
 * @param ns the name of the namespace, as obtained
 *  from ECRS_getNamespaceName
 * @param delta by how much should the rating be
 *  changed?
 * @return new rating of the namespace
 */
int NS_rankNamespace(struct GE_Context * ectx,
		     struct GC_Configuration * cfg,
		     const char * ns,
		     int delta) {
  struct ECRS_MetaData * meta;
  int ret;
  int ranking;

  ret = readNamespaceInfo(ectx,
			  cfg,
			  ns,
			  &meta,
			  &ranking);
  if (ret == SYSERR) {
    ranking = 0;
    meta = ECRS_createMetaData();
  }
  ranking += delta;
  writeNamespaceInfo(ectx,
		     cfg,
		     ns,
		     meta,
		     ranking);
  ECRS_freeMetaData(meta);
  return ranking;
}

typedef struct {
  NS_NamespaceIterator iterator;
  void * closure;
  struct GE_Context * ectx;
  struct GC_Configuration * cfg;
} LNClosure;

static int localListNamespaceHelper(const HashCode512 * nsid,
				    const char * name,
				    void * cls) {
  LNClosure * c = cls;
  int ret;
  struct ECRS_MetaData * meta;
  int rating;

  meta = NULL;
  rating = 0;
  readNamespaceInfo(c->ectx,
		    c->cfg,
		    name,
		    &meta,
		    &rating);
  if (meta == NULL)
    meta = ECRS_createMetaData();
  if (c->iterator != NULL) {
    ret = c->iterator(c->closure,
		      name,
		      nsid,
		      meta,
		      rating);
  } else
    ret = OK;
  ECRS_freeMetaData(meta);
  return ret;
}

static int listNamespaceHelper(const char * fn,
			       const char * dirName,
			       void * cls) {
  LNClosure * c = cls;
  int ret;
  struct ECRS_MetaData * meta;
  int rating;
  HashCode512 id;

  if (OK != enc2hash(fn,
		     &id))
    return OK; /* invalid name */
  if (OK != readNamespaceInfo(c->ectx,
			      c->cfg,
			      fn,
			      &meta,
			      &rating))
    return OK; /* ignore entry */
  if (c->iterator != NULL) {
    ret = c->iterator(c->closure,
		      fn,
		      &id,
		      meta,
		      rating);
  } else
    ret = OK;
  ECRS_freeMetaData(meta);
  return OK;
}

/**
 * List all available (local and non-local) namespaces.
 *
 */
int NS_listNamespaces(struct GE_Context * ectx,
		      struct GC_Configuration * cfg,
		      NS_NamespaceIterator iterator,
		      void * closure) {
  LNClosure cls;
  char * fn;
  char * fnBase;
  int ret1;
  int ret2;

  cls.iterator = iterator;
  cls.closure = closure;
  cls.ectx = ectx;
  cls.cfg = cfg;
  ret1 = ECRS_listNamespaces(ectx,
			     cfg,
			     &localListNamespaceHelper,
			     &cls);
  if (ret1 == -1)
    return ret1;
  GC_get_configuration_value_filename(cfg,
				      "GNUNET",
				      "GNUNET_HOME",
				      GNUNET_HOME_DIRECTORY,
				      &fnBase);
  fn = MALLOC(strlen(fnBase) +
	      strlen(NS_DIR) +
	      4);
  strcpy(fn, fnBase);
  FREE(fnBase);
  strcat(fn, DIR_SEPARATOR_STR);
  strcat(fn, NS_DIR);
  disk_directory_create(ectx, fn);
  ret2 = disk_directory_scan(ectx,
			     fn,
			     &listNamespaceHelper,
			     &cls);
  FREE(fn);
  if (ret2 == -1)
    return ret2;
  return ret1 + ret2;
}

/**
 * Get the filename (or directory name) for the given
 * namespace and content identifier.
 * @param lastId maybe NULL
 */
static char * getUpdateDataFilename(struct GE_Context * ectx,
				    struct GC_Configuration * cfg,
				    const char * nsname,
				    const HashCode512 * lastId) {
  char * tmp;
  char * ret;

  GC_get_configuration_value_filename(cfg,
				      "GNUNET",
				      "GNUNET_HOME",
				      GNUNET_HOME_DIRECTORY,
				      &tmp);
  ret = MALLOC(strlen(tmp) + strlen(NS_UPDATE_DIR) +
	       strlen(nsname) + sizeof(EncName) + 20);
  strcpy(ret, tmp);
  FREE(tmp);
  strcat(ret, DIR_SEPARATOR_STR);
  strcat(ret, NS_UPDATE_DIR);
  strcat(ret, nsname);
  strcat(ret, DIR_SEPARATOR_STR);
  disk_directory_create(ectx, ret);
  if (lastId != NULL) {
    EncName enc;

    hash2enc(lastId, &enc);
    strcat(ret, (char*) &enc);
  }
  return ret;
}

struct UpdateData {
  TIME_T updateInterval;
  TIME_T lastPubTime;
  HashCode512 nextId;
  HashCode512 thisId;
};

/**
 * Read content update information about content
 * published in the given namespace under 'lastId'.
 *
 * @param fi maybe NULL
 * @return OK if update data was found, SYSERR if not.
 */
static int readUpdateData(struct GE_Context * ectx,
			  struct GC_Configuration * cfg,
			  const char * nsname,
			  const HashCode512 * lastId,
			  HashCode512 * nextId,
			  ECRS_FileInfo * fi,
			  TIME_T * updateInterval,
			  TIME_T * lastPubTime) {
  char * fn;
  struct UpdateData * buf;
  char * uri;
  unsigned long long size;
  size_t pos;

  fn = getUpdateDataFilename(ectx,
			     cfg,
			     nsname,
			     lastId);
  if (OK != disk_file_size(ectx,
			   fn,
			   &size,
			   YES)) {
    FREE(fn);
    return SYSERR;
  }
  if ( (size == 0) ||
       (size <= sizeof(struct UpdateData)) ||
       (size > 1024 * 1024 * 16) ) {
    FREE(fn);
    return SYSERR;
  }

  buf = MALLOC(size);
  if (size != disk_file_read(ectx,
			     fn,
			     size,	
			     buf)) {
    FREE(buf);
    FREE(fn);
    return SYSERR;
  }
  FREE(fn);
  if ( ! equalsHashCode512(lastId,
			   &buf->thisId)) {
    FREE(buf);
    return SYSERR;
  }
  uri = (char*) &buf[1];
  size -= sizeof(struct UpdateData);
  pos = 0;
  while ( (pos < size) &&
	  (uri[pos] != '\0') )
    pos++;
  pos++;
  size -= pos;
  if (size == 0) {
    FREE(buf);
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  if (fi != NULL) {
    fi->meta = ECRS_deserializeMetaData(ectx,
					&uri[pos],
					size);
    if (fi->meta == NULL) {
      FREE(buf);
      GE_BREAK(ectx, 0);
      return SYSERR;
    }
    fi->uri = ECRS_stringToUri(ectx,
			       uri);
    if (fi->uri == NULL) {
      ECRS_freeMetaData(fi->meta);
      fi->meta = NULL;
      FREE(buf);
      GE_BREAK(ectx, 0);
      return SYSERR;
    }
  }
  if (updateInterval != NULL)
    *updateInterval = ntohl(buf->updateInterval);
  if (lastPubTime != NULL)
    *lastPubTime = ntohl(buf->lastPubTime);
  if (nextId != NULL)
    *nextId = buf->nextId;
  FREE(buf);
  return OK;
}

/**
 * Write content update information.
 */
static int writeUpdateData(struct GE_Context * ectx,
			   struct GC_Configuration * cfg,
			   const char * nsname,
			   const HashCode512 * thisId,
			   const HashCode512 * nextId,
			   const ECRS_FileInfo * fi,
			   const TIME_T updateInterval,
			   const TIME_T lastPubTime) {
  char * fn;
  char * uri;
  size_t metaSize;
  size_t size;
  struct UpdateData * buf;

  uri = ECRS_uriToString(fi->uri);
  metaSize = ECRS_sizeofMetaData(fi->meta,
				 ECRS_SERIALIZE_FULL);
  size = sizeof(struct UpdateData) + metaSize + strlen(uri) + 1;
  buf = MALLOC(size);
  buf->nextId = *nextId;
  buf->thisId = *thisId;
  buf->updateInterval = htonl(updateInterval);
  buf->lastPubTime = htonl(lastPubTime);
  memcpy(&buf[1],
	 uri,
	 strlen(uri)+1);
  GE_ASSERT(ectx,
	    metaSize ==
	    ECRS_serializeMetaData(ectx,
				   fi->meta,
				   &((char*)&buf[1])[strlen(uri)+1],
				   metaSize,
				   ECRS_SERIALIZE_FULL));
  FREE(uri);
  fn = getUpdateDataFilename(ectx,
			     cfg,
			     nsname,
			     thisId);
  disk_file_write(ectx,
		  fn,
		  buf,
		  size,
		  "400"); /* no editing, just deletion */
  FREE(fn);
  FREE(buf);
  return OK;
}
			

/**
 * Compute the next ID for peridodically updated content.
 * @param updateInterval MUST be a peridic interval (not NONE or SPORADIC)
 * @param thisId MUST be known to NAMESPACE
 * @return OK on success, SYSERR on error
 */
int NS_computeNextId(struct GE_Context * ectx,
		     struct GC_Configuration * cfg,
		     const char * name,
		     const HashCode512 * lastId,
		     const HashCode512 * thisId,
		     TIME_T updateInterval,
		     HashCode512 * nextId) {
  HashCode512 delta;
  cron_t now;
  TIME_T tnow;
  TIME_T lastTime;
  TIME_T ui;

  if ( (updateInterval == ECRS_SBLOCK_UPDATE_SPORADIC) ||
       (updateInterval == ECRS_SBLOCK_UPDATE_NONE) )
    return SYSERR;

  if (OK != readUpdateData(ectx,
			   cfg,
			   name,
			   lastId,
			   NULL,
			   NULL,
			   &ui,
			   &lastTime))
    return SYSERR;
  deltaId(lastId,
	  thisId,
	  &delta);	
  now = get_time();
  TIME(&tnow);
  *nextId = *thisId;
  while (lastTime < tnow + updateInterval/2) {
    lastTime += updateInterval;
    addHashCodes(nextId,
		 &delta,
		 nextId);
  }
  return OK;
}


/**
 * Add an entry into a namespace (also for publishing
 * updates).
 *
 * @param name in which namespace to publish
 * @param updateInterval the desired frequency for updates
 * @param lastId the ID of the last value (maybe NULL)
 * @param thisId the ID of the update (maybe NULL)
 * @param nextId the ID of the next update (maybe NULL)
 * @param dst to which URI should the namespace entry refer?
 * @param md what meta-data should be associated with the
 *        entry?
 * @param uri set to the resulting URI
 */
struct ECRS_URI *
NS_addToNamespace(struct GE_Context * ectx,
		  struct GC_Configuration * cfg,
		  unsigned int anonymityLevel,
		  unsigned int insertPriority,
		  cron_t insertExpiration,
		  const char * name,
		  TIME_T updateInterval,
		  const HashCode512 * lastId,
		  const HashCode512 * thisId,
		  const HashCode512 * nextId,
		  const struct ECRS_URI * dst,
		  const struct ECRS_MetaData * md) {
  TIME_T creationTime;
  HashCode512 nid;
  HashCode512 tid;
  TIME_T now;
  TIME_T lastTime;
  TIME_T lastInterval;
  ECRS_FileInfo fi;
  char * old;
  struct ECRS_URI * uri;

  /* computation of IDs of update(s).  Not as terrible as
     it looks, just enumerating all of the possible cases
     of periodic/sporadic updates and how IDs are computed. */
  creationTime = TIME(&now);
  if (updateInterval != ECRS_SBLOCK_UPDATE_NONE) {
    if ( (lastId != NULL) &&
	 (OK == readUpdateData(ectx,
			       cfg,
			       name,
			       lastId,
			       &tid,
			       NULL,
			       &lastInterval,
			       &lastTime)) ) {
      if (lastInterval != updateInterval) {
	GE_LOG(ectx, GE_WARNING | GE_BULK | GE_USER,
	    _("Publication interval for periodic publication changed."));
      }
      /* try to compute tid and/or
	 nid based on information read from lastId */

      if (updateInterval != ECRS_SBLOCK_UPDATE_SPORADIC) {
	HashCode512 delta;

	deltaId(lastId,
		&tid,
		&delta);	

	creationTime = lastTime + updateInterval;
	while (creationTime < now - updateInterval) {
	  creationTime += updateInterval;
	  addHashCodes(&tid,
		       &delta,
		       &tid);
	}
	if (creationTime > get_time() + 7 * cronDAYS) {
	  GE_LOG(ectx, GE_WARNING | GE_BULK | GE_USER,
	      _("Publishing update for periodically updated "
		"content more than a week ahead of schedule.\n"));
	}
	if (thisId != NULL)
	  tid = *thisId; /* allow override! */
	addHashCodes(&tid,
		     &delta,
		     &nid);
	if (nextId != NULL)
	  nid = *nextId; /* again, allow override */
      } else {
	/* sporadic ones are unpredictable,
	   tid has been obtained from IO, pick random nid if
	   not specified */
	if (thisId != NULL)
	  tid = *thisId; /* allow user override */	
	if (nextId == NULL) {
	  makeRandomId(&nid);
	} else {
	  nid = *nextId;
	}
      }
    } else { /* no previous ID found or given */
      if (nextId == NULL) {
	/* no previous block found and nextId not specified;
	   pick random nid */
	makeRandomId(&nid);
      } else {
	nid = *nextId;
      }
      if (thisId != NULL) {
	tid = *thisId;
      } else {
	makeRandomId(&tid);
      }
    }
  } else {
    if (thisId != NULL) {
      nid = tid = *thisId;
    } else {
      makeRandomId(&tid);
      nid = tid;
    }
  }
  uri = ECRS_addToNamespace(ectx,
			    cfg,
			    name,
			    anonymityLevel,
			    insertPriority,
			    insertExpiration,
			    creationTime,
			    updateInterval,
			    &tid,
			    &nid,
			    dst,
			    md);
  if ( (uri != NULL) &&
       (dst != NULL) ) {
    fi.uri = ECRS_dupUri(dst);
    fi.meta = (struct ECRS_MetaData*) md;
    writeUpdateData(ectx,
		    cfg,
		    name,
		    &tid,
		    &nid,
		    &fi,
		    updateInterval,
		    creationTime);
    ECRS_freeUri(fi.uri);
    if (lastId != NULL) {
      old = getUpdateDataFilename(ectx,
				  cfg,
				  name,
				  lastId);
      UNLINK(old);
      FREE(old);
    }
  }
  return uri;
}

struct lNCC {
  const char * name;
  NS_UpdateIterator it;
  void * closure;
  int cnt;
  struct GE_Context * ectx;
  struct GC_Configuration * cfg;
};

static int lNCHelper(const char * fil,
		     const char * dir,
		     void * ptr) {
  struct lNCC * cls = ptr;
  ECRS_FileInfo fi;
  HashCode512 lastId;
  HashCode512 nextId;
  TIME_T pubFreq;
  TIME_T lastTime;
  TIME_T nextTime;
  TIME_T now;

  if (OK != enc2hash(fil,
		     &lastId)) {
    GE_BREAK(cls->ectx, 0);
    return OK;
  }
  fi.uri = NULL;
  fi.meta = NULL;
  if (OK != readUpdateData(cls->ectx,
			   cls->cfg,
			   cls->name,
			   &lastId,
			   &nextId,
			   &fi,
			   &pubFreq,
			   &lastTime)) {
    GE_BREAK(cls->ectx, 0);
    return OK;
  }
  cls->cnt++;
  if (pubFreq == ECRS_SBLOCK_UPDATE_SPORADIC) {
    nextTime = 0;
  } else {
    TIME(&now);
    nextTime = lastTime;
    if ( (nextTime + pubFreq < now) &&
	    (nextTime + pubFreq > nextTime) )
      nextTime += pubFreq * ((now - nextTime) / pubFreq);
  }
  if (cls->it != NULL) {
    if (OK != cls->it(cls->closure,
		      &fi,
		      &lastId,
		      &nextId,
		      pubFreq,
		      nextTime)) {
      ECRS_freeUri(fi.uri);
      ECRS_freeMetaData(fi.meta);
      return SYSERR;
    }
  }
  ECRS_freeUri(fi.uri);
  ECRS_freeMetaData(fi.meta);
  return OK;
}

/**
 * List all updateable content in a given namespace.
 */
int NS_listNamespaceContent(struct GE_Context * ectx,
			    struct GC_Configuration * cfg,
			    const char * name,
			    NS_UpdateIterator iterator,
			    void * closure) {
  struct lNCC cls;
  char * dirName;

  cls.name = name;
  cls.it = iterator;
  cls.closure = closure;
  cls.cnt = 0;
  cls.ectx = ectx;
  cls.cfg = cfg;
  dirName = getUpdateDataFilename(ectx,
				  cfg,
				  name,
				  NULL);
  disk_directory_create(ectx, dirName);
  if (SYSERR == disk_directory_scan(ectx,
				    dirName,
				    &lNCHelper,
				    &cls)) {
    FREE(dirName);
    return SYSERR;
  }
  FREE(dirName);
  return cls.cnt;
}

static int mergeMeta(EXTRACTOR_KeywordType type,
		     const char * data,
		     void * cls) {
  struct ECRS_MetaData * meta = cls;
  ECRS_addToMetaData(meta,
		     type,
		     data);
  return OK;
}

/**
 * Add a namespace to the set of known namespaces.
 * For all namespace advertisements that we discover
 * NAMESPACE should automatically call this function.
 *
 * @param ns the namespace identifier
 */
void NS_addNamespaceInfo(struct GE_Context * ectx,
			 struct GC_Configuration * cfg,
			 const struct ECRS_URI * uri,
			 const struct ECRS_MetaData * meta) {
  char * name;
  int ranking;
  struct ECRS_MetaData * old;
  HashCode512 id;

  if (! ECRS_isNamespaceUri(uri)) {
    GE_BREAK(ectx, 0);
    return;
  }
  ECRS_getNamespaceId(uri,
		      &id);
  name = ECRS_getNamespaceName(&id);
  if (name == NULL) {
    GE_BREAK(ectx, 0);
    return;
  }
  ranking = 0;
  if (OK == readNamespaceInfo(ectx,
			      cfg,
			      name,
			      &old,
			      &ranking)) {
    ECRS_getMetaData(meta,
		     &mergeMeta,
		     old);
    writeNamespaceInfo(ectx,
		       cfg,
		       name,
		       old,
		       ranking);
    ECRS_freeMetaData(old);
  } else {
    writeNamespaceInfo(ectx,
		       cfg,
		       name,
		       meta,
		       ranking);
  }
  internal_notify(name,
		  &id,
		  meta,
		  ranking);
  FREE(name);
}


/**
 * Get the root of the namespace (if we have one).
 * @return SYSERR on error, OK on success
 */
int NS_getNamespaceRoot(struct GE_Context * ectx,
			struct GC_Configuration * cfg,
			const char * ns,
			HashCode512 * root) {
  char * fn;
  char * fnBase;
  int ret;

  GC_get_configuration_value_filename(cfg,
				      "GNUNET",
				      "GNUNET_HOME",
				      GNUNET_HOME_DIRECTORY,
				      &fnBase);
  fn = MALLOC(strlen(fnBase) +
	      strlen(NS_ROOTS) +
	      strlen(ns) +
	      6);
  strcpy(fn, fnBase);
  strcat(fn, DIR_SEPARATOR_STR);
  strcat(fn, NS_ROOTS);
  disk_directory_create(ectx, fn);
  strcat(fn, DIR_SEPARATOR_STR);
  strcat(fn, ns);
  FREE(fnBase);
  if (sizeof(HashCode512)
      == disk_file_read(ectx,
			fn,
			sizeof(HashCode512),
			root))
    ret = OK;
  else
    ret = SYSERR;
  FREE(fn);
  return ret;
}

void NS_setNamespaceRoot(struct GE_Context * ectx,
			 struct GC_Configuration * cfg,
			 const struct ECRS_URI * uri) {
  char * fn;
  char * fnBase;
  HashCode512 ns;
  char * name;

  if (OK != ECRS_getNamespaceId(uri,
				&ns)) {
    GE_BREAK(ectx, 0);
    return;
  }
  name = ECRS_getNamespaceName(&ns);
  GC_get_configuration_value_filename(cfg,
				      "GNUNET",
				      "GNUNET_HOME",
				      GNUNET_HOME_DIRECTORY,
				      &fnBase);
  fn = MALLOC(strlen(fnBase) +
	      strlen(NS_ROOTS) +
	      strlen(name) +
	      6);
  strcpy(fn, fnBase);
  strcat(fn, DIR_SEPARATOR_STR);
  strcat(fn, NS_ROOTS);
  disk_directory_create(ectx, fn);
  strcat(fn, DIR_SEPARATOR_STR);
  strcat(fn, name);
  FREE(name);
  FREE(fnBase);
  if (OK == ECRS_getSKSContentHash(uri,
				   &ns)) {
    disk_file_write(ectx,
		    fn,
		    &ns,
		    sizeof(HashCode512),
		    "644");
  }
  FREE(fn);
}

/**
 * Register callback to be invoked whenever we discover
 * a new namespace.
 */
int NS_registerDiscoveryCallback(struct GE_Context * ectx,
				 struct GC_Configuration * cfg,
				 NS_NamespaceIterator iterator,
				 void * closure) {
  struct DiscoveryCallback * list;

  list = MALLOC(sizeof(struct DiscoveryCallback));
  list->callback = iterator;
  list->closure = closure;
  MUTEX_LOCK(lock);
  list->next = head;
  head = list;
  NS_listNamespaces(ectx,
		    cfg,
		    iterator,
		    closure);
  MUTEX_UNLOCK(lock);
  return OK;
}

/**
 * Unregister namespace discovery callback.
 */
int NS_unregisterDiscoveryCallback(NS_NamespaceIterator iterator,
				   void * closure) {
  struct DiscoveryCallback * prev;
  struct DiscoveryCallback * pos;

  prev = NULL;
  MUTEX_LOCK(lock);
  pos = head;
  while ( (pos != NULL) &&
	  ( (pos->callback != iterator) ||
	    (pos->closure != closure) ) ) {
    prev = pos;
    pos = pos->next;
  }
  if (pos == NULL) {
    MUTEX_UNLOCK(lock);
    return SYSERR;
  }
  if (prev == NULL)
    head = pos->next;
  else
    prev->next = pos->next;
  FREE(pos);
  MUTEX_UNLOCK(lock);
  return OK;
}


void __attribute__ ((constructor)) gnunet_namespace_ltdl_init() {
  lock = MUTEX_CREATE(NO);
}

void __attribute__ ((destructor)) gnunet_namespace_ltdl_fini() {
  MUTEX_DESTROY(lock);
  lock = NULL;
}


/* end of namespace_info.c */
