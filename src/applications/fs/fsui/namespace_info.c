/*
     This file is part of GNUnet

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
 * @file applications/fs/fsui/namespace_info.c
 * @brief keeping track of namespaces.  This module
 *  is supposed to keep track of other namespaces (and
 *  their advertisments), as well as of our own namespaces
 *  and the updateable content stored therein.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_fsui_lib.h"
#include "fsui.h"

#define NS_DIR "data/namespaces/"

static void writeNamespaceInfo(const char * namespaceName,
			       const struct ECRS_MetaData * meta,
			       int ranking) {
  unsigned int size;
  unsigned int tag;
  char * buf;
  char * fn;
  char * fnBase;

  fn = getConfigurationString(NULL, "GNUNET_HOME");
  fnBase = expandFileName(fn);
  FREE(fn);
  fn = MALLOC(strlen(fnBase) + 
	      strlen(NS_DIR) + 
	      strlen(namespaceName) + 
	      6);
  strcpy(fn, fnBase);
  strcat(fn, DIR_SEPARATOR_STR);
  strcat(fn, NS_DIR);
  mkdirp(fn);
  strcat(fn, DIR_SEPARATOR_STR);
  strcat(fn, namespaceName);
  FREE(fnBase);

  size = ECRS_sizeofMetaData(meta);
  tag = size + sizeof(int);
  buf = MALLOC(tag);
  ((int *) buf)[0] = htonl(ranking); /* ranking */
  GNUNET_ASSERT(size == ECRS_serializeMetaData(meta,
					       &buf[sizeof(int)],
					       size,
					       NO));
  writeFile(fn,
	    buf,
	    tag,
	    "660");
  FREE(fn);
  FREE(buf);
}

static int readNamespaceInfo(const char * namespaceName,
			     struct ECRS_MetaData ** meta,
			     int * ranking) {
  unsigned int size;
  unsigned int tag;
  char * buf;
  char * fn;
  char * fnBase;

  *meta = NULL;
  fn = getConfigurationString(NULL, "GNUNET_HOME");
  fnBase = expandFileName(fn);
  FREE(fn);
  fn = MALLOC(strlen(fnBase) + 
	      strlen(NS_DIR) + 
	      strlen(namespaceName) + 
	      6);
  strcpy(fn, fnBase);
  strcat(fn, DIR_SEPARATOR_STR);
  strcat(fn, NS_DIR);
  strcat(fn, DIR_SEPARATOR_STR);
  strcat(fn, namespaceName);
  FREE(fnBase);
  
  tag = getFileSize(fn);
  if (tag <= sizeof(int)) {
    FREE(fn);
    return SYSERR;
  }
  if (tag > 16 * 1024 * 1024) {
    /* too big, must be invalid! remove! */
    BREAK();
    UNLINK(fn);
    FREE(fn);
    return SYSERR;
  }
  buf = MALLOC(tag);  
  if (size != readFile(fn,
		       tag,
		       buf)) {
    FREE(buf);
    FREE(fn);
    return SYSERR;
  }
  
  size = tag - sizeof(int);  
  *ranking = ntohl(((int *) buf)[0]);  
  if(OK != ECRS_deserializeMetaData(meta,
				    &buf[sizeof(int)],
				    size)) {
    /* invalid data! remove! */
    BREAK();
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
 * @param root set to the URI of the namespace, NULL if no advertisement
 *        was created
 *
 * @return OK on success, SYSERR on error (namespace already exists)
 */
int FSUI_createNamespace(struct FSUI_Context * ctx,
			 const char * namespaceName,
			 const struct ECRS_MetaData * meta,
			 const struct ECRS_URI * advertisementURI,
			 const HashCode160 * rootEntry,
			 struct ECRS_URI ** root) {
  int ret;

  ret = ECRS_createNamespace(namespaceName,
			     meta,
			     ctx->anonymityLevel,
			     getConfigurationInt("FS", "INSERT-PRIORITY"),
			     getConfigurationInt("FS", "INSERT-EXPIRATION") * cronYEARS + cronTime(NULL),
			     advertisementURI,
			     rootEntry,
			     root);
  /* store binding of namespaceName to 'meta' in state DB! */
  if (ret == OK) {
    writeNamespaceInfo(namespaceName,
		       meta,
		       0);
  }
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
int FSUI_rankNamespace(struct FSUI_Context * ctx,
		       const char * ns,
		       int delta) {
  struct ECRS_MetaData * meta;
  int ret;
  int ranking;

  ret = readNamespaceInfo(ns,
			  &meta,
			  &ranking);
  if (ret == SYSERR) {
    ranking = 0;
    meta = ECRS_createMetaData();
  }
  ranking += delta;
  writeNamespaceInfo(ns,
		     meta,
		     ranking);
  ECRS_freeMetaData(meta);
  return ranking;
}

typedef struct {
  FSUI_NamespaceIterator iterator;
  void * closure;
  int ret;
} LNClosure;

static void listNamespaceHelper(const char * fn,
				const char * dirName,
				void * cls) {
  LNClosure * c = cls;
  int ret;
  struct ECRS_MetaData * meta;
  int rating;

  if (c->ret == SYSERR)
    return;
  if (OK != readNamespaceInfo(fn,
			      &meta,
			      &rating))
    return; /* ignore entry */
  ret = c->iterator(c->closure,
		    fn,
		    meta,
		    rating);
  ECRS_freeMetaData(meta);
  if (ret == SYSERR)
    c->ret = ret;
  else
    c->ret++;
}

/**
 * List all available (local or non-local) namespaces.
 * 
 * @param local only list local namespaces (if NO, only
 *   non-local known namespaces are listed)
 */
int FSUI_listNamespaces(struct FSUI_Context * ctx,
			int local,
			FSUI_NamespaceIterator iterator,
			void * closure) {
  int ret;

  if (local == YES) {
    int ret;
    char ** names;
    int i;
    int rating;
    int aborted;
    struct ECRS_MetaData * meta;
    
    aborted = NO;
    names = NULL;
    ret = ECRS_listNamespaces(&names);
    for (i=0;i<ret;i++) {
      if (aborted == NO) {
	if (OK != readNamespaceInfo(names[i],
				    &meta,
				    &rating)) {
	  rating = 0;
	  meta = ECRS_createMetaData();
	}
	if (SYSERR == iterator(closure,
			       names[i],
			       meta,
			       rating))
	  aborted = YES;      
	ECRS_freeMetaData(meta);
      }
      FREE(names[i]);
    }
    GROW(names, ret, 0);
    if (aborted == YES)
      ret = -1;
  } else {
    char * fn;
    char * fnBase;
    LNClosure cls;

    cls.iterator = iterator;
    cls.closure = closure;
    cls.ret = 0;
    fn = getConfigurationString(NULL, "GNUNET_HOME");
    fnBase = expandFileName(fn);
    FREE(fn);
    fn = MALLOC(strlen(fnBase) + 
		strlen(NS_DIR) + 
		4);
    strcpy(fn, fnBase);
    strcat(fn, DIR_SEPARATOR_STR);
    strcat(fn, NS_DIR);
    
    scanDirectory(fn,
		  &listNamespaceHelper,
		  &cls);
    ret = cls.ret;
    FREE(fn);
  }
  return ret;
}

/**
 * Add an entry into a namespace (also for publishing
 * updates).
 *
 * @param name in which namespace to publish
 * @param updateInterval the desired frequency for updates
 * @param lastId the ID of the last value (maybe NULL)
 * @param thisId the ID of the update
 * @param nextId the ID of the next update (maybe NULL)
 * @param dst to which URI should the namespace entry refer?
 * @param md what meta-data should be associated with the
 *        entry?
 * @param uri set to the resulting URI
 */
int FSUI_addToNamespace(struct FSUI_Context * ctx,
			const char * name,
			cron_t updateInterval,
			const HashCode160 * lastId,
			const HashCode160 * thisId,
			const HashCode160 * nextId,
			const struct ECRS_URI * dst,
			const struct ECRS_MetaData * md,
			struct ECRS_URI ** uri) {
  int ret;
  cron_t creationTime;
  HashCode160 nid;
  HashCode160 tid;


  ret = ECRS_addToNamespace(name,
			    ctx->anonymityLevel,
			    getConfigurationInt("FS", "INSERT-PRIORITY"),
			    getConfigurationInt("FS", "INSERT-EXPIRATION") * cronYEARS + cronTime(NULL),
			    creationTime,
			    updateInterval,
			    thisId,
			    nextId,
			    dst,
			    md,
			    uri);
  
  return ret;
}

/**
 * List all updateable content in a given namespace.
 */
int FSUI_listNamespaceContent(struct FSUI_Context * ctx,
			      const char * name,
			      FSUI_UpdateIterator iterator,
			      void * closure) {
  return SYSERR;
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
 * FSUI should automatically call this function.
 * 
 * @param ns the namespace identifier
 */
void FSUI_addNamespaceInfo(const struct ECRS_URI * uri,
			   const struct ECRS_MetaData * meta) {
  char * name;
  int ranking;
  struct ECRS_MetaData * old;

  if (! ECRS_isNamespaceURI(uri)) {
    BREAK();
    return;
  }
  name = ECRS_getNamespaceName(uri);
  if (name == NULL)
    return;
  ranking = 0;
  if (OK == readNamespaceInfo(name,
			      &old,
			      &ranking)) {
    ECRS_getMetaData(meta,
		     &mergeMeta,
		     old);
    writeNamespaceInfo(name,
		       old,
		       ranking);
    ECRS_freeMetaData(old);
  } else {  
    writeNamespaceInfo(name,
		       meta,
		       ranking);
  }
  FREE(name);
}

/* end of namespace_info.c */
