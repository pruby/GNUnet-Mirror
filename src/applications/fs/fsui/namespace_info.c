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

#define NS_HANDLE "namespaces"

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
  return SYSERR;
}

/**
 * Change the ranking of a namespace.
 */
int FSUI_rankNamespace(struct FSUI_Context * ctx,
		       const HashCode160 * ns,
		       int delta) {
  int * eval;
  int value;
  int ret;
  char * name;
  EncName ename;

  hash2enc(ns, &ename);
  name = MALLOC(256);
  SNPRINTF(name, 256, "%s-%s", NS_HANDLE, (char*) &ename);
  eval = NULL;
  ret = stateReadContent(name, (void**) &eval);
  if (ret == -1) {
    eval = MALLOC(sizeof(int));
    *eval = htonl(0);
  }
  value = ntohl(*eval);
  value += delta;
  if (value == 0) {
    stateUnlinkFromDB(name);
  } else if (delta != 0) {
    *eval = ntohl(value);
    stateWriteContent(name, sizeof(int), eval);
  }
  FREE(eval);
  FREE(name);
  return value;
}

/**
 * List all available (local) namespaces.
 * 
 * @param local only list local namespaces (if NO, all
 *   known namespaces are listed)
 */
int FSUI_listNamespaces(struct FSUI_Context * ctx,
			int local,
			FSUI_NamespaceIterator iterator,
			void * closure) {
  int ret;
  int size;
  int pos;
  char * list;

  list = NULL;
  size = stateReadContent(NS_HANDLE,
			  (void**)&list);
  if (size < 0)
    return SYSERR;
  ret = 0;
  while (pos < size) {
    /* FIXME */
    break;
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
 * @param dst to which URI should the namespace entry refer?
 * @param md what meta-data should be associated with the
 *        entry?
 * @param uri set to the resulting URI
 */
int FSUI_addToNamespace(const char * name,
			cron_t updateInterval,
			const HashCode160 * lastId,
			const HashCode160 * thisId,
			const struct ECRS_URI * dst,
			const struct ECRS_MetaData * md,
			struct ECRS_URI ** uri) {
  return SYSERR;
}

/**
 * List all updateable content in a given namespace.
 */
int FSUI_listNamespaceContent(const char * name,
			      FSUI_UpdateIterator iterator,
			      void * closure) {
  return SYSERR;
}




/**
 * Get the nickname of the given namespace.  If the
 * nickname is not unique within our database, append
 * the namespace identifier to make it unique.
 *
 * @return the nickname
 */
char * ECRS_getUniqueNickname(const HashCode160 * ns) {
#if 0
  NBlock * list;
  int ret;
  EncName enc;
  char * nick;
  int unique;
  int i;

  ret = listNamespaces(&list);
  if (ret > 0) {
    nick = NULL;
    for (i=0;i<ret;i++) {
      if (equalsHashCode160(&list[i].namespace,
			    ns)) {
	nick = STRNDUP(list[i].nickname,
		       MAX_NAME_LEN-8);
	break;
      }	
    }
    if (nick == NULL) {
      hash2enc(ns, &enc);
      return STRDUP((char*) &enc);
    }
    unique = YES;
    for (i=0;i<ret;i++)
      if (0 == strncmp(nick,
		       list[i].nickname,
		       MAX_NAME_LEN-8))
	if (! equalsHashCode160(&list[i].namespace,
				ns))
	  unique = NO;
  } else
    unique = NO;

  if (unique) {
    return nick;
  } else {
    char * ret;
    size_t n;

    hash2enc(ns, &enc);
    n = strlen(nick) + 40;
    ret = MALLOC(n);
    SNPRINTF(ret, n, "%s-%s", nick, &enc);
    FREE(nick);
    return ret;    
  } 
#endif
  return STRDUP("NOT IMPLEMENTED");
}

#if 0
/**
 * Add a namespace to the set of known namespaces.
 * For all namespace advertisements that we discover
 * FSUI should automatically call this function.
 * 
 * @param ns the namespace identifier
 */
void addNamespace(const NBlock * ns) {
  NBlock * list;
  int ret;
  unsigned int i;

  if (ntohs(ns->major_formatVersion) != NBLOCK_MAJOR_VERSION) {
    BREAK();
    return;
  }
  list = NULL;
  ret = stateReadContent(NS_HANDLE,
			 (void**)&list);
  if (ret > 0) {
    if ( (ret % sizeof(NBlock)) != 0) {
      FREE(list);
      LOG(LOG_WARNING,
	  _("State DB file '%s' corrupt, deleting contents.\n"),
	  NS_HANDLE);
      stateUnlinkFromDB(NS_HANDLE);
    } else {
      for (i=0;i<ret/sizeof(NBlock);i++) {
	if (0 == memcmp(ns,
			&list[i],
			sizeof(NBlock))) {
	  FREE(list);
	  return; /* seen before */
	}
      }
      FREE(list);
    }
  }
  stateAppendContent(NS_HANDLE,
		     sizeof(NBlock),
		     ns);
}
#endif


/* end of namespace_info.c */
