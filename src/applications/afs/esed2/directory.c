/*
     This file is part of GNUnet.
     (C) 2003 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/esed2/directory.c 
 * @brief Helper functions for building directories.
 * @author Christian Grothoff
 *
 * Directories are an add-on mechanism on top of the ESED II.  As
 * such, gnunetd has no notion of directories.  Thus, this code is
 * NEVER run inside of gnunetd but always by the various AFS tools.
 * Since multiple AFS tools may concurrently access the directories
 * from different processes, IPC is required to synchronize the
 * access.  
 *
 * The "state" database (see include/util/state.h) is used
 * to store the data.  Note that state does not do any locking,
 * and that it in particular can not do any locking for us since 
 * it is IPC!
 */

#include "gnunet_afs_esed2.h"
#include "platform.h"

#define STATE_NAME "dir%u"

static IPC_Semaphore * createIPC() {
  char * basename;
  char * tmpname;
  char * ipcName;
  IPC_Semaphore * sem;
  size_t n;

  basename = getConfigurationString("",
				    "GNUNET_HOME");
  n = strlen(basename) + 512;
  tmpname = MALLOC(n);
  SNPRINTF(tmpname, n, "%s/directory_ipc_lock", basename);
  ipcName = expandFileName(tmpname);
  FREE(basename);
  FREE(tmpname);
  sem = IPC_SEMAPHORE_NEW(ipcName, 1);
  FREE(ipcName);
  return sem;				    
}

/**
 * Makes a root-node available for directory building.
 *
 * This function is called whenever a root-node is encountered.  This
 * can either be because the user inserted a file locally; because we
 * received a search result or because the user retrieved a directory
 * with root-nodes.  From which context the root node was encountered
 * is specified in the context parameters.<p>
 *
 * makeRootNodeAvailable adds the node to the list of files that
 * we can build a directory from later.  The context is used to allow
 * the user to filter on root-node sources.
 * 
 * @param root the file identifier that was encountered
 * @param context the context in which the identifier was encountered
 */
void makeRootNodeAvailable(const RootNode * root,
			   unsigned int context) {
  IPC_Semaphore * sem;
  char name[32];
  int ret;
  void * result;

  if (! testConfigurationString("AFS",
				"COLLECT-FILE-IDENTIFIERS",
				"YES") ) {
    LOG(LOG_DEBUG,
	"Collecting file identifiers disabled by configuration.\n");
    return;
  }
  SNPRINTF(name, 
	   32,
	   STATE_NAME,
	   context);
  sem = createIPC();
  IPC_SEMAPHORE_DOWN(sem); 
  result = NULL;
  ret = stateReadContent(name, &result);
  if (ret > 0) {
    /* if size is not a multiple of the RootNode
       size, try to fix DB by truncating! */
    if (ret % sizeof(RootNode) != 0) {
      ret -= ret % sizeof(RootNode);
      stateWriteContent(name, ret, result);
    }    
    ret = ret / sizeof(RootNode);
    while (ret > 0) {
      if (0 == memcmp(root,
		      &((RootNode*)result)[--ret],
		      sizeof(RootNode))) {
	FREE(result);
	IPC_SEMAPHORE_UP(sem);
	IPC_SEMAPHORE_FREE(sem);	
	return; /* already present */
      }
    }
    FREE(result);
  }
  stateAppendContent(name, sizeof(RootNode), root);
  IPC_SEMAPHORE_UP(sem);
  IPC_SEMAPHORE_FREE(sem);
}

/**
 * Remove all of the root-nodes of a particular type
 * from the directory database.
 *
 * @param contexts context bitmask of the databases that should be emptied.
 */ 
void emptyDirectoryDatabase(unsigned int contexts) {
  IPC_Semaphore * sem;
  unsigned int i;
  char name[32];

  sem = createIPC();
  IPC_SEMAPHORE_DOWN(sem);
  i=1;
  while (contexts > 0) {
    if ((contexts & i) > 0) {
      contexts -= i;

      SNPRINTF(name, 
	       32,
	       STATE_NAME,
	       i);
      stateUnlinkFromDB(name);
    }
    i*=2;
  } 
  IPC_SEMAPHORE_UP(sem);
  IPC_SEMAPHORE_FREE(sem);
}

/**
 * Iterate over all entries that match the given context
 * mask.
 *
 * @param contexts context bitmask for the entries to iterate over
 * @param callback function to call on each entry, may be NULL
 * @param closure extra argument to the callback
 * @return number of entries found
 */
int iterateDirectoryDatabase(unsigned int contexts,
			     RootNodeCallback callback,
			     void * closure) {
  IPC_Semaphore * sem;
  unsigned int i;
  char name[32];
  int rval = 0;
  void * result;
  int ret;

  sem = createIPC();
  IPC_SEMAPHORE_DOWN(sem);
  i = 1;
  while (contexts > 0) {
    if ((contexts & i) > 0) {
      contexts -= i;
      SNPRINTF(name, 
	       32,
	       STATE_NAME,
	       i);
      ret = stateReadContent(name, &result);
      if (ret > 0) {
	/* if size is not a multiple of the RootNode
	   size, try to fix DB by truncating! */
	if (ret % sizeof(RootNode) != 0) {
	  ret -= ret % sizeof(RootNode);
	  stateWriteContent(name, ret, result);
	}    
	ret = ret / sizeof(RootNode);
	while (ret > 0) {
	  if (callback != NULL)
	    callback(&((RootNode*)result)[--ret],
		     closure);
	  else
	    ret--;
	  rval++;
	}
	FREE(result);
      }
    }
    i*=2;
  } 
  IPC_SEMAPHORE_UP(sem);
  IPC_SEMAPHORE_FREE(sem);
  return rval;
}

/**
 * Build a GNUnet directory in memoy.
 * 
 * @param numberOfEntries how many files are in the directory
 * @param name what is the name of the directory
 * @param entries the entries in the directory
 * @return the directory
 */
GNUnetDirectory * buildDirectory(int numberOfEntries,
				 const char * nameConst,
				 const RootNode * entries) {
  GNUnetDirectory * result;
  char * name;

  name = STRDUP(nameConst);
  result = MALLOC(sizeof(GNUnetDirectory)+numberOfEntries*sizeof(RootNode));
  memset(result,
	 0,
	 sizeof(GNUnetDirectory)+numberOfEntries*sizeof(RootNode));
  memcpy(&result->MAGIC[0],
	 GNUNET_DIRECTORY_MAGIC,
	 8);
  result->version = htons(0);
  result->number_of_files = htonl(numberOfEntries);
  if (name[strlen(name)-1] != DIR_SEPARATOR) {
    char * tmp;
    tmp = MALLOC(strlen(name)+2);
    strcpy(tmp, name);
    strcat(tmp, "/");
    FREE(name);
    name = tmp;
  }
  if (strlen(name) > MAX_DESC_LEN-1)
    name[MAX_DESC_LEN-1] = 0;
  memcpy(&result->description[0],
	 name,
	 strlen(name));
  FREE(name);
  memcpy(&((GNUnetDirectory_GENERIC*)result)->contents[0],
	 entries,
	 sizeof(RootNode) * numberOfEntries);
  return result;
}

/**
 * Write a directory to a file.
 * 
 * @param dir the directory
 * @param fn the filename
 * @return OK on success, SYSERR on error
 */
int writeGNUnetDirectory(const GNUnetDirectory * dir,
			 const char * fn) {
  int size;

  size = sizeof(GNUnetDirectory) + 
    sizeof(RootNode) * ntohl(dir->number_of_files);
  writeFile(fn, dir, size, "660");
  return OK;
}

/**
 * Read a directory from a file.
 * 
 * @param fn the filename
 * @return the directory on success, NULL on error
 */
GNUnetDirectory * readGNUnetDirectory(const char * fn) {
  unsigned int size;
  GNUnetDirectory * result;
  
  if (! assertIsFile(fn))
    return NULL;
  size = getFileSize(fn);
  if ( ( (size % 1024) != 0) ||
       ( size < 1024) )
    return NULL; /* bad size for directory! */
  result = MALLOC(size);
  if (size != (unsigned int)readFile(fn, size, result)) {
    FREE(result);
    return NULL;
  }
  if ( (0 != ntohs(result->version)) ||
       (0 != strncmp(result->MAGIC, GNUNET_DIRECTORY_MAGIC, 8) ) ||
       (size / 1024 != ntohl(result->number_of_files)+1) ) {
    FREE(result);
    return NULL;
  }
  return result;
}

/**
 * Appends a suffix ".gnd" to a given string if the suffix 
 * doesn't exist already. Existing suffix '/' is replaced if 
 * encountered.
 *
 * @param dn the directory name (string)
 * @return the converted name on success, caller must free
 */
char * expandDirectoryName(const char * dn) {
  char * newName;
  unsigned int len;
 
  GNUNET_ASSERT(dn != NULL);
  len = strlen(dn);
  newName = MALLOC(len+strlen(GNUNET_DIRECTORY_EXT)+4);
  strcpy(newName, dn);
     
  if (newName[len-1] == DIR_SEPARATOR)
    newName[--len] = '\0';
  if (len < strlen(GNUNET_DIRECTORY_EXT) ||
      strcmp(&newName[len-strlen(GNUNET_DIRECTORY_EXT)],
             GNUNET_DIRECTORY_EXT) != 0 ) {
    strcat(newName,GNUNET_DIRECTORY_EXT);
  }

  return newName;
}

/* end of directory.c */

