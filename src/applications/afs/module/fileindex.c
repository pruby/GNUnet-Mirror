/*
     This file is part of GNUnet.
     (C) 2001, 2002 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/module/fileindex.c
 * @brief access to the list of indexed files
 * @author Christian Grothoff
 *
 * This module is responsible for storing the names 
 * of indexed files. The index for a file is always
 * >0, since 0 is reserved for "not indexed".
 */

#include "fileindex.h"

#define DEBUG_FILEINDEX NO

/**
 * Maximum length of the name of an indexed file (with path).
 */ 
#define MAX_LINE_SIZE 1024

/**
 * names of indexed files 
 */
static char ** indexed_files = NULL;

/**
 * Size of the indexed_files list.
 */
static unsigned short indexed_files_size;

/**
 * number of files that are indexed
 */
static unsigned short indexed_files_count;

/**
 * Mutex for synced access to indexed_files
 */ 
static Mutex lock;

/**
 * stat handle for indexed_files_count
 */
static int stat_indexed_files_count;

/**
 * stat handle for total size of indexed files
 */
static int stat_indexed_files_size;

static char * shared_file_list;

#define DATABASELIST "database.list"

/**
 * Get the name of the file where we store the
 * list of indexed files.
 */
static char * getSharedFileList() {
  char * afsdir;
  char * res;

  afsdir = getFileName("AFS",
		       "AFSDIR",
		       _("Configuration file must specify filename for"
			 " storing AFS data in section"
			 " '%s' under '%s'.\n"));
  res = MALLOC(strlen(afsdir)+
	       strlen(DATABASELIST)+2);
  strcpy(res, afsdir);
  mkdirp(res); /* important: the directory may not exist yet! */
  strcat(res, "/");
  strcat(res, DATABASELIST);
  FREE(afsdir);
  return res;
}

/**
 * Scan the list of on-demand shared files to initialize indexed_files
 *
 * @return OK on success, SYSERR on error
 */
static int scanDatabaseList() {
  char * fil;
  FILE * handle;
  char * result;
  char * line;
  int pos;
  unsigned long long totalSize;
  
  MUTEX_LOCK(&lock);
  if (indexed_files != NULL) {
    int i;
    for (i=0;i<indexed_files_size;i++)
      FREENONNULL(indexed_files[i]);
    FREENONNULL(indexed_files);
  }
  indexed_files = NULL;
  indexed_files_count = 0;
  indexed_files_size = 0;
  statSet(stat_indexed_files_count, 
	  0);
  statSet(stat_indexed_files_size,
	  0);
  
  fil = shared_file_list;
  handle = FOPEN(fil, "a+");
  if (handle == NULL) {
    LOG_FILE_STRERROR(LOG_WARNING, "fopen", fil);
    MUTEX_UNLOCK(&lock);
    return SYSERR;
  }
  fseek(handle, 0, SEEK_SET);
  line = MALLOC(MAX_LINE_SIZE);
  result = line;
  pos = 0;
  while (1) {    
    result = fgets(line, MAX_LINE_SIZE - 1, handle);
    if (result == NULL)
      break;
    if (strlen(result) > 1)
      indexed_files_count++;
    pos++;
  }
  if (indexed_files_count == 0) {
    fclose(handle);
    FREE(line);
    MUTEX_UNLOCK(&lock);
    statSet(stat_indexed_files_count, 
	    indexed_files_count);
    return OK;
  }  
  fseek(handle, 0, SEEK_SET);
  indexed_files_size = pos;
  indexed_files = MALLOC(indexed_files_size * sizeof(char *));
  pos = 0;
  totalSize = 0;
  result = line;
  while (result != NULL) {
    result = fgets(line, MAX_LINE_SIZE - 1, handle);
    if ( result == NULL )
      break;
    if ( strlen(result) > 1 ) {
      line[strlen(line)-1] = '\0'; /* eat line feed */
      totalSize += getFileSize(line);
      indexed_files[pos++] = STRDUP(line);
    } else
      indexed_files[pos++] = NULL;
  }
  FREE(line);
  fclose(handle);  
  MUTEX_UNLOCK(&lock);
  statSet(stat_indexed_files_count, 
	  indexed_files_count);
  statSet(stat_indexed_files_size,
	  totalSize);
  return OK;
}

/**
 * Initialize the fileindex module.
 */
void initFileIndex() {
  shared_file_list 
    = getSharedFileList();
  stat_indexed_files_count
    = statHandle(_("# indexed files"));
  stat_indexed_files_size
    = statHandle(_("# size of indexed files"));
  MUTEX_CREATE(&lock);
  if (SYSERR == scanDatabaseList())
    errexit(_("Could not initialize %s module.\n"),
	    __FILE__);
}

/**
 * Shutdown the fileindex module.
 */
void doneFileIndex() {
  if (indexed_files != NULL) {
    int i;
    for (i=0;i<indexed_files_size;i++)
      FREENONNULL(indexed_files[i]);
    FREE(indexed_files);
  }
  FREE(shared_file_list);
  MUTEX_DESTROY(&lock);
}

/**
 * Get the name of an indexed file.
 *
 * @param index the index of the file
 * @return the filename (caller frees)
 */
char * getIndexedFileName(unsigned short index) {
  char * res;

  if ( (index == 0) ||
       (index > indexed_files_size) ) {
    BREAK();
    return NULL;
  }
  MUTEX_LOCK(&lock);
  if (indexed_files[index-1] == NULL) 
    res = NULL;
  else
    res = STRDUP(indexed_files[index-1]);
  MUTEX_UNLOCK(&lock);
  return res;
}

/**
 * Invoke a method on each of the filenames of
 * the indexed files. If the method returns
 * SYSERR, remove the file from the list of
 * indexed files!
 *
 * @param method callback to call for each indexed file
 * @param data the last argument to method
 * @return the number of shared files (after changes
 *         caused by this call)
 */
int forEachIndexedFile(IndexedFileNameCallback method,
		       void * data) {
  int i;
  int changed = NO;
  char * fn;
  
  MUTEX_LOCK(&lock);
  for (i=0;i<indexed_files_size;i++) 
    if (indexed_files[i] != NULL) {
      fn = STRDUP(indexed_files[i]);
      MUTEX_UNLOCK(&lock);
      if (SYSERR == method(fn, 
			   i+1,
			   data)) {
	MUTEX_LOCK(&lock);
	FREENONNULL(indexed_files[i]);
	indexed_files[i] = NULL;
	changed = YES;
      } else 
	MUTEX_LOCK(&lock);      
      FREE(fn);
    }
  if (YES == changed) {
    /* write changed list to the drive */
    char * fil;
    FILE * handle;

    fil = shared_file_list;
    handle = FOPEN(fil, "w+");
    if (handle == NULL) {
      LOG(LOG_WARNING, 
	  _("List '%s' of directly shared filenames not available!\n"),
	  fil);
      MUTEX_UNLOCK(&lock);
      return SYSERR;
    }
    for (i=0;i<indexed_files_size;i++) 
      if (indexed_files[i] != NULL)
	fprintf(handle, 
		"%s\n", 
		indexed_files[i]);
      else
	fprintf(handle,
		"\n");
    fclose(handle);
  }
  MUTEX_UNLOCK(&lock);
  return indexed_files_count;
}

/**
 * Add a name to the list of filenames.
 * @param filename the name of the file to add
 * @returns the index of filename in the index, -1 on error
 *          NEVER returns 0.
 */
int appendFilename(const char * fn) {
  char * filename;
  char * fil;
  FILE * handle;
  int result;
  char * line;
  char * scanf;
  int pos;

  GNUNET_ASSERT(fn != NULL);
  MUTEX_LOCK(&lock);
  fil = shared_file_list;
  handle = FOPEN(fil, "r+");
  if (handle == NULL) 
    DIE_FILE_STRERROR("fopen", fil);
  filename = expandFileName(fn);   
  GNUNET_ASSERT(filename != NULL);
  if (strlen(filename) >= MAX_LINE_SIZE) {
    MUTEX_UNLOCK(&lock);
    fclose(handle);
    return SYSERR;
  }
  result = 0;
  pos = 0;
  line = MALLOC(MAX_LINE_SIZE);
  while (1) {
    scanf = fgets(line, MAX_LINE_SIZE-1, handle);
    pos++;
    if (scanf == NULL)
      break;
    /* line always contains the line-feed, do not include that when
       diffing */
    if ( (strncmp(line, filename, strlen(filename)) == 0) &&
	 (strlen(line) == strlen(filename) + 1) ) {
      result = pos;
      break;
    }
  }
  FREE(line);
  if (result != 0) {
    fclose(handle);  
    FREE(filename);
    MUTEX_UNLOCK(&lock);
#if DEBUG_FILEINDEX
    LOG(LOG_DEBUG,
	"File already in index: %d\n",
	result);
#endif
    return result; /* already there! */
  }
  if (pos > 0xFFFF) {
    fclose(handle);  
    FREE(filename);
    MUTEX_UNLOCK(&lock);
    LOG(LOG_WARNING,
	_("Too many files indexed (limit is 65535).\n"));
    return -1;
  }
  /* not there, append */
  fprintf(handle,
	  "%s\n", 
	  filename);
  fclose(handle);  
  FREE(filename);
  MUTEX_UNLOCK(&lock);
  scanDatabaseList();
#if DEBUG_FILEINDEX
  LOG(LOG_DEBUG,
      "Added file to index at position %d.\n",
      pos);
#endif
  return pos; /* return index */
}

/* end of fileindex.c */
