/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/fsui/file_info.c
 * @brief Helper functions for keeping track of files for building directories.
 * @author Christian Grothoff
 *
 * The "state" database (see util/state.c) is used to store the toggle
 * flag. An mmapped file (STATE_NAME) is used to store the actual URIs.
 * An IPC semaphore is used to guard the access.
 */

#include "platform.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_ecrs_lib.h"

#define DEBUG_FILE_INFO NO

#define STATE_NAME DIR_SEPARATOR_STR "data" DIR_SEPARATOR_STR "fs_uridb"
#define TRACK_OPTION "fs_uridb_status"

static IPC_Semaphore * createIPC() {
  char * basename;
  char * tmpname;
  char * ipcName;
  IPC_Semaphore * sem;
  size_t n;

  basename = getConfigurationString("GNUNET",
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

static char * getUriDbName() {
  char * new;
  char * pfx;

  pfx = getFileName("GNUNET", 
		    "GNUNET_HOME",
		    _("Configuration file must specify a "
		      "directory for GNUnet to store "
		      "per-peer data under %s%s\n"));
  new = MALLOC(strlen(pfx) + strlen(STATE_NAME) + 1);
  strcpy(new, pfx);
  strcat(new, STATE_NAME); 
  FREE(pfx);
  return new;
}



/**
 * Get the FSUI URI tracking status.
 *
 * @return YES of tracking is enabled, NO if not
 */
int FSUI_trackStatus() {
  int * status;

  status = NULL;
  if ( (sizeof(int) != stateReadContent(TRACK_OPTION,
					(void**)&status)) ||
       (ntohl(*status) != YES) ) {
    FREENONNULL(status);
#if DEBUG_FILE_INFO
    LOG(LOG_DEBUG,
	_("Collecting file identifiers disabled.\n"));
#endif
    return NO;
  } else {
    FREENONNULL(status);
    return YES;
  }
}

/**
 * Makes a URI available for directory building.
 */
void FSUI_trackURI(const ECRS_FileInfo * fi) {
  IPC_Semaphore * sem;
  char * data;
  unsigned int size;
  char * suri;
  int fh;
  char * fn;

  if (NO == FSUI_trackStatus())
    return;
  size = ECRS_sizeofMetaData(fi->meta,
			     ECRS_SERIALIZE_FULL);
  data = MALLOC(size);
  GNUNET_ASSERT(size == ECRS_serializeMetaData(fi->meta,
					       data,
					       size,
					       ECRS_SERIALIZE_FULL));
  size = htonl(size);
  suri = ECRS_uriToString(fi->uri);
  sem = createIPC();
  IPC_SEMAPHORE_DOWN(sem);
  fn = getUriDbName();
  fh = fileopen(fn, O_WRONLY|O_APPEND|O_CREAT|O_LARGEFILE, S_IRUSR|S_IWUSR);
  if (fh == -1) {
    LOG_FILE_STRERROR(LOG_WARNING,
		      "open",
		      fn);
  } else {
    WRITE(fh, suri, strlen(suri) + 1);
    WRITE(fh, &size, sizeof(unsigned int));
    WRITE(fh, data, ntohl(size));
    CLOSE(fh);
  }
  FREE(fn);
  IPC_SEMAPHORE_UP(sem);
  IPC_SEMAPHORE_FREE(sem);
  FREE(data);
  FREE(suri);
}

/**
 * Remove all of the root-nodes of a particular type
 * from the tracking database.
 */
void FSUI_clearTrackedURIS() {
  IPC_Semaphore * sem;
  char * fn;

  sem = createIPC();
  IPC_SEMAPHORE_DOWN(sem);
  fn = getUriDbName();
  if (0 != UNLINK(fn))
    LOG_FILE_STRERROR(LOG_WARNING,
		      "unlink",
		      fn);
  FREE(fn);
  IPC_SEMAPHORE_UP(sem);
  IPC_SEMAPHORE_FREE(sem);
}

/**
 * Toggle tracking URIs.
 *
 * @param onOff YES to enable tracking, NO to disable
 *  disabling tracking
 */
void FSUI_trackURIS(int onOff) {
  onOff = htonl(onOff);
  stateWriteContent(TRACK_OPTION,
		    sizeof(int),
		    &onOff);
}

/**
 * Iterate over all entries that match the given context
 * mask.
 *
 * @param iterator function to call on each entry, may be NULL
 * @param closure extra argument to the callback
 * @return number of entries found
 */
int FSUI_listURIs(ECRS_SearchProgressCallback iterator,
		  void * closure) {
  IPC_Semaphore * sem;
  int rval;
  char * result;
  off_t ret;
  off_t pos;
  off_t spos;
  unsigned int msize;
  ECRS_FileInfo fi;
  int fd;
  char * fn;
  struct stat buf;

  fn = getUriDbName();
  sem = createIPC();
  IPC_SEMAPHORE_DOWN(sem);
  if (0 != STAT(fn, &buf)) {
    IPC_SEMAPHORE_UP(sem);
    IPC_SEMAPHORE_FREE(sem);
    return 0; /* no URI db */
  }  
  fd = fileopen(fn, O_LARGEFILE | O_RDONLY);
  if (fd == -1) {
    IPC_SEMAPHORE_UP(sem);
    IPC_SEMAPHORE_FREE(sem);
    LOG_FILE_STRERROR(LOG_WARNING, "open", fn);
    FREE(fn);
    return SYSERR; /* error opening URI db */
  }
  result = MMAP(NULL, buf.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (result == MAP_FAILED) {
    CLOSE(fd);
    LOG_FILE_STRERROR(LOG_WARNING, "mmap", fn);
    FREE(fn);
    IPC_SEMAPHORE_UP(sem);
    IPC_SEMAPHORE_FREE(sem);
    return SYSERR;
  }
  ret = buf.st_size;
  pos = 0;
  rval = 0;
  while (pos < ret) {
    spos = pos;
    while ( (spos < ret) &&
	    (result[spos] != '\0') )
      spos++;
    spos++; /* skip '\0' */
    if ( (spos + sizeof(int) >= ret) ||
	 (spos + sizeof(int) < spos) ) {
      BREAK();
      goto FORMATERROR;
    }
    fi.uri = ECRS_stringToUri(&result[pos]);
    if (fi.uri == NULL) {
      BREAK();
      goto FORMATERROR;
    }
    memcpy(&msize,
	   &result[spos],
	   sizeof(int));
    msize = ntohl(msize);
    spos += sizeof(int);
    if ( (spos + msize > ret) ||
	 (spos + msize < spos) ) {
      BREAK();
      ECRS_freeUri(fi.uri);
      goto FORMATERROR;
    }
    fi.meta = ECRS_deserializeMetaData(&result[spos],
				       msize);
    if (fi.meta == NULL) {
      BREAK();
      ECRS_freeUri(fi.uri);
      goto FORMATERROR;
    }
    pos = spos + msize;
    if (iterator != NULL) {
      if (OK != iterator(&fi,
			 NULL,
			 NO,
			 closure)) {
	ECRS_freeMetaData(fi.meta);
	ECRS_freeUri(fi.uri);
	if (0 != MUNMAP(result, buf.st_size))
	  LOG_FILE_STRERROR(LOG_WARNING, "munmap", fn);
	CLOSE(fd);
	FREE(fn);
	IPC_SEMAPHORE_UP(sem);
	IPC_SEMAPHORE_FREE(sem);
	return SYSERR; /* iteration aborted */
      }
    }
    rval++;
    ECRS_freeMetaData(fi.meta);
    ECRS_freeUri(fi.uri);
  }
  if (0 != MUNMAP(result, buf.st_size))
    LOG_FILE_STRERROR(LOG_WARNING, "munmap", fn);
  CLOSE(fd);
  FREE(fn);
  IPC_SEMAPHORE_UP(sem);
  IPC_SEMAPHORE_FREE(sem);
  return rval;
 FORMATERROR:
  LOG(LOG_WARNING,
      _("Deleted corrupt URI database in `%s'."),
      STATE_NAME);
  if (0 != MUNMAP(result, buf.st_size))
    LOG_FILE_STRERROR(LOG_WARNING, "munmap", fn);
  CLOSE(fd);
  FREE(fn);
  IPC_SEMAPHORE_UP(sem);
  IPC_SEMAPHORE_FREE(sem);
  FSUI_clearTrackedURIS();
  return SYSERR;
}


/* end of file_info.c */
