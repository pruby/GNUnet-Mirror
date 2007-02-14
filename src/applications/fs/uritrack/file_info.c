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
 * @file applications/fs/uritrack/file_info.c
 * @brief Helper functions for keeping track of files for building directories.
 * @author Christian Grothoff
 *
 * An mmapped file (STATE_NAME) is used to store the URIs.
 * An IPC semaphore is used to guard the access.
 */

#include "gnunet_directories.h"
#include "gnunet_util.h"
#include "gnunet_uritrack_lib.h"
#include "platform.h"
#include "callbacks.h"

#define DEBUG_FILE_INFO NO

#define STATE_NAME DIR_SEPARATOR_STR "data" DIR_SEPARATOR_STR "fs_uridb"
#define TRACK_OPTION "fs_uridb_status"

static struct IPC_SEMAPHORE * 
createIPC(struct GE_Context * ectx,
	  struct GC_Configuration * cfg) {
  char * basename;
  char * ipcName;
  struct IPC_SEMAPHORE * sem;
  size_t n;

  GC_get_configuration_value_filename(cfg,
				      "GNUNET",
				      "GNUNET_HOME",
				      GNUNET_HOME_DIRECTORY,
				      &basename);
  n = strlen(basename) + 512;
  ipcName = MALLOC(n);
  SNPRINTF(ipcName, n, "%s/directory_ipc_lock", basename);
  FREE(basename);
  sem = IPC_SEMAPHORE_CREATE(ectx, ipcName, 1);
  FREE(ipcName);
  return sem;				
}

static char * 
getUriDbName(struct GE_Context * ectx,
	     struct GC_Configuration * cfg) {
  char * nw;
  char * pfx;

  GC_get_configuration_value_filename(cfg,
				      "GNUNET",
				      "GNUNET_HOME",
				      GNUNET_HOME_DIRECTORY,
				      &pfx);
  nw = MALLOC(strlen(pfx) + strlen(STATE_NAME) + 2);
  strcpy(nw, pfx);
  strcat(nw, DIR_SEPARATOR_STR);
  strcat(nw, STATE_NAME);
  FREE(pfx);
  disk_directory_create_for_file(ectx,
				 nw);
  return nw;
}

static char *
getToggleName(struct GE_Context * ectx,
	      struct GC_Configuration * cfg) {
  char * nw;
  char * pfx;

  GC_get_configuration_value_filename(cfg,
				      "GNUNET",
				      "GNUNET_HOME",
				      GNUNET_HOME_DIRECTORY,
				      &pfx);
  nw = MALLOC(strlen(pfx) + strlen(TRACK_OPTION) + 2);
  strcpy(nw, pfx);
  strcat(nw, DIR_SEPARATOR_STR);
  strcat(nw, TRACK_OPTION);
  FREE(pfx);
  disk_directory_create_for_file(ectx,
				 nw);
  return nw;
}

/**
 * Get the URITRACK URI tracking status.
 *
 * @return YES of tracking is enabled, NO if not
 */
int URITRACK_trackStatus(struct GE_Context * ectx,
			 struct GC_Configuration * cfg) {
  int status;
  char * tn;

  tn = getToggleName(ectx,
		     cfg);
  if (YES != disk_file_test(ectx,
			    tn)) {
    FREE(tn);
    return NO; /* default: off */
  }
  if ( (sizeof(int) != disk_file_read(ectx,
				      tn,
				      sizeof(int),
				      &status)) ||
       (ntohl(status) != YES) ) {
    FREE(tn);
#if DEBUG_FILE_INFO
    GE_LOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   _("Collecting file identifiers disabled.\n"));
#endif
    return NO;
  } else {
    FREE(tn);
    return YES;
  }
}

/**
 * Makes a URI available for directory building.
 */
void URITRACK_trackURI(struct GE_Context * ectx,
		       struct GC_Configuration * cfg,
		       const ECRS_FileInfo * fi) {
  struct IPC_SEMAPHORE * sem;
  char * data;
  unsigned int size;
  char * suri;
  int fh;
  char * fn;

  if (NO == URITRACK_trackStatus(ectx, cfg))
    return;
  size = ECRS_sizeofMetaData(fi->meta,
			     ECRS_SERIALIZE_FULL);
  data = MALLOC(size);
  GE_ASSERT(ectx, size == ECRS_serializeMetaData(ectx,
						 fi->meta,
						 data,
						 size,
						 ECRS_SERIALIZE_FULL | ECRS_SERIALIZE_NO_COMPRESS));
  size = htonl(size);
  suri = ECRS_uriToString(fi->uri);
  sem = createIPC(ectx, cfg);
  IPC_SEMAPHORE_DOWN(sem, YES);
  fn = getUriDbName(ectx, cfg);
  fh = disk_file_open(ectx,
		      fn,
		      O_WRONLY|O_APPEND|O_CREAT|O_LARGEFILE,
		      S_IRUSR|S_IWUSR);
  if (fh != -1) {
    WRITE(fh, suri, strlen(suri) + 1);
    WRITE(fh, &size, sizeof(unsigned int));
    WRITE(fh, data, ntohl(size));
    CLOSE(fh);
  }
  FREE(fn);
  IPC_SEMAPHORE_UP(sem);
  IPC_SEMAPHORE_DESTROY(sem);
  FREE(data);
  FREE(suri);
  URITRACK_internal_notify(fi);
}

/**
 * Remove all of the root-nodes of a particular type
 * from the tracking database.
 */
void URITRACK_clearTrackedURIS(struct GE_Context * ectx,
			       struct GC_Configuration * cfg) {
  struct IPC_SEMAPHORE * sem;
  char * fn;

  sem = createIPC(ectx, cfg);
  IPC_SEMAPHORE_DOWN(sem, YES);
  fn = getUriDbName(ectx, cfg);
  if (YES == disk_file_test(ectx,
			    fn)) {
    if (0 != UNLINK(fn))
      GE_LOG_STRERROR_FILE(ectx,
			   GE_ERROR | GE_USER | GE_ADMIN | GE_BULK,
			   "unlink",
			   fn);
  }
  FREE(fn);
  IPC_SEMAPHORE_UP(sem);
  IPC_SEMAPHORE_DESTROY(sem);
}

/**
 * Toggle tracking URIs.
 *
 * @param onOff YES to enable tracking, NO to disable
 *  disabling tracking
 */
void URITRACK_trackURIS(struct GE_Context * ectx,
			struct GC_Configuration * cfg,
			int onOff) {
  int o = htonl(onOff);
  char * tn;

  tn = getToggleName(ectx,
		     cfg);
  disk_file_write(ectx,
		  tn,
		  &o,
		  sizeof(int),
		  "600");
  FREE(tn);
}

/**
 * Iterate over all entries that match the given context
 * mask.
 *
 * @param iterator function to call on each entry, may be NULL
 * @param closure extra argument to the callback
 * @param need_metadata YES if metadata should be
 *        provided, NO if metadata is not needed (faster)
 * @return number of entries found
 */
int URITRACK_listURIs(struct GE_Context * ectx,
		      struct GC_Configuration * cfg,
		      int need_metadata,
		      ECRS_SearchProgressCallback iterator,
		      void *closure) {
  struct IPC_SEMAPHORE *sem;
  int rval;
  char *result;
  off_t ret;
  off_t pos;
  off_t spos;
  unsigned int msize;
  ECRS_FileInfo fi;
  int fd;
  char *fn;
  struct stat buf;

  fn = getUriDbName(ectx, cfg);
  sem = createIPC(ectx, cfg);
  IPC_SEMAPHORE_DOWN(sem, YES);
  if ( (0 != STAT(fn, &buf)) ||
       (buf.st_size == 0) ) {
    IPC_SEMAPHORE_UP(sem);
    IPC_SEMAPHORE_DESTROY(sem);
    FREE(fn);
    return 0;                   /* no URI db */
  }
  fd = disk_file_open(ectx,
		      fn,
		      O_LARGEFILE | O_RDONLY);
  if (fd == -1) {
    IPC_SEMAPHORE_UP(sem);
    IPC_SEMAPHORE_DESTROY(sem);
    GE_LOG_STRERROR_FILE(ectx,
			 GE_ERROR | GE_USER | GE_ADMIN | GE_BULK,
			 "open",
			 fn);
    FREE(fn);
    return SYSERR;              /* error opening URI db */
  }
  result = MMAP(NULL,
		buf.st_size,
		PROT_READ,
		MAP_SHARED,
		fd,
		0);
  if (result == MAP_FAILED) {
    CLOSE(fd);
    GE_LOG_STRERROR_FILE(ectx,
			 GE_ERROR | GE_USER | GE_ADMIN | GE_BULK,
			 "mmap",
			 fn);
    FREE(fn);
    IPC_SEMAPHORE_UP(sem);
    IPC_SEMAPHORE_DESTROY(sem);
    return SYSERR;
  }
  ret = buf.st_size;
  pos = 0;
  rval = 0;
  while(pos < ret) {
    spos = pos;
    while((spos < ret) && (result[spos] != '\0'))
      spos++;
    spos++;                     /* skip '\0' */
    if((spos + sizeof(int) >= ret) || (spos + sizeof(int) < spos)) {
      GE_BREAK(ectx, 0);
      goto FORMATERROR;
    }
    fi.uri = ECRS_stringToUri(ectx,
			      &result[pos]);
    if(fi.uri == NULL) {
      GE_BREAK(ectx, 0);
      goto FORMATERROR;
    }
    memcpy(&msize, &result[spos], sizeof(int));
    msize = ntohl(msize);
    spos += sizeof(int);
    if((spos + msize > ret) || (spos + msize < spos)) {
      GE_BREAK(ectx, 0);
      ECRS_freeUri(fi.uri);
      goto FORMATERROR;
    }
    if (need_metadata == YES) {
      fi.meta = ECRS_deserializeMetaData(ectx,
					 &result[spos], msize);
      if(fi.meta == NULL) {
	GE_BREAK(ectx, 0);
	ECRS_freeUri(fi.uri);
	goto FORMATERROR;
      }
    } else {
      fi.meta = NULL;
    }
    pos = spos + msize;
    if(iterator != NULL) {
      if (OK != iterator(&fi, NULL, NO, closure)) {
	if (fi.meta != NULL)
	  ECRS_freeMetaData(fi.meta);
        ECRS_freeUri(fi.uri);
        if (0 != MUNMAP(result, buf.st_size))
          GE_LOG_STRERROR_FILE(ectx,
			       GE_ERROR | GE_ADMIN | GE_BULK,
			       "munmap",
			       fn);
        CLOSE(fd);
        FREE(fn);
        IPC_SEMAPHORE_UP(sem);
        IPC_SEMAPHORE_DESTROY(sem);
        return SYSERR;          /* iteration aborted */
      }
    }
    rval++;
    if (fi.meta != NULL)
      ECRS_freeMetaData(fi.meta);
    ECRS_freeUri(fi.uri);
  }
  if(0 != MUNMAP(result, buf.st_size))
    GE_LOG_STRERROR_FILE(ectx,
			 GE_ERROR | GE_ADMIN | GE_BULK,
			 "munmap",
			 fn);
  CLOSE(fd);
  FREE(fn);
  IPC_SEMAPHORE_UP(sem);
  IPC_SEMAPHORE_DESTROY(sem);
  return rval;
FORMATERROR:
  GE_LOG(ectx,
	 GE_WARNING | GE_BULK | GE_USER,
	 _("Deleted corrupt URI database in `%s'."),
	 STATE_NAME);
  if(0 != MUNMAP(result, buf.st_size))
    GE_LOG_STRERROR_FILE(ectx,
			 GE_ERROR | GE_ADMIN | GE_BULK,
			 "munmap",
			 fn);
  CLOSE(fd);
  FREE(fn);
  IPC_SEMAPHORE_UP(sem);
  IPC_SEMAPHORE_DESTROY(sem);
  URITRACK_clearTrackedURIS(ectx, cfg);
  return SYSERR;
}


/* end of file_info.c */
