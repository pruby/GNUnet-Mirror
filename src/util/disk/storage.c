/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/disk/storage.c
 * @brief disk IO convenience methods
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_string.h"
#include "gnunet_util_disk.h"



#if LINUX || CYGWIN
#include <sys/vfs.h>
#else
#ifdef SOMEBSD
#include <sys/param.h>
#include <sys/mount.h>
#else
#ifdef OSX
#include <sys/param.h>
#include <sys/mount.h>
#else
#ifdef SOLARIS
#include <sys/types.h>
#include <sys/statvfs.h>
#else
#ifdef MINGW
#define		_IFMT		0170000	/* type of file */
#define		_IFLNK		0120000	/* symbolic link */
#define	S_ISLNK(m)	(((m)&_IFMT) == _IFLNK)
#else
#error PORT-ME: need to port statfs (how much space is left on the drive?)
#endif
#endif
#endif
#endif
#endif

#ifndef SOMEBSD
 #ifndef WINDOWS
  #ifndef OSX
   #include <wordexp.h>
  #endif
 #endif
#endif

typedef struct {
  struct GE_Context * ectx;
  unsigned long long total;
  int include_sym_links;
} GetFileSizeData;

static int getSizeRec(const char * filename,
		      const char * dirname,
		      void * ptr) {
  GetFileSizeData * gfsd = ptr;
#ifdef HAVE_STAT64
  struct stat64 buf;
#else
  struct stat buf;
#endif
  char * fn;

  GE_ASSERT(gfsd->ectx, filename != NULL);
  if ( (dirname != NULL) &&
       (strlen(dirname) > 0) ) {
    fn = MALLOC(strlen(filename) + strlen(dirname) + 3);
    if (strlen(dirname) > 0) {
      strcpy(fn, dirname);
      if (dirname[strlen(dirname)-1] != DIR_SEPARATOR)
	strcat(fn, DIR_SEPARATOR_STR); /* add tailing / if needed */
    }
    /* Windows paths don't start with / */
#ifndef MINGW
    else
      strcpy(fn, DIR_SEPARATOR_STR);
#endif
    if (filename[0] == DIR_SEPARATOR)
      /* if filename starts with a "/", don't copy it */
      strcat(fn, &filename[1]);
    else
      strcat(fn, filename);
  } else
    fn = STRDUP(filename);

#ifdef HAVE_STAT64
  if (0 != STAT64(fn, &buf)) {
    GE_LOG_STRERROR_FILE(gfsd->ectx,
			 GE_WARNING | GE_USER | GE_REQUEST,
			 "stat64",
			 fn);
    FREE(fn);
    return SYSERR;
  }
#else
  if (0 != STAT(fn, &buf)) {
    GE_LOG_STRERROR_FILE(gfsd->ectx,
			 GE_WARNING | GE_USER | GE_REQUEST,
			 "stat",
			 fn);
    FREE(fn);
    return SYSERR;
  }
#endif
  if ( (! S_ISLNK(buf.st_mode)) ||
       (gfsd->include_sym_links == YES) )
    gfsd->total += buf.st_size;
  if ( (S_ISDIR(buf.st_mode)) &&
       ( (!S_ISLNK(buf.st_mode)) ||
	 (gfsd->include_sym_links == YES) ) ) {
    if (SYSERR ==
	disk_directory_scan(gfsd->ectx,
			    fn,
			    &getSizeRec,
			    gfsd)) {
      FREE(fn);
      return SYSERR;
    }
  }
  FREE(fn);
  return OK;
}

/**
 * Get the size of the file (or directory)
 * of the given file (in bytes).
 *
 * @return SYSERR on error, OK on success
 */
int disk_file_size(struct GE_Context * ectx,
		   const char * filename,
		   unsigned long long * size,
		   int includeSymLinks) {
  GetFileSizeData gfsd;
  int ret;

  GE_ASSERT(ectx, size != NULL);
  gfsd.ectx = ectx;
  gfsd.total = 0;
  gfsd.include_sym_links = includeSymLinks;
  ret = getSizeRec(filename, "", &gfsd);
  *size = gfsd.total;
  return ret;
}

/**
 * Get the number of blocks that are left on the partition that
 * contains the given file (for normal users).
 *
 * @param part a file on the partition to check
 * @return -1 on errors, otherwise the number of free blocks
 */
long disk_get_blocks_available(struct GE_Context * ectx,
			       const char * part) {
#ifdef SOLARIS
  struct statvfs buf;

  if (0 != statvfs(part, &buf)) {
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_USER | GE_ADMIN | GE_BULK,
			 "statfs",
			 part);
    return -1;
  }
  return buf.f_bavail;
#elif MINGW
  DWORD dwDummy;
  DWORD dwBlocks;
  char szDrive[4];

  memcpy(szDrive, part, 3);
  szDrive[3] = 0;
  if (!GetDiskFreeSpace(szDrive,
			&dwDummy,
			&dwDummy,
			&dwBlocks,
			&dwDummy)) {
    GE_LOG(ectx,
	   GE_WARNING | GE_USER | GE_ADMIN | GE_BULK,
	   _("`%s' failed for drive `%s': %u\n"),
	   "GetDiskFreeSpace",
	   szDrive,
	   GetLastError());

    return -1;
  }
  return dwBlocks;
#else
  struct statfs s;
  if (0 != statfs(part, &s)) {
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_USER | GE_ADMIN | GE_BULK,
			 "statfs",
			 part);
    return -1;
  }
  return s.f_bavail;
#endif
}

/**
 * Test if fil is a directory.
 *
 * @return YES if yes, NO if not, SYSERR if it
 *   does not exist
 */
int disk_directory_test(struct GE_Context * ectx,
			const char * fil) {
  struct stat filestat;
  int ret;

  ret = STAT(fil, &filestat);
  if (ret != 0) {
    if (errno != ENOENT) {
      GE_LOG_STRERROR_FILE(ectx,
			   GE_WARNING | GE_USER | GE_ADMIN | GE_REQUEST,
			   "stat",
			   fil);
      return SYSERR;
    }
    return NO;
  }
  if (! S_ISDIR(filestat.st_mode))
    return NO;
  if (ACCESS(fil, R_OK | X_OK) < 0 ) {
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_USER | GE_ADMIN | GE_REQUEST,
			 "access",
			 fil);
    return SYSERR;
  }
  return YES;
}

/**
 * Check that fil corresponds to a filename
 * (of a file that exists and that is not a directory).
 * @returns YES if yes, NO if not a file, SYSERR if something
 * else (will print an error message in that case, too).
 */
int disk_file_test(struct GE_Context * ectx,
		   const char * fil) {
  struct stat filestat;
  int ret;

  ret = STAT(fil, &filestat);
  if (ret != 0) {
    if (errno != ENOENT) {
      GE_LOG_STRERROR_FILE(ectx,
			   GE_WARNING | GE_USER | GE_ADMIN | GE_REQUEST,
			   "stat",
			   fil);
      return SYSERR;
    }
    return NO;
  }
  if (! S_ISREG(filestat.st_mode))
    return NO;
  if (ACCESS(fil, R_OK) < 0 ) {
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_USER | GE_ADMIN | GE_REQUEST,
			 "access",
			 fil);
    return SYSERR;
  }
  return YES;
}

/**
 * Implementation of "mkdir -p"
 * @param dir the directory to create
 * @returns OK on success, SYSERR on failure
 */
int disk_directory_create(struct GE_Context * ectx,
			  const char * dir) {
  char * rdir;
  int len;
  int pos;
  int ret = OK;

  rdir = string_expandFileName(ectx,
			       dir);
  if (rdir == NULL)
    return SYSERR;

  len = strlen(rdir);
#ifndef MINGW
  pos = 1; /* skip heading '/' */
#else
  /* Local or Network path? */
  if (strncmp(rdir, "\\\\", 2) == 0) {
    pos = 2;
    while (rdir[pos]) {
      if (rdir[pos] == '\\') {
        pos++;
        break;
      }
      pos++;
    }
  } else {
    pos = 3;  /* strlen("C:\\") */
  }
#endif
  while (pos <= len) {
    if ( (rdir[pos] == DIR_SEPARATOR) ||
	 (pos == len) ) {
      rdir[pos] = '\0';
      ret = disk_directory_test(ectx, rdir);
      if (ret == SYSERR) {
	FREE(rdir);
	return SYSERR;
      }
      if (ret == NO) {
#ifndef MINGW
	ret = mkdir(rdir,
		    S_IRUSR | S_IWUSR |
		    S_IXUSR | S_IRGRP |
		    S_IXGRP | S_IROTH |
		    S_IXOTH); /* 755 */
#else
	ret = mkdir(rdir);
#endif
	if ( (ret != 0) &&
	     (errno != EEXIST) ) {
	  GE_LOG_STRERROR_FILE(ectx,
			       GE_ERROR | GE_USER | GE_BULK,
			       "mkdir",
			       rdir);
	  FREE(rdir);
	  return SYSERR;
	}
      }
      rdir[pos] = DIR_SEPARATOR;
    }
    pos++;
  }
  FREE(rdir);
  return OK;
}


/**
 * Create the directory structure for storing
 * a file.
 *
 * @param filename name of a file in the directory
 * @returns OK on success, SYSERR on failure
 */
int disk_directory_create_for_file(struct GE_Context * ectx,
				   const char * dir) {
  char * rdir;
  int len;
  int ret;

  rdir = string_expandFileName(ectx,
			       dir);
  if (rdir == NULL)
    return SYSERR;
  len = strlen(rdir);
  while ( (len > 0) &&
	  (rdir[len] != DIR_SEPARATOR) )
    len--;
  rdir[len] = '\0';
  ret = disk_directory_create(ectx, rdir);
  FREE(rdir);
  return ret;
}

/**
 * Read the contents of a binary file into a buffer.
 * @param fileName the name of the file, not freed,
 *        must already be expanded!
 * @param len the maximum number of bytes to read
 * @param result the buffer to write the result to
 * @return the number of bytes read on success, -1 on failure
 */
int disk_file_read(struct GE_Context * ectx,
		   const char * fileName,
		   int len,
		   void * result) {
  /* open file, must exist, open read only */
  int handle;
  int size;

  GE_ASSERT(ectx, fileName != NULL);
  GE_ASSERT(ectx, len > 0);
  if (len == 0)
    return 0;
  GE_ASSERT(ectx, result != NULL);
  handle = disk_file_open(ectx,
			  fileName,
			  O_RDONLY,
			  S_IRUSR);
  if (handle < 0)
    return -1;
  size = READ(handle, result, len);
  disk_file_close(ectx, fileName, handle);
  return size;
}


/**
 * Convert string to value ('755' for chmod-call)
 */
static int atoo(const char *s) {
  int n = 0;

  while ( ('0' <= *s) && (*s < '8') ) {
    n <<= 3;
    n += *s++ - '0';
  }
  return n;
}

/**
 * Write a buffer to a file.
 * @param fileName the name of the file, NOT freed!
 * @param buffer the data to write
 * @param n number of bytes to write
 * @param mode permissions to set on the file
 * @return OK on success, SYSERR on error
 */
int disk_file_write(struct GE_Context * ectx,
		    const char * fileName,
		    const void * buffer,
		    unsigned int n,
		    const char * mode) {
  int handle;
  char * fn;

  /* open file, open with 600, create if not
     present, otherwise overwrite */
  GE_ASSERT(ectx, fileName != NULL);
  fn = string_expandFileName(ectx, fileName);
  handle = disk_file_open(ectx,
			  fn,
			  O_CREAT | O_WRONLY,
			  S_IRUSR | S_IWUSR);
  if (handle == -1) {
    FREE(fn);
    return SYSERR;
  }
  GE_ASSERT(ectx,
	    (n == 0) || (buffer != NULL));
  /* write the buffer take length from the beginning */
  if (n != WRITE(handle, buffer, n)) {
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_USER | GE_IMMEDIATE,
			 "write",
			 fn);
    disk_file_close(ectx, fn, handle);
    FREE(fn);
    return SYSERR;
  }
  disk_file_close(ectx, fn, handle);
  if (0 != CHMOD(fn,
		 atoo(mode))) {
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_USER | GE_BULK,
			 "chmod",
			 fn);
  }
  FREE(fn);
  return OK;
}

/**
 * Scan a directory for files. The name of the directory
 * must be expanded first (!).
 * @param dirName the name of the directory
 * @param callback the method to call for each file,
 *        can be NULL, in that case, we only count
 * @param data argument to pass to callback
 * @return the number of files found, SYSERR on error or
 *         ieration aborted by callback returning SYSERR
 */
int disk_directory_scan(struct GE_Context * ectx,
			const char * dirName,
			DirectoryEntryCallback callback,
			void * data) {
  DIR * dinfo;
  struct dirent *finfo;
  struct stat istat;
  int count = 0;

  GE_ASSERT(ectx, dirName != NULL);
  if (0 != STAT(dirName, &istat)) {
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_USER | GE_BULK,
			 "stat",
			 dirName);
    return SYSERR;
  }
  if (!S_ISDIR(istat.st_mode)) {
    GE_LOG(ectx,
	   GE_WARNING | GE_USER | GE_BULK,
	   _("Expected `%s' to be a directory!\n"),
	   dirName);
    return SYSERR;
  }
  errno = 0;
  dinfo = OPENDIR(dirName);
  if ( (errno == EACCES) || (dinfo == NULL)) {
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_USER | GE_BULK,
			 "opendir",
			 dirName);
    return SYSERR;
  }
  while ((finfo = readdir(dinfo)) != NULL) {
    if (finfo->d_name[0] == '.')
      continue;
    if (callback != NULL) {
      if (OK != callback(finfo->d_name,
			 dirName,
			 data)) {
	closedir(dinfo);
	return SYSERR;
      }
    }	
    count++;
  }
  closedir(dinfo);
  return count;
}

/**
 * Callback for disk_directory_remove
 */
static int rmHelper(const char * fil,
		    const char * dir,
		    void * ctx) {
  struct GE_Context * ectx = ctx;
  char * fn;
  size_t n;

  n = strlen(dir) + strlen(fil) + 2;
  fn = MALLOC(n);
  SNPRINTF(fn,
	   n,
	   "%s/%s",
	   dir,
	   fil);
  if (SYSERR == disk_directory_remove(ectx,
				      fn)) {
    FREE(fn);
    return SYSERR;
  }
  FREE(fn);
  return OK;
}

/**
 * Remove all files in a directory (rm -rf). Call with
 * caution.
 *
 *
 * @param fileName the file to remove
 * @return OK on success, SYSERR on error
 */
int disk_directory_remove(struct GE_Context * ectx,
			  const char * fileName) {
  if (UNLINK(fileName) == 0)
    return OK;
  if ( (errno != EISDIR) &&
       /* EISDIR is not sufficient in all cases, e.g.
	  sticky /tmp directory may result in EPERM on BSD.
	  So we also explicitly check "isDirectory" */
       (YES != disk_directory_test(ectx, fileName)) ) {
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_USER | GE_ADMIN | GE_BULK,
			 "rmdir",
			 fileName);
    return SYSERR;
  }
  if (SYSERR == disk_directory_scan(ectx,
				    fileName,
				    &rmHelper,
				    ectx))
    return SYSERR;
  if (0 != RMDIR(fileName)) {
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_USER | GE_ADMIN | GE_BULK,
			 "rmdir",
			 fileName);
    return SYSERR;
  }
  return OK;
}

void disk_file_close(struct GE_Context * ectx,
		     const char * filename,
		     int fd) {
  if (0 != CLOSE(fd))
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_USER | GE_BULK,
			 "close",
			 filename);
}

int disk_file_open(struct GE_Context * ectx,
		   const char * filename,
		   int oflag,
		   ...) {
  char * fn;
  int mode;
  int ret;
#ifdef MINGW
  char szFile[_MAX_PATH + 1];
  long lRet;

  if ((lRet = plibc_conv_to_win_path(filename,
				     szFile)) != ERROR_SUCCESS) {
    errno = ENOENT;
    SetLastError(lRet);
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_USER | GE_DEVELOPER | GE_ADMIN | GE_BULK,
			 "plibc_conv_to_win_path",
			 filename);
    return -1;
  }
  fn = STRDUP(szFile);
#else
  fn = string_expandFileName(ectx, filename);
#endif
  if (oflag & O_CREAT) {
    va_list arg;
    va_start(arg, oflag);
    mode = va_arg(arg, int);
    va_end(arg);
  } else {
    mode = 0;
  }
#ifdef MINGW
  /* set binary mode */
  oflag |= O_BINARY;
#endif
  ret = open(fn, oflag, mode);
  if (ret == -1)
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_USER | GE_BULK,
			 "open",
			 fn);
  FREE(fn);
  return ret;
}

#define COPY_BLK_SIZE 65536

/**
 * Copy a file.
 * @return OK on success, SYSERR on error
 */
int disk_file_copy(struct GE_Context * ectx,
		   const char * src,
		   const char * dst) {
  char * buf;
  unsigned long long pos;
  unsigned long long size;
  unsigned long long len;
  int in;
  int out;

  if (OK != disk_file_size(ectx,
			   src,
			   &size,
			   YES))
    return SYSERR;
  pos = 0;
  in = disk_file_open(ectx,
		      src,
		      O_RDONLY | O_LARGEFILE);
  if (in == -1)
    return SYSERR;
  out = disk_file_open(ectx,
		       dst,
		       O_LARGEFILE | O_WRONLY | O_CREAT | O_EXCL,
		       S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
  if (out == -1) {
    disk_file_close(ectx,
		    src,
		    in);
    return SYSERR;
  }
  buf = MALLOC(COPY_BLK_SIZE);
  while (pos < size) {
    len = COPY_BLK_SIZE;
    if (len > size - pos)
      len = size - pos;
    if (len != READ(in, buf, len))
      goto FAIL;
    if (len != WRITE(out, buf, len))
      goto FAIL;
    pos += len;
  }
  FREE(buf);
  disk_file_close(ectx, src, in);
  disk_file_close(ectx, dst, out);
  return OK;
 FAIL:
  FREE(buf);
  disk_file_close(ectx, src, in);
  disk_file_close(ectx, dst, out);
  return SYSERR;
}

/* end of storage.c */
