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
 * @file util/storage.c
 * @brief IO convenience methods
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "platform.h"

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
#error FIXME: need to port statfs (how much space is left on the drive?)
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


/* FIXME: Currently this function does not return errors */
static void getSizeRec(const char * filename,
		       const char * dirname,
		       unsigned long long * size) {
  struct stat buf;
  char * fn;

  if (filename == NULL)
    return;
  if (dirname != NULL) {
    fn = MALLOC(strlen(filename) + strlen(dirname) + 2);
    fn[0] = '\0';
    if (strlen(dirname) > 0) {
      strcat(fn, dirname);
      if (dirname[strlen(dirname)-1] != DIR_SEPARATOR)
	strcat(fn, "/"); /* add tailing / if needed */
    }
    /* Windows paths don't start with / */
#ifndef MINGW
    else
      strcat(fn, "/");
#endif
    if (filename[0] == DIR_SEPARATOR) /* if filename starts with a "/", don't copy it */
      strcat(fn, &filename[1]);
    else
      strcat(fn, filename);
  } else
    fn = STRDUP(filename);

  if (0 != STAT(fn, &buf)) {
    LOG_FILE_STRERROR(LOG_EVERYTHING, "stat", fn);
    FREE(fn);
    return;
  }
  *size += buf.st_size;
  if ( (S_ISDIR(buf.st_mode)) &&
       (!S_ISLNK(buf.st_mode)) ) {
    scanDirectory(fn,
		  (DirectoryEntryCallback)&getSizeRec,
		  size);
  }
  FREE(fn);
}

/* FIXME: Currently this function does not return errors */
static void getSizeWithoutSymlinksRec(const char * filename,
				      const char * dirname,
				      unsigned long long * size) {
  struct stat buf;
  char * fn;

  if (filename == NULL)
    return;
  if (dirname != NULL) {
    fn = MALLOC(strlen(filename) + strlen(dirname) + 2);
    fn[0] = '\0';
    if (strlen(dirname) > 0) {
      strcat(fn, dirname);
      if (dirname[strlen(dirname)-1] != DIR_SEPARATOR)
	strcat(fn, "/"); /* add tailing / if needed */
    }
    /* Windows paths don't start with / */
#ifndef MINGW
    else
      strcat(fn, "/");
#endif
    if (filename[0] == DIR_SEPARATOR) /* if filename starts with a "/", don't copy it */
      strcat(fn, &filename[1]);
    else
      strcat(fn, filename);
  } else
    fn = STRDUP(filename);

  if (0 != STAT(fn, &buf)) {
    LOG_FILE_STRERROR(LOG_EVERYTHING, "stat", fn);
    FREE(fn);
    return;
  }
  if (! S_ISLNK(buf.st_mode))
    *size += buf.st_size;
  if ( (S_ISDIR(buf.st_mode)) &&
       (!S_ISLNK(buf.st_mode)) ) {
    scanDirectory(fn,
		  (DirectoryEntryCallback)&getSizeRec,
		  size);
  }
  FREE(fn);
}

/**
 * Get the number of blocks that are left on the partition that
 * contains the given file (for normal users).
 *
 * @param part a file on the partition to check
 * @return -1 on errors, otherwise the number of free blocks
 */
long getBlocksLeftOnDrive(const char * part) {
#ifdef SOLARIS
  struct statvfs buf;

  if (0 == statvfs(part, &buf)) {
    return buf.f_bavail;
  } else {
    LOG_STRERROR(LOG_ERROR, "statfs");
    return -1;
  }
#elif MINGW
  DWORD dwDummy, dwBlocks;
  char szDrive[4];

  memcpy(szDrive, part, 3);
  szDrive[3] = 0;
  if(!GetDiskFreeSpace(szDrive, &dwDummy, &dwDummy, &dwBlocks, &dwDummy))
  {
    LOG(LOG_ERROR,
        _("'%s' failed for drive %s: %u\n"),
	"GetDiskFreeSpace",
        szDrive, GetLastError());

    return -1;
  }
  else
  {
    return dwBlocks;
  }
#else
  struct statfs s;
  if (0 == statfs(part, &s)) {
    return s.f_bavail;
  } else {
    LOG_STRERROR(LOG_ERROR, "statfs");
    return -1;
  }
#endif
}

/**
 * Get the size of the file (or directory)
 * of the given file (in bytes).
 * FIXME: Currently this function does not return errors
 */
unsigned long long getFileSize(const char * filename) {
  unsigned long long size;

  size = 0;
  getSizeRec(filename, "", &size);
  return size;
}

/**
 * Get the size of the file (or directory) without
 * counting symlinks.
 * FIXME: Currently this function does not return errors
 */
unsigned long long getFileSizeWithoutSymlinks(const char * filename) {
  unsigned long long size;

  size = 0;
  getSizeWithoutSymlinksRec(filename, "", &size);
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
 * Test if fil is a directory.
 * @returns YES if yes, NO if not
 */
int isDirectory(const char * fil) {
  struct stat filestat;
  int ret;

  ret = STAT(fil, &filestat);
  if (ret != 0) {
    LOG_FILE_STRERROR(LOG_EVERYTHING, "stat", fil);
    return NO;
  }
  if (S_ISDIR(filestat.st_mode))
    return YES;
  else
    return NO;
}

/**
 * Assert that fil corresponds to a filename
 * (of a file that exists and that is not a directory).
 * @returns 1 if yes, 0 if not (will print an error
 * message in that case, too).
 */
int assertIsFile(const char * fil) {
  struct stat filestat;
  int ret;

  ret = STAT(fil, &filestat);
  if (ret != 0) {
    LOG_FILE_STRERROR(LOG_EVERYTHING, "stat", fil);
    return 0;
  }
  if (!S_ISREG(filestat.st_mode)) {
    LOG(LOG_WARNING,
	_("'%s' is not a regular file.\n"),
	fil);
    return 0;
  }
  if (ACCESS(fil, R_OK) < 0 ) {
    LOG_FILE_STRERROR(LOG_WARNING, "access", fil);
    return 0;
  }
  return 1;
}

/**
 * Complete filename (a la shell) from abbrevition.
 * @param fil the name of the file, may contain ~/ or
 *        be relative to the current directory
 * @returns the full file name,
 *          NULL is returned on error
 */
char * expandFileName(const char * fil) {
  char buffer[512];
  char * fn;
#ifndef MINGW
  size_t n;
  char * fm;
  const char *fil_ptr;
#else
  long lRet;
#endif

  if (fil == NULL)
    return NULL;

#ifndef MINGW
  if (fil[0] == DIR_SEPARATOR) {
    /* absolute path, just copy */
    return(STRDUP(fil));
  }
  else if (fil[0] == '~') {
    fm = getenv("HOME");
    if (fm == NULL) {
      /* keep it symbolic to show error to user! */
      fm = "$HOME";
    }

    /* do not copy '~' */
    fil_ptr = fil + 1;

	/* skip over dir seperator to be consistent */
    if (fil_ptr[0] == DIR_SEPARATOR) {
    	fil_ptr++;
    }
  } else {
    fil_ptr = fil;
    if (getcwd(buffer, 512) != NULL)
      fm = buffer;
    else
      fm = "$PWD";
  }

  n = strlen(fm) + 1 + strlen(fil_ptr) + 1;
  fn = MALLOC(n);

  SNPRINTF(fn, n,
	   "%s/%s", fm, fil_ptr);
#else
  fn = MALLOC(MAX_PATH + 1);

  if ((lRet = conv_to_win_path(fil, buffer)) != ERROR_SUCCESS)
  {
  	SetErrnoFromWinError(lRet);

    return NULL;
  }
  /* is the path relative? */
  if ((strncmp(buffer + 1, ":\\", 2) != 0) &&
      (strncmp(buffer, "\\\\", 2) != 0))
  {
    char szCurDir[MAX_PATH + 1];
    lRet = GetCurrentDirectory(MAX_PATH + 1, szCurDir);
    if (lRet + strlen(fn) + 1 > (MAX_PATH + 1))
    {
      SetErrnoFromWinError(ERROR_BUFFER_OVERFLOW);

      return NULL;
    }
    SNPRINTF(fn,
	     MAX_PATH+1,
	     "%s\\%s", szCurDir, buffer);
  }
  else
  {
    strcpy(fn, buffer);
  }
#endif
  return fn;
}

/**
 * Implementation of "mkdir -p"
 * @param dir the directory to create
 * @returns OK on success, SYSERR on failure
 */
int mkdirp(const char * dir) {
  char * rdir;
  int len;
  int pos;
  int ret = OK;

  rdir = expandFileName(dir); /* expand directory */
  len = strlen(rdir);
#ifndef MINGW
  pos = 1; /* skip heading '/' */
#else

  /* Local or Network path? */
  if (strncmp(rdir, "\\\\", 2) == 0)
  {
    pos = 2;
    while (rdir[pos])
    {
      if (rdir[pos] == '\\')
      {
        pos ++;

        break;
      }
      pos ++;
    }
  }
  else
  {
    pos = 3;  /* strlen("C:\\") */
  }
#endif
  while (pos <= len) {
    if ( (rdir[pos] == DIR_SEPARATOR) ||
	 (pos == len) ) {
      rdir[pos] = '\0';
      if (! isDirectory(rdir))
#ifndef MINGW
	if (0 != mkdir(rdir,
		       S_IRUSR | S_IWUSR |
		       S_IXUSR | S_IRGRP |
		       S_IXGRP | S_IROTH |
		       S_IXOTH)) { /* 755 */
#else
	if (0 != mkdir(rdir)) {
#endif
	  if (errno != EEXIST) {
	    LOG_FILE_STRERROR(LOG_ERROR, "mkdir", rdir);
	    ret = SYSERR;
	  }
	}
      rdir[pos] = DIR_SEPARATOR;
    }
    pos++;
  }
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
int readFile(const char * fileName,
	     int  len,
	     void * result) {
  /* open file, must exist, open read only */
  int handle;
  int size;

  if ((fileName == NULL) || (result == NULL))
    return -1;
  handle = OPEN(fileName,O_RDONLY,S_IRUSR);
  if (handle < 0)
    return -1;
  size = READ(handle, result, len);
  CLOSE(handle);
  return size;
}

/**
 * Write a buffer to a file.
 * @param fileName the name of the file, NOT freed!
 * @param buffer the data to write
 * @param n number of bytes to write
 * @param mode permissions to set on the file
 */
void writeFile(const char * fileName,
	       const void * buffer,
	       unsigned int n,
	       const char *mode) {
  int handle;
  /* open file, open with 600, create if not
     present, otherwise overwrite */
  if ((fileName == NULL) || (buffer == NULL))
    return;
  handle = OPEN(fileName,
		O_CREAT|O_WRONLY,S_IRUSR|S_IWUSR);
  if (handle == -1) {
    LOG_FILE_STRERROR(LOG_WARNING, "open", fileName);
    return;
  }
  /* write the buffer take length from the beginning */
  if (n != WRITE(handle, buffer, n))
    LOG_FILE_STRERROR(LOG_WARNING, "write", fileName);
  CHMOD(fileName, atoo(mode));
  CLOSE(handle);
}

/**
 * Build a filename from directory and filename, completing like the shell does
 * @param dir the name of the directory, may contain ~/ or other shell stuff. Will
 *        NOT be freed!
 * @param fil the name of the file, will NOT be deallocated anymore!
 * @param result where to store the full file name (must be large enough!)
 */
void buildFileName(const char * dir,
		   const EncName * fil,
		   char * result) {
  GNUNET_ASSERT((dir != NULL) && (fil != NULL) && (result != NULL));
  strcpy(result, dir);
  strcat(result, (char*)fil);
}

/**
 * Scan a directory for files. The name of the directory
 * must be expanded first (!).
 * @param dirName the name of the directory
 * @param callback the method to call for each file,
 *        can be NULL, in that case, we only count
 * @param data argument to pass to callback
 * @return the number of files found, -1 on error
 */
int scanDirectory(const char * dirName,
		  DirectoryEntryCallback callback,
		  void * data) {
  DIR * dinfo;
  struct dirent *finfo;
  struct stat istat;
  int count = 0;

  if (dirName == NULL)
    return -1;
  if (0 != STAT(dirName, &istat)) {
    LOG_FILE_STRERROR(LOG_WARNING, "stat", dirName);
    return -1;
  }
  if (!S_ISDIR(istat.st_mode)) {
    LOG(LOG_ERROR,
	_("'%s' expected '%s' to be a directory!\n"),
	__FUNCTION__,
	dirName);
    return -1;
  }
  errno = 0;
  dinfo = OPENDIR(dirName);
  if ((errno == EACCES) || (dinfo == NULL)) {
    LOG_FILE_STRERROR(LOG_WARNING, "opendir", dirName);
    return -1;
  }
  while ((finfo = readdir(dinfo)) != NULL) {
    if (finfo->d_name[0] == '.')
      continue;
    if (callback != NULL)
      callback(finfo->d_name,
	       dirName,
	       data);
    count++;
  }
  closedir(dinfo);
  return count;
}

/**
 * Callback for rm_minus_rf.
 */
static void rmHelper(const char * fil,
		     const char * dir,
		     int * ok) {
  char * fn;
  size_t n;

  n = strlen(dir) + strlen(fil) + 2;
  fn = MALLOC(n);
  SNPRINTF(fn, n, "%s/%s", dir, fil);
  if (SYSERR == rm_minus_rf(fn))
    *ok = SYSERR;
  FREE(fn);
}

/**
 * Remove all files in a directory (rm -rf). Call with
 * caution.
 *
 *
 * @param fileName the file to remove
 * @return OK on success, SYSERR on error
 */
int rm_minus_rf(const char * fileName) {
  if (UNLINK(fileName) == 0)
    return OK;
  if ( (errno == EISDIR) ||
       /* EISDIR is not sufficient in all cases, e.g.
	  sticky /tmp directory may result in EPERM on BSD.
	  So we also explicitly check "isDirectory" */
       (YES == isDirectory(fileName)) ) {
    int ok;

    ok = OK;
    scanDirectory(fileName,
		  (DirectoryEntryCallback)&rmHelper,
		  &ok);
    if (ok == OK)
      if (0 != RMDIR(fileName)) {
	LOG_FILE_STRERROR(LOG_WARNING, "rmdir", fileName);
	ok = SYSERR;
      }
    return ok;
  } else {
    LOG_FILE_STRERROR(LOG_WARNING, "unlink", fileName);
    return SYSERR;
  }
}

void close_(int fd,
	    const char * filename,
	    int linenumber) {
#ifdef MINGW
  /* Windows sockets have to be closed using closesocket() */
  if (closesocket(fd) != 0) {
#endif
    if (0 != close(fd)) {
#ifdef MINGW
      /* Close Windows handle */
      if (! CloseHandle((HANDLE) fd)) {
#endif
	LOG(LOG_INFO,
	    _("'%s' failed at %s:%d with error: %s\n"),
#ifdef MINGW
	    "CloseHandle",
#else
	    "close",
#endif
	    filename,
	    linenumber, STRERROR(errno));
      }
#ifdef MINGW
    } else {
      /* discard blocking mode */
      unsigned int uiIndex;
      WaitForSingleObject(hSocksLock, INFINITE);
      for(uiIndex = 0; uiIndex < uiSockCount; uiIndex++)
        if (pSocks[uiIndex].s == fd)
          pSocks[uiIndex].s = -1;
      ReleaseMutex(hSocksLock);
    }
  }
#endif
}

#define COPY_BLK_SIZE 65536

/**
 * Copy a file.
 * @return OK on success, SYSERR on error
 */
int copyFile(const char * src,
	     const char * dst) {
  char * buf;
  unsigned long long pos;
  unsigned long long size;
  unsigned long long len;
  int in;
  int out;

  buf = MALLOC(COPY_BLK_SIZE);
  pos = 0;
  in = OPEN(src, O_RDONLY
#ifdef O_LARGEFILE
	     | O_LARGEFILE
#endif
	    );
  if (in == -1)
    return SYSERR;
  out = OPEN(dst, O_WRONLY | O_CREAT | O_EXCL
#ifdef O_LARGEFILE
	     | O_LARGEFILE
#endif
	     , S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
  if (out == -1) {
    CLOSE(in);
    return SYSERR;
  }
  size = getFileSize(src);
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
  CLOSE(in);
  CLOSE(out);
  return OK;
 FAIL:
  CLOSE(in);
  CLOSE(out);
  return SYSERR;
}

/* end of storage.c */
