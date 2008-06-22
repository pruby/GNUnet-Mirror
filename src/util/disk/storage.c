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
#define  	_IFMT		0170000 /* type of file */
#define  	_IFLNK		0120000 /* symbolic link */
#define  S_ISLNK(m)	(((m)&_IFMT) == _IFLNK)
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

typedef struct
{
  struct GNUNET_GE_Context *ectx;
  unsigned long long total;
  int include_sym_links;
} GetFileSizeData;

static int
getSizeRec (const char *filename, const char *dirname, void *ptr)
{
  GetFileSizeData *gfsd = ptr;
#ifdef HAVE_STAT64
  struct stat64 buf;
#else
  struct stat buf;
#endif
  char *fn;

  GNUNET_GE_ASSERT (gfsd->ectx, filename != NULL);
  if ((dirname != NULL) && (strlen (dirname) > 0))
    {
      fn = GNUNET_malloc (strlen (filename) + strlen (dirname) + 3);
      if (strlen (dirname) > 0)
        {
          strcpy (fn, dirname);
          if (dirname[strlen (dirname) - 1] != DIR_SEPARATOR)
            strcat (fn, DIR_SEPARATOR_STR);     /* add tailing / if needed */
        }
      /* Windows paths don't start with / */
#ifndef MINGW
      else
        strcpy (fn, DIR_SEPARATOR_STR);
#endif
      if (filename[0] == DIR_SEPARATOR)
        /* if filename starts with a "/", don't copy it */
        strcat (fn, &filename[1]);
      else
        strcat (fn, filename);
    }
  else
    fn = GNUNET_strdup (filename);

#ifdef HAVE_STAT64
  if (0 != STAT64 (fn, &buf))
    {
      GNUNET_GE_LOG_STRERROR_FILE (gfsd->ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_USER |
                                   GNUNET_GE_REQUEST, "stat64", fn);
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
#else
  if (0 != STAT (fn, &buf))
    {
      GNUNET_GE_LOG_STRERROR_FILE (gfsd->ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_USER |
                                   GNUNET_GE_REQUEST, "stat", fn);
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
#endif
  if ((!S_ISLNK (buf.st_mode)) || (gfsd->include_sym_links == GNUNET_YES))
    gfsd->total += buf.st_size;
  if ((S_ISDIR (buf.st_mode)) &&
      (0 == ACCESS (fn, X_OK)) &&
      ((!S_ISLNK (buf.st_mode)) || (gfsd->include_sym_links == GNUNET_YES)))
    {
      if (GNUNET_SYSERR ==
          GNUNET_disk_directory_scan (gfsd->ectx, fn, &getSizeRec, gfsd))
        {
          GNUNET_free (fn);
          return GNUNET_SYSERR;
        }
    }
  GNUNET_free (fn);
  return GNUNET_OK;
}

/**
 * Get the size of the file (or directory)
 * of the given file (in bytes).
 *
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int
GNUNET_disk_file_size (struct GNUNET_GE_Context *ectx,
                       const char *filename,
                       unsigned long long *size, int includeSymLinks)
{
  GetFileSizeData gfsd;
  int ret;

  GNUNET_GE_ASSERT (ectx, size != NULL);
  gfsd.ectx = ectx;
  gfsd.total = 0;
  gfsd.include_sym_links = includeSymLinks;
  ret = getSizeRec (filename, "", &gfsd);
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
long
GNUNET_disk_get_blocks_available (struct GNUNET_GE_Context *ectx,
                                  const char *part)
{
#ifdef SOLARIS
  struct statvfs buf;

  if (0 != statvfs (part, &buf))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_USER |
                                   GNUNET_GE_ADMIN | GNUNET_GE_BULK, "statfs",
                                   part);
      return -1;
    }
  return buf.f_bavail;
#elif MINGW
  DWORD dwDummy;
  DWORD dwBlocks;
  char szDrive[4];

  memcpy (szDrive, part, 3);
  szDrive[3] = 0;
  if (!GetDiskFreeSpace (szDrive, &dwDummy, &dwDummy, &dwBlocks, &dwDummy))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_ADMIN |
                     GNUNET_GE_BULK, _("`%s' failed for drive `%s': %u\n"),
                     "GetDiskFreeSpace", szDrive, GetLastError ());

      return -1;
    }
  return dwBlocks;
#else
  struct statfs s;
  if (0 != statfs (part, &s))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_USER |
                                   GNUNET_GE_ADMIN | GNUNET_GE_BULK, "statfs",
                                   part);
      return -1;
    }
  return s.f_bavail;
#endif
}

/**
 * Test if fil is a directory.
 *
 * @return GNUNET_YES if yes, GNUNET_NO if not, GNUNET_SYSERR if it
 *   does not exist
 */
int
GNUNET_disk_directory_test (struct GNUNET_GE_Context *ectx, const char *fil)
{
  struct stat filestat;
  int ret;

  ret = STAT (fil, &filestat);
  if (ret != 0)
    {
      if (errno != ENOENT)
        {
          GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                       GNUNET_GE_WARNING | GNUNET_GE_USER |
                                       GNUNET_GE_ADMIN | GNUNET_GE_REQUEST,
                                       "stat", fil);
          return GNUNET_SYSERR;
        }
      return GNUNET_NO;
    }
  if (!S_ISDIR (filestat.st_mode))
    return GNUNET_NO;
  if (ACCESS (fil, R_OK | X_OK) < 0)
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_USER |
                                   GNUNET_GE_ADMIN | GNUNET_GE_REQUEST,
                                   "access", fil);
      return GNUNET_SYSERR;
    }
  return GNUNET_YES;
}

/**
 * Check that fil corresponds to a filename
 * (of a file that exists and that is not a directory).
 * @returns GNUNET_YES if yes, GNUNET_NO if not a file, GNUNET_SYSERR if something
 * else (will print an error message in that case, too).
 */
int
GNUNET_disk_file_test (struct GNUNET_GE_Context *ectx, const char *fil)
{
  struct stat filestat;
  int ret;
  char *rdir;

  rdir = GNUNET_expand_file_name (ectx, fil);
  if (rdir == NULL)
    return GNUNET_SYSERR;

  ret = STAT (rdir, &filestat);
  if (ret != 0)
    {
      if (errno != ENOENT)
        {
          GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                       GNUNET_GE_WARNING | GNUNET_GE_USER |
                                       GNUNET_GE_ADMIN | GNUNET_GE_REQUEST,
                                       "stat", rdir);
          GNUNET_free (rdir);
          return GNUNET_SYSERR;
        }
      GNUNET_free (rdir);
      return GNUNET_NO;
    }
  if (!S_ISREG (filestat.st_mode))
    {
      GNUNET_free (rdir);
      return GNUNET_NO;
    }
  if (ACCESS (rdir, R_OK) < 0)
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_USER |
                                   GNUNET_GE_ADMIN | GNUNET_GE_REQUEST,
                                   "access", rdir);
      GNUNET_free (rdir);
      return GNUNET_SYSERR;
    }
  GNUNET_free (rdir);
  return GNUNET_YES;
}

/**
 * Implementation of "mkdir -p"
 * @param dir the directory to create
 * @returns GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_disk_directory_create (struct GNUNET_GE_Context *ectx, const char *dir)
{
  char *rdir;
  int len;
  int pos;
  int ret = GNUNET_OK;

  rdir = GNUNET_expand_file_name (ectx, dir);
  if (rdir == NULL)
    return GNUNET_SYSERR;

  len = strlen (rdir);
#ifndef MINGW
  pos = 1;                      /* skip heading '/' */
#else
  /* Local or Network path? */
  if (strncmp (rdir, "\\\\", 2) == 0)
    {
      pos = 2;
      while (rdir[pos])
        {
          if (rdir[pos] == '\\')
            {
              pos++;
              break;
            }
          pos++;
        }
    }
  else
    {
      pos = 3;                  /* strlen("C:\\") */
    }
#endif
  while (pos <= len)
    {
      if ((rdir[pos] == DIR_SEPARATOR) || (pos == len))
        {
          rdir[pos] = '\0';
          ret = GNUNET_disk_directory_test (ectx, rdir);
          if (ret == GNUNET_SYSERR)
            {
              GNUNET_free (rdir);
              return GNUNET_SYSERR;
            }
          if (ret == GNUNET_NO)
            {
#ifndef MINGW
              ret = mkdir (rdir, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);  /* 755 */
#else
              ret = mkdir (rdir);
#endif
              if ((ret != 0) && (errno != EEXIST))
                {
                  GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                               GNUNET_GE_ERROR |
                                               GNUNET_GE_USER |
                                               GNUNET_GE_BULK, "mkdir", rdir);
                  GNUNET_free (rdir);
                  return GNUNET_SYSERR;
                }
            }
          rdir[pos] = DIR_SEPARATOR;
        }
      pos++;
    }
  GNUNET_free (rdir);
  return GNUNET_OK;
}


/**
 * Create the directory structure for storing
 * a file.
 *
 * @param filename name of a file in the directory
 * @returns GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_disk_directory_create_for_file (struct GNUNET_GE_Context *ectx,
                                       const char *dir)
{
  char *rdir;
  int len;
  int ret;

  rdir = GNUNET_expand_file_name (ectx, dir);
  if (rdir == NULL)
    return GNUNET_SYSERR;
  len = strlen (rdir);
  while ((len > 0) && (rdir[len] != DIR_SEPARATOR))
    len--;
  rdir[len] = '\0';
  ret = GNUNET_disk_directory_create (ectx, rdir);
  GNUNET_free (rdir);
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
int
GNUNET_disk_file_read (struct GNUNET_GE_Context *ectx,
                       const char *fileName, int len, void *result)
{
  /* open file, must exist, open read only */
  int handle;
  int size;

  GNUNET_GE_ASSERT (ectx, fileName != NULL);
  GNUNET_GE_ASSERT (ectx, len > 0);
  if (len == 0)
    return 0;
  GNUNET_GE_ASSERT (ectx, result != NULL);
  handle = GNUNET_disk_file_open (ectx, fileName, O_RDONLY, S_IRUSR);
  if (handle < 0)
    return -1;
  size = READ (handle, result, len);
  GNUNET_disk_file_close (ectx, fileName, handle);
  return size;
}


/**
 * Convert string to value ('755' for chmod-call)
 */
static int
atoo (const char *s)
{
  int n = 0;

  while (('0' <= *s) && (*s < '8'))
    {
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
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_disk_file_write (struct GNUNET_GE_Context *ectx,
                        const char *fileName,
                        const void *buffer, unsigned int n, const char *mode)
{
  int handle;
  char *fn;

  /* open file, open with 600, create if not
     present, otherwise overwrite */
  GNUNET_GE_ASSERT (ectx, fileName != NULL);
  fn = GNUNET_expand_file_name (ectx, fileName);
  handle =
    GNUNET_disk_file_open (ectx, fn, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
  if (handle == -1)
    {
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  GNUNET_GE_ASSERT (ectx, (n == 0) || (buffer != NULL));
  /* write the buffer take length from the beginning */
  if (n != WRITE (handle, buffer, n))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_USER |
                                   GNUNET_GE_IMMEDIATE, "write", fn);
      GNUNET_disk_file_close (ectx, fn, handle);
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  GNUNET_disk_file_close (ectx, fn, handle);
  if (0 != CHMOD (fn, atoo (mode)))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_USER |
                                   GNUNET_GE_BULK, "chmod", fn);
    }
  GNUNET_free (fn);
  return GNUNET_OK;
}

/**
 * Scan a directory for files. The name of the directory
 * must be expanded first (!).
 * @param dirName the name of the directory
 * @param callback the method to call for each file,
 *        can be NULL, in that case, we only count
 * @param data argument to pass to callback
 * @return the number of files found, GNUNET_SYSERR on error or
 *         ieration aborted by callback returning GNUNET_SYSERR
 */
int
GNUNET_disk_directory_scan (struct GNUNET_GE_Context *ectx,
                            const char *dirName,
                            GNUNET_DirectoryEntryCallback callback,
                            void *data)
{
  DIR *dinfo;
  struct dirent *finfo;
  struct stat istat;
  int count = 0;

  GNUNET_GE_ASSERT (ectx, dirName != NULL);
  if (0 != STAT (dirName, &istat))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_USER |
                                   GNUNET_GE_BULK, "stat", dirName);
      return GNUNET_SYSERR;
    }
  if (!S_ISDIR (istat.st_mode))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK,
                     _("Expected `%s' to be a directory!\n"), dirName);
      return GNUNET_SYSERR;
    }
  errno = 0;
  dinfo = OPENDIR (dirName);
  if ((errno == EACCES) || (dinfo == NULL))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_USER |
                                   GNUNET_GE_BULK, "opendir", dirName);
      if (dinfo != NULL)
        closedir (dinfo);
      return GNUNET_SYSERR;
    }
  while ((finfo = readdir (dinfo)) != NULL)
    {
      if ((0 == strcmp (finfo->d_name, ".")) ||
          (0 == strcmp (finfo->d_name, "..")))
        continue;
      if (callback != NULL)
        {
          if (GNUNET_OK != callback (finfo->d_name, dirName, data))
            {
              closedir (dinfo);
              return GNUNET_SYSERR;
            }
        }
      count++;
    }
  closedir (dinfo);
  return count;
}

/**
 * Callback for GNUNET_disk_directory_remove
 */
static int
rmHelper (const char *fil, const char *dir, void *ctx)
{
  struct GNUNET_GE_Context *ectx = ctx;
  char *fn;
  size_t n;

  n = strlen (dir) + strlen (fil) + 2;
  fn = GNUNET_malloc (n);
  GNUNET_snprintf (fn, n, "%s/%s", dir, fil);
  if (GNUNET_SYSERR == GNUNET_disk_directory_remove (ectx, fn))
    {
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  GNUNET_free (fn);
  return GNUNET_OK;
}

/**
 * Remove all files in a directory (rm -rf). Call with
 * caution.
 *
 *
 * @param fileName the file to remove
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_disk_directory_remove (struct GNUNET_GE_Context *ectx,
                              const char *fileName)
{
  struct stat istat;

  if (0 != LSTAT (fileName, &istat))
    return GNUNET_NO;           /* file may not exist... */
  if (UNLINK (fileName) == 0)
    return GNUNET_OK;
  if ((errno != EISDIR) &&
      /* EISDIR is not sufficient in all cases, e.g.
         sticky /tmp directory may result in EPERM on BSD.
         So we also explicitly check "isDirectory" */
      (GNUNET_YES != GNUNET_disk_directory_test (ectx, fileName)))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_USER |
                                   GNUNET_GE_ADMIN | GNUNET_GE_BULK, "rmdir",
                                   fileName);
      return GNUNET_SYSERR;
    }
  if (GNUNET_SYSERR ==
      GNUNET_disk_directory_scan (ectx, fileName, &rmHelper, ectx))
    return GNUNET_SYSERR;
  if (0 != RMDIR (fileName))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_USER |
                                   GNUNET_GE_ADMIN | GNUNET_GE_BULK, "rmdir",
                                   fileName);
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

void
GNUNET_disk_file_close (struct GNUNET_GE_Context *ectx, const char *filename,
                        int fd)
{
  if (0 != CLOSE (fd))
    GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                 GNUNET_GE_WARNING | GNUNET_GE_USER |
                                 GNUNET_GE_BULK, "close", filename);
}

int
GNUNET_disk_file_open (struct GNUNET_GE_Context *ectx, const char *filename,
                       int oflag, ...)
{
  char *fn;
  int mode;
  int ret;
#ifdef MINGW
  char szFile[_MAX_PATH + 1];
  long lRet;

  if ((lRet = plibc_conv_to_win_path (filename, szFile)) != ERROR_SUCCESS)
    {
      errno = ENOENT;
      SetLastError (lRet);
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_USER |
                                   GNUNET_GE_DEVELOPER | GNUNET_GE_ADMIN |
                                   GNUNET_GE_BULK, "plibc_conv_to_win_path",
                                   filename);
      return -1;
    }
  fn = GNUNET_strdup (szFile);
#else
  fn = GNUNET_expand_file_name (ectx, filename);
#endif
  if (oflag & O_CREAT)
    {
      va_list arg;
      va_start (arg, oflag);
      mode = va_arg (arg, int);
      va_end (arg);
    }
  else
    {
      mode = 0;
    }
#ifdef MINGW
  /* set binary mode */
  oflag |= O_BINARY;
#endif
  ret = OPEN (fn, oflag, mode);
  if (ret == -1)
    GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                 GNUNET_GE_WARNING | GNUNET_GE_USER |
                                 GNUNET_GE_BULK, "open", fn);
  GNUNET_free (fn);
  return ret;
}

#define COPY_BLK_SIZE 65536

/**
 * Copy a file.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_disk_file_copy (struct GNUNET_GE_Context *ectx, const char *src,
                       const char *dst)
{
  char *buf;
  unsigned long long pos;
  unsigned long long size;
  unsigned long long len;
  int in;
  int out;

  if (GNUNET_OK != GNUNET_disk_file_size (ectx, src, &size, GNUNET_YES))
    return GNUNET_SYSERR;
  pos = 0;
  in = GNUNET_disk_file_open (ectx, src, O_RDONLY | O_LARGEFILE);
  if (in == -1)
    return GNUNET_SYSERR;
  out = GNUNET_disk_file_open (ectx,
                               dst,
                               O_LARGEFILE | O_WRONLY | O_CREAT | O_EXCL,
                               S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
  if (out == -1)
    {
      GNUNET_disk_file_close (ectx, src, in);
      return GNUNET_SYSERR;
    }
  buf = GNUNET_malloc (COPY_BLK_SIZE);
  while (pos < size)
    {
      len = COPY_BLK_SIZE;
      if (len > size - pos)
        len = size - pos;
      if (len != READ (in, buf, len))
        goto FAIL;
      if (len != WRITE (out, buf, len))
        goto FAIL;
      pos += len;
    }
  GNUNET_free (buf);
  GNUNET_disk_file_close (ectx, src, in);
  GNUNET_disk_file_close (ectx, dst, out);
  return GNUNET_OK;
FAIL:
  GNUNET_free (buf);
  GNUNET_disk_file_close (ectx, src, in);
  GNUNET_disk_file_close (ectx, dst, out);
  return GNUNET_SYSERR;
}

/* end of storage.c */
