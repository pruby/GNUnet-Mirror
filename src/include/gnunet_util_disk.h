/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_util_disk.h
 * @brief disk IO apis
 */

#ifndef GNUNET_UTIL_DISK_H
#define GNUNET_UTIL_DISK_H

#include "gnunet_util_error.h"

/* we need size_t, and since it can be both unsigned int
   or unsigned long long, this IS platform dependent;
   but "stdlib.h" should be portable 'enough' to be
   unconditionally available... */
#include <stdlib.h>

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Get the number of blocks that are left on the partition that
 * contains the given file (for normal users).
 *
 * @param part a file on the partition to check
 * @return -1 on errors, otherwise the number of free blocks
 */
long GNUNET_disk_get_blocks_available (struct GNUNET_GE_Context *ectx,
                                       const char *part);

/**
 * Check that fil corresponds to a filename
 * (of a file that exists and that is not a directory).
 *
 * @returns GNUNET_YES if yes, GNUNET_NO if not a file, GNUNET_SYSERR if something
 * else (will print an error message in that case, too).
 */
int GNUNET_disk_file_test (struct GNUNET_GE_Context *ectx, const char *fil);

/**
 * Get the size of the file (or directory)
 * of the given file (in bytes).
 *
 * @param includeSymLinks should symbolic links be
 *        included?
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_disk_file_size (struct GNUNET_GE_Context *ectx,
                           const char *filename,
                           unsigned long long *size, int includeSymLinks);

/**
 * Wrapper around "open()".  Opens a file.
 *
 * @return file handle, -1 on error
 */
int GNUNET_disk_file_open (struct GNUNET_GE_Context *ectx,
                           const char *filename, int oflag, ...);

/**
 * Wrapper around "close()".  Closes a file.
 */
void GNUNET_disk_file_close (struct GNUNET_GE_Context *ectx,
                             const char *filename, int fd);

/**
 * Read the contents of a binary file into a buffer.
 * @param fileName the name of the file, not freed,
 *        must already be expanded!
 * @param len the maximum number of bytes to read
 * @param result the buffer to write the result to
 * @return the number of bytes read on success, -1 on failure
 */
int GNUNET_disk_file_read (struct GNUNET_GE_Context *ectx,
                           const char *fileName, int len, void *result);

/**
 * Write a buffer to a file.
 * @param fileName the name of the file, NOT freed!
 * @param buffer the data to write
 * @param n number of bytes to write
 * @param mode the mode for file permissions
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_disk_file_write (struct GNUNET_GE_Context *ectx,
                            const char *fileName,
                            const void *buffer, unsigned int n,
                            const char *mode);

/**
 * Copy a file.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_disk_file_copy (struct GNUNET_GE_Context *ectx,
                           const char *src, const char *dst);

/**
 * Scan a directory for files. The name of the directory
 * must be expanded first (!).
 *
 * @param dirName the name of the directory
 * @param callback the method to call for each file
 * @param data argument to pass to callback
 * @return the number of files found, -1 on error
 */
int GNUNET_disk_directory_scan (struct GNUNET_GE_Context *ectx,
                                const char *dirName,
                                GNUNET_FileNameCallback callback, void *data);


/**
 * Create the directory structure for storing
 * a file.
 *
 * @param filename name of a file in the directory
 * @returns GNUNET_OK on success, GNUNET_SYSERR on failure,
 *          GNUNET_NO if directory exists but is not writeable
 */
int GNUNET_disk_directory_create_for_file (struct GNUNET_GE_Context *ectx,
                                           const char *filename);

/**
 * Test if fil is a directory that can be accessed.
 * Will not print an error message if the directory
 * does not exist.  Will log errors if GNUNET_SYSERR is
 * returned.
 *
 * @return GNUNET_YES if yes, GNUNET_NO if does not exist, GNUNET_SYSERR
 *   on any error and if exists but not directory
 */
int GNUNET_disk_directory_test (struct GNUNET_GE_Context *ectx,
                                const char *fil);

/**
 * Remove all files in a directory (rm -rf). Call with
 * caution.
 *
 * @param fileName the file to remove
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_disk_directory_remove (struct GNUNET_GE_Context *ectx,
                                  const char *fileName);

/**
 * Implementation of "mkdir -p"
 *
 * @param dir the directory to create
 * @returns GNUNET_SYSERR on failure, GNUNET_OK otherwise
 */
int GNUNET_disk_directory_create (struct GNUNET_GE_Context *ectx,
                                  const char *dir);

/**
 * @brief Removes special characters as ':' from a filename.
 * @param fn the filename to canonicalize
 */
void GNUNET_disk_filename_canonicalize (char *fn);


/**
 * Construct full path to a file inside of the private
 * directory used by GNUnet.  Also creates the corresponding
 * directory.  If the resulting name is supposed to be
 * a directory, end the last argument in '/' (or pass
 * DIR_SEPARATOR_STR as the last argument before NULL).
 *
 * @param is_daemon are we gnunetd or a client?
 * @param varargs is NULL-terminated list of
 *                path components to append to the
 *                private directory name.
 * @return the constructed filename
 */
char *GNUNET_get_home_filename (struct GNUNET_GE_Context *ectx,
                                struct GNUNET_GC_Configuration *cfg,
                                int is_daemon, ...);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_UTIL_DISK_H */
#endif
/* end of gnunet_util_disk.h */
