/*
     This file is part of GNUnet.
     (C) 2002, 2003, 2004, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/state/state.c
 * @brief tiny, stateful database too keep track of internal state
 *
 * Directory based implementation of a tiny, stateful database
 * to keep track of GNUnet _internal_ configuration parameters
 * that users are not supposed to see (e.g. *previous* quota,
 * previous database type for AFS, etc.)
 *
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_core.h"
#include "gnunet_directories.h"
#include "gnunet_state_service.h"
#include "platform.h"

#define STATE_DEBUG NO

#define DIR_EXT "state.sdb"

static char *handle;

/**
 * Read the contents of a bucket to a buffer.
 *
 * @param name the hashcode representing the entry
 * @param result the buffer to write the result to
 *        (*result should be NULL, sufficient space is allocated)
 * @return the number of bytes read on success, -1 on failure
 */
static int
stateReadContent (struct GE_Context *ectx, const char *name, void **result)
{
  /* open file, must exist, open read only */
  char *dbh = handle;
  int fd;
  int size;
  char *fil;
  unsigned long long fsize;
  size_t n;

  GE_ASSERT (ectx, handle != NULL);
  if (result == NULL)
    return -1;
  n = strlen (dbh) + strlen (name) + 2;
  fil = MALLOC (n);
  SNPRINTF (fil, n, "%s/%s", dbh, name);
  if ((OK != disk_file_test (ectx,
                             fil)) ||
      (OK != disk_file_size (ectx,
                             fil,
                             &fsize,
                             YES)) ||
      (fsize == 0) ||
      (-1 == (fd = disk_file_open (ectx, fil, O_RDONLY, S_IRUSR))))
    {
      FREE (fil);
      return -1;
    }
  *result = MALLOC_LARGE (fsize);
  size = READ (fd, *result, fsize);
  disk_file_close (ectx, fil, fd);
  FREE (fil);
  if (size == -1)
    {
      FREE (*result);
      *result = NULL;
    }
  return size;
}


/**
 * Append content to file.
 *
 * @param name the key for the entry
 * @param len the number of bytes in block
 * @param block the data to store
 * @return SYSERR on error, OK if ok.
 */
static int
stateAppendContent (struct GE_Context *ectx,
                    const char *name, int len, const void *block)
{
  char *dbh = handle;
  char *fil;
  int fd;
  size_t n;

  GE_ASSERT (ectx, handle != NULL);
  n = strlen (dbh) + strlen (name) + 2;
  fil = MALLOC (n);
  SNPRINTF (fil, n, "%s/%s", dbh, name);
  fd = disk_file_open (ectx, fil, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  if (fd == -1)
    {
      GE_LOG_STRERROR_FILE (ectx,
                            GE_WARNING | GE_BULK | GE_USER, "open", fil);
      FREE (fil);
      return SYSERR;            /* failed! */
    }
  LSEEK (fd, 0, SEEK_END);
  WRITE (fd, block, len);
  disk_file_close (ectx, fil, fd);
  FREE (fil);
  return OK;
}

/**
 * Write content to a file.
 *
 * @param name the key for the entry
 * @param len the number of bytes in block
 * @param block the data to store
 * @return SYSERR on error, OK if ok.
 */
static int
stateWriteContent (struct GE_Context *ectx,
                   const char *name, int len, const void *block)
{
  char *dbh = handle;
  char *fil;
  int fd;
  size_t n;

  GE_ASSERT (ectx, handle != NULL);
  n = strlen (dbh) + strlen (name) + 2;
  fil = MALLOC (n);
  SNPRINTF (fil, n, "%s/%s", dbh, name);
  fd = disk_file_open (ectx, fil, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  if (fd == -1)
    {
      GE_LOG_STRERROR_FILE (ectx,
                            GE_WARNING | GE_BULK | GE_USER, "open", fil);
      FREE (fil);
      return SYSERR;            /* failed! */
    }
  WRITE (fd, block, len);
  if (0 != FTRUNCATE (fd, len))
    GE_LOG_STRERROR_FILE (ectx,
                          GE_WARNING | GE_BULK | GE_ADMIN, "ftruncate", fil);
  disk_file_close (ectx, fil, fd);
  FREE (fil);
  return OK;
}

/**
 * Free space in the database by removing one file
 * @param name the hashcode representing the name of the file
 *        (without directory)
 */
static int
stateUnlinkFromDB (struct GE_Context *ectx, const char *name)
{
  char *dbh = handle;
  char *fil;
  size_t n;

  GE_ASSERT (ectx, handle != NULL);
  n = strlen (dbh) + strlen (name) + 2;
  fil = MALLOC (n);
  SNPRINTF (fil, n, "%s/%s", dbh, name);
  UNLINK (fil);
  FREE (fil);
  return OK;
}

State_ServiceAPI *
provide_module_state (CoreAPIForApplication * capi)
{
  static State_ServiceAPI api;

  char *dbh;
  size_t n;

  dbh = NULL;
  if (-1 == GC_get_configuration_value_filename (capi->cfg,
                                                 "GNUNETD",
                                                 "GNUNETD_HOME",
                                                 VAR_DAEMON_DIRECTORY, &dbh))
    return NULL;
  GE_ASSERT (capi->ectx, dbh != NULL);
  n = strlen (dbh) + strlen (DIR_EXT) + 5;
  handle = MALLOC (n);
  SNPRINTF (handle, n, "%s/%s/", dbh, DIR_EXT);
  FREE (dbh);
  if (SYSERR == disk_directory_create (capi->ectx, handle))
    {
      FREE (handle);
      handle = NULL;
      return NULL;
    }
  api.read = &stateReadContent;
  api.append = &stateAppendContent;
  api.write = &stateWriteContent;
  api.unlink = &stateUnlinkFromDB;
  return &api;
}

/**
 * Clean shutdown of the storage module (not used at the moment)
 */
void
release_module_state ()
{
  GE_ASSERT (NULL, handle != NULL);
  FREE (handle);
  handle = NULL;
}

/* end of state.c */
