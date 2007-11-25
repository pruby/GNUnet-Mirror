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

#define STATE_DEBUG GNUNET_NO

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
stateReadContent (struct GNUNET_GE_Context *ectx, const char *name,
                  void **result)
{
  /* open file, must exist, open read only */
  char *dbh = handle;
  int fd;
  int size;
  char *fil;
  unsigned long long fsize;
  size_t n;

  GNUNET_GE_ASSERT (ectx, handle != NULL);
  if (result == NULL)
    return -1;
  n = strlen (dbh) + strlen (name) + 2;
  fil = GNUNET_malloc (n);
  GNUNET_snprintf (fil, n, "%s/%s", dbh, name);
  if ((GNUNET_OK != GNUNET_disk_file_test (ectx,
                                           fil)) ||
      (GNUNET_OK != GNUNET_disk_file_size (ectx,
                                           fil,
                                           &fsize,
                                           GNUNET_YES)) ||
      (fsize == 0) ||
      (-1 == (fd = GNUNET_disk_file_open (ectx, fil, O_RDONLY, S_IRUSR))))
    {
      GNUNET_free (fil);
      return -1;
    }
  *result = GNUNET_malloc_large (fsize);
  size = READ (fd, *result, fsize);
  GNUNET_disk_file_close (ectx, fil, fd);
  GNUNET_free (fil);
  if (size == -1)
    {
      GNUNET_free (*result);
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
 * @return GNUNET_SYSERR on error, GNUNET_OK if ok.
 */
static int
stateAppendContent (struct GNUNET_GE_Context *ectx,
                    const char *name, int len, const void *block)
{
  char *dbh = handle;
  char *fil;
  int fd;
  size_t n;

  GNUNET_GE_ASSERT (ectx, handle != NULL);
  n = strlen (dbh) + strlen (name) + 2;
  fil = GNUNET_malloc (n);
  GNUNET_snprintf (fil, n, "%s/%s", dbh, name);
  fd = GNUNET_disk_file_open (ectx, fil, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  if (fd == -1)
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_BULK |
                                   GNUNET_GE_USER, "open", fil);
      GNUNET_free (fil);
      return GNUNET_SYSERR;     /* failed! */
    }
  LSEEK (fd, 0, SEEK_END);
  WRITE (fd, block, len);
  GNUNET_disk_file_close (ectx, fil, fd);
  GNUNET_free (fil);
  return GNUNET_OK;
}

/**
 * Write content to a file.
 *
 * @param name the key for the entry
 * @param len the number of bytes in block
 * @param block the data to store
 * @return GNUNET_SYSERR on error, GNUNET_OK if ok.
 */
static int
stateWriteContent (struct GNUNET_GE_Context *ectx,
                   const char *name, int len, const void *block)
{
  char *dbh = handle;
  char *fil;
  int fd;
  size_t n;

  GNUNET_GE_ASSERT (ectx, handle != NULL);
  n = strlen (dbh) + strlen (name) + 2;
  fil = GNUNET_malloc (n);
  GNUNET_snprintf (fil, n, "%s/%s", dbh, name);
  fd = GNUNET_disk_file_open (ectx, fil, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  if (fd == -1)
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_BULK |
                                   GNUNET_GE_USER, "open", fil);
      GNUNET_free (fil);
      return GNUNET_SYSERR;     /* failed! */
    }
  WRITE (fd, block, len);
  if (0 != FTRUNCATE (fd, len))
    GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                 GNUNET_GE_WARNING | GNUNET_GE_BULK |
                                 GNUNET_GE_ADMIN, "ftruncate", fil);
  GNUNET_disk_file_close (ectx, fil, fd);
  GNUNET_free (fil);
  return GNUNET_OK;
}

/**
 * Free space in the database by removing one file
 * @param name the hashcode representing the name of the file
 *        (without directory)
 */
static int
stateUnlinkFromDB (struct GNUNET_GE_Context *ectx, const char *name)
{
  char *dbh = handle;
  char *fil;
  size_t n;

  GNUNET_GE_ASSERT (ectx, handle != NULL);
  n = strlen (dbh) + strlen (name) + 2;
  fil = GNUNET_malloc (n);
  GNUNET_snprintf (fil, n, "%s/%s", dbh, name);
  UNLINK (fil);
  GNUNET_free (fil);
  return GNUNET_OK;
}

GNUNET_State_ServiceAPI *
provide_module_state (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_State_ServiceAPI api;

  char *dbh;
  size_t n;

  dbh = NULL;
  if (-1 == GNUNET_GC_get_configuration_value_filename (capi->cfg,
                                                        "GNUNETD",
                                                        "GNUNETD_HOME",
                                                        GNUNET_DEFAULT_DAEMON_VAR_DIRECTORY,
                                                        &dbh))
    return NULL;
  GNUNET_GE_ASSERT (capi->ectx, dbh != NULL);
  n = strlen (dbh) + strlen (DIR_EXT) + 5;
  handle = GNUNET_malloc (n);
  GNUNET_snprintf (handle, n, "%s/%s/", dbh, DIR_EXT);
  GNUNET_free (dbh);
  if (GNUNET_SYSERR == GNUNET_disk_directory_create (capi->ectx, handle))
    {
      GNUNET_free (handle);
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
  GNUNET_GE_ASSERT (NULL, handle != NULL);
  GNUNET_free (handle);
  handle = NULL;
}

/* end of state.c */
