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

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_util.h"
#include "gnunet_uritrack_lib.h"
#include "callbacks.h"

#define DEBUG_FILE_INFO GNUNET_NO

#define STATE_NAME DIR_SEPARATOR_STR "data" DIR_SEPARATOR_STR "fs_uridb"
#define TRACK_OPTION "fs_uridb_status"

static struct GNUNET_IPC_Semaphore *
createIPC (struct GNUNET_GE_Context *ectx,
           struct GNUNET_GC_Configuration *cfg)
{
  char *ipcName;
  struct GNUNET_IPC_Semaphore *sem;

  ipcName =
    GNUNET_get_home_filename (ectx, cfg, GNUNET_NO, "uritrack_ipc_lock",
                              NULL);
  sem = GNUNET_IPC_semaphore_create (ectx, ipcName, 1);
  GNUNET_free (ipcName);
  return sem;
}

static char *
getUriDbName (struct GNUNET_GE_Context *ectx,
              struct GNUNET_GC_Configuration *cfg)
{
  return GNUNET_get_home_filename (ectx, cfg, GNUNET_NO, STATE_NAME, NULL);
}

static char *
getToggleName (struct GNUNET_GE_Context *ectx,
               struct GNUNET_GC_Configuration *cfg)
{
  return GNUNET_get_home_filename (ectx, cfg, GNUNET_NO, TRACK_OPTION, NULL);
}

/**
 * Get the URITRACK URI tracking status.
 *
 * @return GNUNET_YES of tracking is enabled, GNUNET_NO if not
 */
int
GNUNET_URITRACK_get_tracking_status (struct GNUNET_GE_Context *ectx,
                                     struct GNUNET_GC_Configuration *cfg)
{
  int status;
  char *tn;

  tn = getToggleName (ectx, cfg);
  if (GNUNET_YES != GNUNET_disk_file_test (ectx, tn))
    {
      GNUNET_free (tn);
      return GNUNET_NO;         /* default: off */
    }
  if ((sizeof (int) != GNUNET_disk_file_read (ectx,
                                              tn,
                                              sizeof (int),
                                              &status))
      || (ntohl (status) != GNUNET_YES))
    {
      GNUNET_free (tn);
#if DEBUG_FILE_INFO
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     _("Collecting file identifiers disabled.\n"));
#endif
      return GNUNET_NO;
    }
  else
    {
      GNUNET_free (tn);
      return GNUNET_YES;
    }
}

struct CheckPresentClosure
{
  const GNUNET_ECRS_FileInfo *fi;
  int present;
};

static int
checkPresent (const GNUNET_ECRS_FileInfo * fi,
              const GNUNET_HashCode * key, int isRoot, void *closure)
{
  struct CheckPresentClosure *cpc = closure;
  if (GNUNET_ECRS_uri_test_equal (fi->uri, cpc->fi->uri))
    {
      cpc->present = 1;
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

/**
 * Makes a URI available for directory building.
 */
void
GNUNET_URITRACK_track (struct GNUNET_GE_Context *ectx,
                       struct GNUNET_GC_Configuration *cfg,
                       const GNUNET_ECRS_FileInfo * fi)
{
  struct GNUNET_IPC_Semaphore *sem;
  char *data;
  unsigned int size;
  char *suri;
  int fh;
  char *fn;
  struct CheckPresentClosure cpc;

  if (GNUNET_NO == GNUNET_URITRACK_get_tracking_status (ectx, cfg))
    return;
  cpc.present = 0;
  cpc.fi = fi;
  GNUNET_URITRACK_list (ectx, cfg, GNUNET_NO, &checkPresent, &cpc);
  if (cpc.present == 1)
    return;
  size = GNUNET_meta_data_get_serialized_size (fi->meta,
                                               GNUNET_SERIALIZE_FULL
                                               |
                                               GNUNET_SERIALIZE_NO_COMPRESS);
  data = GNUNET_malloc (size);
  GNUNET_GE_ASSERT (ectx,
                    size == GNUNET_meta_data_serialize (ectx,
                                                        fi->meta,
                                                        data,
                                                        size,
                                                        GNUNET_SERIALIZE_FULL
                                                        |
                                                        GNUNET_SERIALIZE_NO_COMPRESS));
  size = htonl (size);
  suri = GNUNET_ECRS_uri_to_string (fi->uri);
  sem = createIPC (ectx, cfg);
  GNUNET_IPC_semaphore_down (sem, GNUNET_YES);
  fn = getUriDbName (ectx, cfg);
  fh = GNUNET_disk_file_open (ectx,
                              fn,
                              O_WRONLY | O_APPEND | O_CREAT |
                              O_LARGEFILE, S_IRUSR | S_IWUSR);
  if (fh != -1)
    {
      WRITE (fh, suri, strlen (suri) + 1);
      WRITE (fh, &size, sizeof (unsigned int));
      WRITE (fh, data, ntohl (size));
      CLOSE (fh);
    }
  GNUNET_free (fn);
  GNUNET_IPC_semaphore_up (sem);
  GNUNET_IPC_semaphore_destroy (sem);
  GNUNET_free (data);
  GNUNET_free (suri);
  GNUNET_URITRACK_internal_notify (fi);
}

/**
 * Remove all of the root-nodes of a particular type
 * from the tracking database.
 */
void
GNUNET_URITRACK_clear (struct GNUNET_GE_Context *ectx,
                       struct GNUNET_GC_Configuration *cfg)
{
  struct GNUNET_IPC_Semaphore *sem;
  char *fn;

  sem = createIPC (ectx, cfg);
  GNUNET_IPC_semaphore_down (sem, GNUNET_YES);
  fn = getUriDbName (ectx, cfg);
  if (GNUNET_YES == GNUNET_disk_file_test (ectx, fn))
    {
      if (0 != UNLINK (fn))
        GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                     GNUNET_GE_ERROR | GNUNET_GE_USER |
                                     GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                                     "unlink", fn);
    }
  GNUNET_free (fn);
  GNUNET_IPC_semaphore_up (sem);
  GNUNET_IPC_semaphore_destroy (sem);
}

/**
 * Toggle tracking URIs.
 *
 * @param onOff GNUNET_YES to enable tracking, GNUNET_NO to disable
 *  disabling tracking
 */
void
GNUNET_URITRACK_toggle_tracking (struct GNUNET_GE_Context *ectx,
                                 struct GNUNET_GC_Configuration *cfg,
                                 int onOff)
{
  int o = htonl (onOff);
  char *tn;

  tn = getToggleName (ectx, cfg);
  GNUNET_disk_file_write (ectx, tn, &o, sizeof (int), "600");
  GNUNET_free (tn);
}

/**
 * Iterate over all entries that match the given context
 * mask.
 *
 * @param iterator function to call on each entry, may be NULL
 * @param closure extra argument to the callback
 * @param need_metadata GNUNET_YES if metadata should be
 *        provided, GNUNET_NO if metadata is not needed (faster)
 * @return number of entries found
 */
int
GNUNET_URITRACK_list (struct GNUNET_GE_Context *ectx,
                      struct GNUNET_GC_Configuration *cfg,
                      int need_metadata,
                      GNUNET_ECRS_SearchResultProcessor iterator,
                      void *closure)
{
  struct GNUNET_IPC_Semaphore *sem;
  int rval;
  char *result;
  off_t ret;
  off_t pos;
  off_t spos;
  unsigned int msize;
  GNUNET_ECRS_FileInfo fi;
  int fd;
  char *fn;
  struct stat buf;

  fn = getUriDbName (ectx, cfg);
  sem = createIPC (ectx, cfg);
  GNUNET_IPC_semaphore_down (sem, GNUNET_YES);
  if ((0 != STAT (fn, &buf)) || (buf.st_size == 0))
    {
      GNUNET_IPC_semaphore_up (sem);
      GNUNET_IPC_semaphore_destroy (sem);
      GNUNET_free (fn);
      return 0;                 /* no URI db */
    }
  fd = GNUNET_disk_file_open (ectx, fn, O_LARGEFILE | O_RDONLY);
  if (fd == -1)
    {
      GNUNET_IPC_semaphore_up (sem);
      GNUNET_IPC_semaphore_destroy (sem);
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_ERROR | GNUNET_GE_USER |
                                   GNUNET_GE_ADMIN | GNUNET_GE_BULK, "open",
                                   fn);
      GNUNET_free (fn);
      return GNUNET_SYSERR;     /* error opening URI db */
    }
  result = MMAP (NULL, buf.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (result == MAP_FAILED)
    {
      CLOSE (fd);
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_ERROR | GNUNET_GE_USER |
                                   GNUNET_GE_ADMIN | GNUNET_GE_BULK, "mmap",
                                   fn);
      GNUNET_free (fn);
      GNUNET_IPC_semaphore_up (sem);
      GNUNET_IPC_semaphore_destroy (sem);
      return GNUNET_SYSERR;
    }
  ret = buf.st_size;
  pos = 0;
  rval = 0;
  while (pos < ret)
    {
      spos = pos;
      while ((spos < ret) && (result[spos] != '\0'))
        spos++;
      spos++;                   /* skip '\0' */
      if (spos + sizeof (int) >= ret)
        {
          GNUNET_GE_BREAK (ectx, 0);
          goto FORMATERROR;
        }
      fi.uri = GNUNET_ECRS_string_to_uri (ectx, &result[pos]);
      if (fi.uri == NULL)
        {
          GNUNET_GE_BREAK (ectx, 0);
          goto FORMATERROR;
        }
      memcpy (&msize, &result[spos], sizeof (int));
      msize = ntohl (msize);
      spos += sizeof (int);
      if ((spos + msize > ret) || (spos + msize < spos))
        {
          GNUNET_GE_BREAK (ectx, 0);
          GNUNET_ECRS_uri_destroy (fi.uri);
          goto FORMATERROR;
        }
      if (need_metadata == GNUNET_YES)
        {
          fi.meta = GNUNET_meta_data_deserialize (ectx, &result[spos], msize);
          if (fi.meta == NULL)
            {
              GNUNET_GE_BREAK (ectx, 0);
              GNUNET_ECRS_uri_destroy (fi.uri);
              goto FORMATERROR;
            }
        }
      else
        {
          fi.meta = NULL;
        }
      pos = spos + msize;
      if (iterator != NULL)
        {
          if (GNUNET_OK != iterator (&fi, NULL, GNUNET_NO, closure))
            {
              if (fi.meta != NULL)
                GNUNET_meta_data_destroy (fi.meta);
              GNUNET_ECRS_uri_destroy (fi.uri);
              if (0 != MUNMAP (result, buf.st_size))
                GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                             GNUNET_GE_ERROR | GNUNET_GE_ADMIN
                                             | GNUNET_GE_BULK, "munmap", fn);
              CLOSE (fd);
              GNUNET_free (fn);
              GNUNET_IPC_semaphore_up (sem);
              GNUNET_IPC_semaphore_destroy (sem);
              return GNUNET_SYSERR;     /* iteration aborted */
            }
        }
      rval++;
      if (fi.meta != NULL)
        GNUNET_meta_data_destroy (fi.meta);
      GNUNET_ECRS_uri_destroy (fi.uri);
    }
  if (0 != MUNMAP (result, buf.st_size))
    GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                 GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                 GNUNET_GE_BULK, "munmap", fn);
  CLOSE (fd);
  GNUNET_free (fn);
  GNUNET_IPC_semaphore_up (sem);
  GNUNET_IPC_semaphore_destroy (sem);
  return rval;
FORMATERROR:
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                 _("Deleted corrupt URI database in `%s'."), STATE_NAME);
  if (0 != MUNMAP (result, buf.st_size))
    GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                 GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                 GNUNET_GE_BULK, "munmap", fn);
  CLOSE (fd);
  GNUNET_free (fn);
  GNUNET_IPC_semaphore_up (sem);
  GNUNET_IPC_semaphore_destroy (sem);
  GNUNET_URITRACK_clear (ectx, cfg);
  return GNUNET_SYSERR;
}


/* end of file_info.c */
