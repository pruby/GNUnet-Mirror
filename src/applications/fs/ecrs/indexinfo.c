/*
     This file is part of GNUnet.
     (C) 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/indexinfo.c
 * @brief information about indexed files
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_fs_lib.h"
#include "gnunet_getoption_lib.h"

/**
 * Test if a file is indexed.
 *
 * @return GNUNET_YES if the file is indexed, GNUNET_NO if not, GNUNET_SYSERR on errors
 *  (i.e. filename could not be accessed and thus we have problems
 *  checking; also possible that the file was modified after indexing;
 *  in either case, if GNUNET_SYSERR is returned the user should probably
 *  be notified that 'something is wrong')
 */
int
GNUNET_ECRS_file_test_indexed (struct GNUNET_GE_Context *ectx,
                               struct GNUNET_GC_Configuration *cfg,
                               const char *filename)
{
  GNUNET_HashCode hc;
  struct GNUNET_ClientServerConnection *sock;
  int ret;

  if (GNUNET_SYSERR == GNUNET_hash_file (ectx, filename, &hc))
    return GNUNET_SYSERR;
  sock = GNUNET_client_connection_create (ectx, cfg);
  if (sock == NULL)
    return GNUNET_SYSERR;
  ret = GNUNET_FS_test_indexed (sock, &hc);
  GNUNET_client_connection_destroy (sock);
  return ret;
}

struct iiC
{
  struct GNUNET_GE_Context *ectx;
  GNUNET_ECRS_FileProcessor iterator;
  void *closure;
  int cnt;
};

static int
iiHelper (const char *fn, const char *dir, void *ptr)
{
  struct iiC *cls = ptr;
  char *fullName;
  char *lnkName;
  unsigned int size;
  int ret;

  fullName = GNUNET_malloc (strlen (dir) + strlen (fn) + 4);
  strcpy (fullName, dir);
  strcat (fullName, DIR_SEPARATOR_STR);
  strcat (fullName, fn);
  size = 256;
  lnkName = GNUNET_malloc (size);
  while (1)
    {
      ret = READLINK (fullName, lnkName, size - 1);
      if (ret == -1)
        {
          if (errno == ENAMETOOLONG)
            {
              if (size * 2 < size)
                {
                  GNUNET_free (lnkName);
                  GNUNET_free (fullName);
                  return GNUNET_OK;     /* error */
                }
              GNUNET_array_grow (lnkName, size, size * 2);
              continue;
            }
          if (errno != EINVAL)
            {
              GNUNET_GE_LOG_STRERROR_FILE (cls->ectx,
                                           GNUNET_GE_WARNING | GNUNET_GE_BULK
                                           | GNUNET_GE_ADMIN | GNUNET_GE_USER,
                                           "readlink", fullName);
            }
          GNUNET_free (lnkName);
          GNUNET_free (fullName);
          return GNUNET_OK;     /* error */
        }
      else
        {
          lnkName[ret] = '\0';
          break;
        }
    }
  cls->cnt++;
  if (GNUNET_OK != cls->iterator (lnkName, cls->closure))
    {
      cls->cnt = GNUNET_SYSERR;
      GNUNET_free (fullName);
      GNUNET_free (lnkName);
      return GNUNET_SYSERR;
    }
  GNUNET_free (fullName);
  GNUNET_free (lnkName);
  return GNUNET_OK;
}

/**
 * Iterate over all indexed files.
 *
 * This function will ONLY work if gnunetd runs on the
 * same machine as the current process and if the indexed
 * files could be symlinked.  If indexed files had to be
 * uploaded to a remote machine or copied, the original
 * names will have been lost.  In that case, the iterator
 * will NOT iterate over these files.
 *
 * @return number of files indexed, GNUNET_SYSERR if iterator aborted
 */
int
GNUNET_ECRS_get_indexed_files (struct GNUNET_GE_Context *ectx,
                               struct GNUNET_GC_Configuration *cfg,
                               GNUNET_ECRS_FileProcessor iterator,
                               void *closure)
{
  char *tmp;
  char *indexDirectory;
  struct GNUNET_ClientServerConnection *sock;
  struct iiC cls;

  sock = GNUNET_client_connection_create (ectx, cfg);
  if (sock == NULL)
    return 0;
  tmp = GNUNET_get_daemon_configuration_value (sock, "FS", "INDEX-DIRECTORY");
  GNUNET_client_connection_destroy (sock);
  if (tmp == NULL)
    {
      return 0;
    }
  indexDirectory = GNUNET_expand_file_name (ectx, tmp);
  GNUNET_free (tmp);
  cls.ectx = ectx;
  cls.iterator = iterator;
  cls.closure = closure;
  cls.cnt = 0;
  GNUNET_disk_directory_scan (ectx, indexDirectory, &iiHelper, &cls);
  GNUNET_free (indexDirectory);
  return cls.cnt;
}

/* end of indexinfo.c */
