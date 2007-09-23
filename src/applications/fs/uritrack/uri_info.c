/*
     This file is part of GNUnet.
     (C) 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/uritrack/uri_info.c
 * @brief information about URIs
 * @author Christian Grothoff
 *
 * Note that the information is only accurate with "high
 * probability" but not at all guaranteed (this is done
 * to bound disk size of the DB and to get high performance).
 */

#include "gnunet_directories.h"
#include "gnunet_util.h"
#include "gnunet_uritrack_lib.h"
#include "platform.h"

static char *
getDBName (struct GC_Configuration *cfg)
{
  char *basename;
  char *ipcName;
  size_t n;

  GC_get_configuration_value_filename (cfg,
                                       "GNUNET",
                                       "GNUNET_HOME",
                                       GNUNET_HOME_DIRECTORY, &basename);
  n = strlen (basename) + 512;
  ipcName = MALLOC (n);
  SNPRINTF (ipcName, n, "%s/uri_info.db", basename);
  FREE (basename);
  return ipcName;
}

static unsigned long long
getDBSize (struct GC_Configuration *cfg)
{
  unsigned long long value;

  value = 1024 * 1024;
  GC_get_configuration_value_number (cfg,
                                     "FS",
                                     "URI_DB_SIZE",
                                     1,
                                     1024 * 1024 * 1024, 1024 * 1024, &value);
  return value;
}

/**
 * Find out what we know about a given URI's past.  Note that we only
 * track the states for a (finite) number of URIs and that the
 * information that we give back maybe inaccurate (returning
 * URITRACK_FRESH if the URI did not fit into our bounded-size map,
 * even if the URI is not fresh anymore; also, if the URI has a
 * hash-collision in the map, there is a 1:256 chance that we will
 * return information from the wrong URI without detecting it).
 */
enum URITRACK_STATE
URITRACK_getState (struct GE_Context *ectx,
                   struct GC_Configuration *cfg, const struct ECRS_URI *uri)
{
  char *s;
  int crc;
  int fd;
  unsigned long long size;
  unsigned char io[2];
  off_t o;

  s = ECRS_uriToString (uri);
  crc = crc32N (s, strlen (s));
  FREE (s);
  s = getDBName (cfg);
  if (NO == disk_file_test (ectx, s))
    return URITRACK_FRESH;
  size = getDBSize (cfg);
  fd = disk_file_open (ectx, s, O_RDONLY);
  FREE (s);
  if (fd == -1)
    return URITRACK_FRESH;
  o = 2 * (crc % size);
  if (o != LSEEK (fd, o, SEEK_SET))
    {
      GE_LOG_STRERROR_FILE (ectx,
                            GE_WARNING | GE_USER | GE_ADMIN | GE_BULK,
                            "lseek", s);
      CLOSE (fd);
      return URITRACK_FRESH;
    }
  if (2 != read (fd, io, 2))
    {
      CLOSE (fd);
      return URITRACK_FRESH;
    }
  CLOSE (fd);
  if (io[0] == (unsigned char) crc)
    return (enum URITRACK_STATE) io[1];
  return URITRACK_FRESH;
}

/**
 * Add additional information about a given URI's past.
 */
void
URITRACK_addState (struct GE_Context *ectx,
                   struct GC_Configuration *cfg,
                   const struct ECRS_URI *uri, enum URITRACK_STATE state)
{
  char *s;
  int crc;
  int fd;
  unsigned long long size;
  unsigned char io[2];
  off_t o;

  s = ECRS_uriToString (uri);
  crc = crc32N (s, strlen (s));
  FREE (s);
  s = getDBName (cfg);
  size = getDBSize (cfg);
  fd = disk_file_open (ectx, s, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  if (fd == -1)
    {
      FREE (s);
      return;
    }
  o = 2 * (crc % size);
  if (o != LSEEK (fd, o, SEEK_SET))
    {
      GE_LOG_STRERROR_FILE (ectx,
                            GE_WARNING | GE_USER | GE_ADMIN | GE_BULK,
                            "lseek", s);
      CLOSE (fd);
      FREE (s);
      return;
    }
  if (2 != read (fd, io, 2))
    {
      io[0] = crc;
      io[1] = URITRACK_FRESH;
    }
  else if (io[0] != (unsigned char) crc)
    {
      io[0] = (unsigned char) crc;
      io[1] = URITRACK_FRESH;
    }
  io[1] |= state;
  if (o != LSEEK (fd, o, SEEK_SET))
    {
      GE_LOG_STRERROR_FILE (ectx,
                            GE_WARNING | GE_USER | GE_ADMIN | GE_BULK,
                            "lseek", s);
      CLOSE (fd);
      FREE (s);
      return;
    }
  if (2 != write (fd, io, 2))
    GE_LOG_STRERROR_FILE (ectx,
                          GE_WARNING | GE_USER | GE_ADMIN | GE_BULK,
                          "write", s);
  disk_file_close (ectx, s, fd);
  FREE (s);
}

/* end of uri_info.c */
