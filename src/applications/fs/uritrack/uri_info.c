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
getDBName (struct GNUNET_GC_Configuration *cfg)
{
  char *basename;
  char *ipcName;
  size_t n;

  GNUNET_GC_get_configuration_value_filename (cfg,
                                              "GNUNET",
                                              "GNUNET_HOME",
                                              GNUNET_DEFAULT_HOME_DIRECTORY,
                                              &basename);
  n = strlen (basename) + 512;
  ipcName = GNUNET_malloc (n);
  GNUNET_snprintf (ipcName, n, "%s/uri_info.db", basename);
  GNUNET_free (basename);
  return ipcName;
}

static unsigned long long
getDBSize (struct GNUNET_GC_Configuration *cfg)
{
  unsigned long long value;

  value = 1024 * 1024;
  GNUNET_GC_get_configuration_value_number (cfg,
                                            "FS",
                                            "URI_DB_SIZE",
                                            1,
                                            1024 * 1024 * 1024, 1024 * 1024,
                                            &value);
  return value;
}

/**
 * Find out what we know about a given URI's past.  Note that we only
 * track the states for a (finite) number of URIs and that the
 * information that we give back maybe inaccurate (returning
 * GNUNET_URITRACK_FRESH if the URI did not fit into our bounded-size map,
 * even if the URI is not fresh anymore; also, if the URI has a
 * GNUNET_hash-collision in the map, there is a 1:256 chance that we will
 * return information from the wrong URI without detecting it).
 */
enum GNUNET_URITRACK_STATE
GNUNET_URITRACK_get_state (struct GNUNET_GE_Context *ectx,
                           struct GNUNET_GC_Configuration *cfg,
                           const struct GNUNET_ECRS_URI *uri)
{
  char *s;
  int crc;
  int fd;
  unsigned long long size;
  unsigned char io[2];
  off_t o;

  s = GNUNET_ECRS_uri_to_string (uri);
  crc = GNUNET_crc32_n (s, strlen (s));
  GNUNET_free (s);
  s = getDBName (cfg);
  if (GNUNET_NO == GNUNET_disk_file_test (ectx, s))
    return GNUNET_URITRACK_FRESH;
  size = getDBSize (cfg);
  fd = GNUNET_disk_file_open (ectx, s, O_RDONLY);
  GNUNET_free (s);
  if (fd == -1)
    return GNUNET_URITRACK_FRESH;
  o = 2 * (crc % size);
  if (o != LSEEK (fd, o, SEEK_SET))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_USER |
                                   GNUNET_GE_ADMIN | GNUNET_GE_BULK, "lseek",
                                   s);
      CLOSE (fd);
      return GNUNET_URITRACK_FRESH;
    }
  if (2 != read (fd, io, 2))
    {
      CLOSE (fd);
      return GNUNET_URITRACK_FRESH;
    }
  CLOSE (fd);
  if (io[0] == (unsigned char) crc)
    return (enum GNUNET_URITRACK_STATE) io[1];
  return GNUNET_URITRACK_FRESH;
}

/**
 * Add additional information about a given URI's past.
 */
void
GNUNET_URITRACK_add_state (struct GNUNET_GE_Context *ectx,
                           struct GNUNET_GC_Configuration *cfg,
                           const struct GNUNET_ECRS_URI *uri,
                           enum GNUNET_URITRACK_STATE state)
{
  char *s;
  int crc;
  int fd;
  unsigned long long size;
  unsigned char io[2];
  off_t o;

  s = GNUNET_ECRS_uri_to_string (uri);
  crc = GNUNET_crc32_n (s, strlen (s));
  GNUNET_free (s);
  s = getDBName (cfg);
  size = getDBSize (cfg);
  fd = GNUNET_disk_file_open (ectx, s, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  if (fd == -1)
    {
      GNUNET_free (s);
      return;
    }
  o = 2 * (crc % size);
  if (o != LSEEK (fd, o, SEEK_SET))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_USER |
                                   GNUNET_GE_ADMIN | GNUNET_GE_BULK, "lseek",
                                   s);
      CLOSE (fd);
      GNUNET_free (s);
      return;
    }
  if (2 != read (fd, io, 2))
    {
      io[0] = crc;
      io[1] = GNUNET_URITRACK_FRESH;
    }
  else if (io[0] != (unsigned char) crc)
    {
      io[0] = (unsigned char) crc;
      io[1] = GNUNET_URITRACK_FRESH;
    }
  io[1] |= state;
  if (o != LSEEK (fd, o, SEEK_SET))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_USER |
                                   GNUNET_GE_ADMIN | GNUNET_GE_BULK, "lseek",
                                   s);
      CLOSE (fd);
      GNUNET_free (s);
      return;
    }
  if (2 != write (fd, io, 2))
    GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                 GNUNET_GE_WARNING | GNUNET_GE_USER |
                                 GNUNET_GE_ADMIN | GNUNET_GE_BULK, "write",
                                 s);
  GNUNET_disk_file_close (ectx, s, fd);
  GNUNET_free (s);
}

/* end of uri_info.c */
