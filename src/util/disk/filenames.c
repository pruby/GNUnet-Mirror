/*
     This file is part of GNUnet.
     (C) 2008 Christian Grothoff (and other contributing authors)

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
 * @file util/disk/filenames.c
 * @brief filename creation convenience method
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_util_string.h"
#include "gnunet_util_disk.h"


/**
 * @brief Removes special characters as ':' from a filename.
 * @param fn the filename to canonicalize
 */
void
GNUNET_disk_filename_canonicalize (char *fn)
{
  char *idx;
  char c;

  idx = fn;
  while (*idx)
    {
      c = *idx;

      if (c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' ||
          c == '"' || c == '<' || c == '>' || c == '|')
        {
          *idx = '_';
        }

      idx++;
    }
}

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
char *
GNUNET_get_home_filename (struct GNUNET_GE_Context *ectx,
                          struct GNUNET_GC_Configuration *cfg,
                          int is_daemon, ...)
{
  const char *c;
  char *pfx;
  char *ret;
  va_list ap;
  unsigned int needed;

  GNUNET_GC_get_configuration_value_filename (cfg,
                                              is_daemon
                                              ? "GNUNETD"
                                              : "GNUNET",
                                              is_daemon
                                              ? "GNUNETD_HOME"
                                              : "GNUNET_HOME",
                                              is_daemon
                                              ?
                                              GNUNET_DEFAULT_DAEMON_VAR_DIRECTORY
                                              : GNUNET_DEFAULT_HOME_DIRECTORY,
                                              &pfx);
  needed = strlen (pfx) + 2;
  if ((pfx[strlen (pfx) - 1] != '/') && (pfx[strlen (pfx) - 1] != '\\'))
    needed++;
  va_start (ap, is_daemon);
  while (1)
    {
      c = va_arg (ap, const char *);
      if (c == NULL)
        break;
      needed += strlen (c);
      if ((c[strlen (c) - 1] != '/') && (c[strlen (c) - 1] != '\\'))
        needed++;
    }
  va_end (ap);
  ret = GNUNET_malloc (needed);
  strcpy (ret, pfx);
  GNUNET_free (pfx);
  va_start (ap, is_daemon);
  while (1)
    {
      c = va_arg (ap, const char *);
      if (c == NULL)
        break;
      if ((c[strlen (c) - 1] != '/') && (c[strlen (c) - 1] != '\\'))
        strcat (ret, DIR_SEPARATOR_STR);
      strcat (ret, c);
    }
  va_end (ap);
  if ((ret[strlen (ret) - 1] != '/') && (ret[strlen (ret) - 1] != '\\'))
    GNUNET_disk_directory_create_for_file (ectx, ret);
  else
    GNUNET_disk_directory_create (ectx, ret);
  return ret;
}

/* end of filenames.c */
