/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/namespace/common.c
 * @brief helper functions
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_directories.h"
#include "common.h"

/**
 * Get the filename (or directory name) for the given
 * pseudonym identifier and directory prefix.
 */
char *
GNUNET_PSEUDO_internal_get_data_filename_ (struct GNUNET_GE_Context *ectx,
                                           struct GNUNET_GC_Configuration
                                           *cfg, const char *prefix,
                                           const GNUNET_HashCode * psid)
{
  char *tmp;
  char *ret;
  GNUNET_EncName enc;

  GNUNET_GC_get_configuration_value_filename (cfg,
                                              "GNUNET",
                                              "GNUNET_HOME",
                                              GNUNET_DEFAULT_HOME_DIRECTORY,
                                              &tmp);
  ret =
    GNUNET_malloc (strlen (tmp) + strlen (prefix) +
                   sizeof (GNUNET_EncName) + 20);
  strcpy (ret, tmp);
  GNUNET_free (tmp);
  if (ret[strlen (ret) - 1] != DIR_SEPARATOR)
    strcat (ret, DIR_SEPARATOR_STR);
  strcat (ret, prefix);
  GNUNET_disk_directory_create (ectx, ret);
  if (psid != NULL)
    {
      GNUNET_hash_to_enc (psid, &enc);
      strcat (ret, (const char *) &enc);
    }
  return ret;
}

/* end of common.c */
