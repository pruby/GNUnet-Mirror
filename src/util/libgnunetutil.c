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
 * @file util/libgnunetutil.c
 * @brief general init routines
 * @author Heikki Lindholm
 */
#include "platform.h"
#include "gnunet_util_string.h"
#include "gnunet_util_os.h"

void __attribute__ ((constructor)) GNUNET_util_generic_ltdl_init ()
{
#if ENABLE_NLS
  char *path;

  path = GNUNET_get_installation_path (GNUNET_IPK_LOCALEDIR);
  if (path != NULL)
    {
      BINDTEXTDOMAIN ("GNUnet", path);
      GNUNET_free (path);
    }
#endif
}
