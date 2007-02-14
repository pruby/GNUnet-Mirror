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
 * An mmapped file (STATE_NAME) is used to store the URIs.
 * An IPC semaphore is used to guard the access.
 */

#include "gnunet_directories.h"
#include "gnunet_util.h"
#include "gnunet_uritrack_lib.h"
#include "platform.h"

/**
 * Find out what we know about a given URI's past.
 */
enum URITRACK_STATE URITRACK_getState(const struct ECRS_URI * uri) {
  return URITRACK_FRESH;
}

/**
 * Add additional information about a given URI's past.
 */
void URITRACK_addState(const struct ECRS_URI * uri,
		       enum URITRACK_STATE state) {
}

/* end of uri_info.c */
