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
 * @file applications/fs/pseudonym/pseudonym_notification.h
 * @brief implementation of the notification mechanism
 * @author Christian Grothoff
 */


#include "gnunet_util.h"

#ifndef PSEUDONYM_NOTIFICATON_H
#define PSEUDONYM_NOTIFICATON_H

/**
 * Internal notification about new tracked pseudonym.
 */
void
GNUNET_pseudonym_internal_notify_ (const GNUNET_HashCode * id,
                                   const struct GNUNET_MetaData *md,
                                   int rating);

#endif
