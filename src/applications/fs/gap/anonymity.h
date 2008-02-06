/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/gap/module/anonymity.h
 * @brief code for checking if cover traffic is sufficient
 * @author Christian Grothoff
 */

#ifndef ANONYMITY_H
#define ANONYMITY_H

#include "gnunet_core.h"

/**
 * Initialize the migration module.
 */
void GNUNET_FS_ANONYMITY_init (GNUNET_CoreAPIForPlugins * capi);

void GNUNET_FS_ANONYMITY_done (void);

/**
 * Consider traffic volume before sending out content or
 * queries.
 *
 * @return GNUNET_OK if cover traffic is sufficient
 */
int
GNUNET_FS_ANONYMITY_check (unsigned int anonymityLevel,
                           unsigned short content_type);

#endif
