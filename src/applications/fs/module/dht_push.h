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
 * This module is responsible for pushing non-anonymous
 * content out into the DHT.
 *
 * @author Christian Grothoff
 * @file applications/fs/module/dht_push.h
 */
#ifndef DHT_PUSH_H
#define DHT_PUSH_H

#include "gnunet_core.h"
#include "gnunet_dht_service.h"

/**
 * Initialize the migration module.
 */
void init_dht_push (CoreAPIForApplication * capi, DHT_ServiceAPI * s);

void done_dht_push (void);

/* end of dht_push.h */
#endif
