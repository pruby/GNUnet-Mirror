/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/core.h
 * @brief Implementation of the APIs to the GNUnet core
 * @author Christian Grothoff
 */

#ifndef CORE_H
#define CORE_H

#include "gnunet_core.h"
#include "gnunet_transport.h"

/**
 * Initialize the CORE's globals.
 */
int GNUNET_CORE_init (struct GNUNET_GE_Context *ectx,
                      struct GNUNET_GC_Configuration *cfg,
                      struct GNUNET_CronManager *cron,
                      struct GNUNET_LoadMonitor *monitor);

/**
 * Shutdown the CORE modules (also shuts down all
 * application modules).
 */
void GNUNET_CORE_done (void);

void *GNUNET_CORE_request_service (const char *pos);

int GNUNET_CORE_release_service (void *service);

/**
 * @return GNUNET_OK on success, GNUNET_SYSERR if some modules failed to unload
 */
int GNUNET_CORE_unload_application_modules (void);

/**
 * @return GNUNET_OK on success, GNUNET_SYSERR if some modules failed to load
 */
int GNUNET_CORE_load_application_modules (void);




#endif
