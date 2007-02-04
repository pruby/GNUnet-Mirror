/*
     This file is part of GNUnet
     (C) 2001, 2002, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)


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
 * @file server/startup.h
 * @author Christian Grothoff
 * @brief Helper methods for the startup of gnunetd:
 * - PID file handling
 */

#ifndef STARTUP_H
#define STARTUP_H

#include "gnunet_util.h"
#include "platform.h"

int changeUser(struct GE_Context * ectx,
	       struct GC_Configuration * cfg);

int setFdLimit(struct GE_Context * ectx,
	       struct GC_Configuration * cfg);

/**
 * Write our process ID to the pid file.
 */
void writePIDFile(struct GE_Context * ectx,
		  struct GC_Configuration * cfg);

/**
 * Delete the pid file.
 */
void deletePIDFile(struct GE_Context * ectx,
		   struct GC_Configuration * cfg);

/**
 * @brief Cap datastore limit to the filesystem's capabilities
 * @notice FAT does not support files larger than 2/4 GB
 * @param ectx error handler
 * @param cfg configuration manager
 */
void capFSQuotaSize(struct GE_Context * ectx,
               struct GC_Configuration * cfg);

/**
 * Shutdown gnunetd
 * @param cfg configuration
 * @param sig signal code that causes shutdown, optional
 */
void shutdown_gnunetd(struct GC_Configuration * cfg, int sig);


#ifdef MINGW
void win_service_main(void (*gnunet_main)());
#endif
#endif
/* end of startup.h */
