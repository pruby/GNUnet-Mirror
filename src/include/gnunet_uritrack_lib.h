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
 * @file include/gnunet_uritrack_lib.h
 * @brief support for tracking known GNUnet FS URIs
 * @author Christian Grothoff
 */

#ifndef GNUNET_URITRACK_LIB_H
#define GNUNET_URITRACK_LIB_H

#include "gnunet_ecrs_lib.h"

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Toggle tracking URIs.
 *
 * @param onOff YES to enable tracking, NO to disable
 *  disabling tracking
 */
void URITRACK_trackURIS(struct GE_Context * ectx,
			struct GC_Configuration * cfg,
			int onOff); /* file_info.c */

/**
 * Deletes all entries in the URITRACK tracking cache.
 */
void URITRACK_clearTrackedURIS(struct GE_Context * ectx,
			       struct GC_Configuration * cfg); /* file_info.c */

/**
 * Get the URITRACK URI tracking status.
 *
 * @return YES of tracking is enabled, NO if not
 */
int URITRACK_trackStatus(struct GE_Context * ectx,
			 struct GC_Configuration * cfg); /* file_info.c */

/**
 * Makes a URI available for directory building.  This function is
 * automatically called by all URITRACK functions and only in the
 * interface for clients that call ECRS directly.
 */
void URITRACK_trackURI(struct GE_Context * ectx,
		       struct GC_Configuration * cfg,
		       const ECRS_FileInfo * fi); /* file_info.c */

/**
 * List all URIs.
 */
int URITRACK_listURIs(struct GE_Context * ectx,
		      struct GC_Configuration * cfg,
		      ECRS_SearchProgressCallback iterator,
		      void * closure); /* file_info.c */

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
