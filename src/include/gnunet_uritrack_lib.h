/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 *
 * @param need_metadata YES if metadata should be
 *        provided, NO if metadata is not needed (faster)
 */
int URITRACK_listURIs(struct GE_Context * ectx,
		      struct GC_Configuration * cfg,
		      int need_metadata,
		      ECRS_SearchProgressCallback iterator,
		      void * closure); /* file_info.c */

/**
 * Register a handler that is called whenever
 * a URI is tracked.  If URIs are already in
 * the database, the callback will be called
 * for all existing URIs as well.
 */
int URITRACK_registerTrackCallback(struct GE_Context * ectx,
				   struct GC_Configuration * cfg,
				   ECRS_SearchProgressCallback iterator,
				   void * closure); /* callbacks.c */

/**
 * Unregister a URI callback.
 */
int URITRACK_unregisterTrackCallback(ECRS_SearchProgressCallback iterator,
				     void * closure); /* callbacks.c */

/**
 * Possible ways in which a given URI has been used or encountered.
 */
enum URITRACK_STATE {
  URITRACK_FRESH              =    0,
  URITRACK_INSERTED           =    1,
  URITRACK_INDEXED            =    2,
  URITRACK_DIRECTORY_ADDED    =    4,

  URITRACK_DOWNLOAD_STARTED   =   16,
  URITRACK_DOWNLOAD_ABORTED   =   32,
  URITRACK_DOWNLOAD_COMPLETED =   64,

  URITRACK_SEARCH_RESULT      =  256,
  URITRACK_DIRECTORY_FOUND    =  512,
  URITRACK_USER_INPUT         = 1024,
};

/**
 * Find out what we know about a given URI's past.
 */
enum URITRACK_STATE URITRACK_getState(const struct ECRS_URI * uri);

/**
 * Add additional information about a given URI's past.
 */
void URITRACK_addState(const struct ECRS_URI * uri,
		       enum URITRACK_STATE state);

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
