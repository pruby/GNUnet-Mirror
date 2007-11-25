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
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Toggle tracking URIs.
 *
 * @param onOff GNUNET_YES to enable tracking, GNUNET_NO to disable
 *  disabling tracking
 */
void GNUNET_URITRACK_toggle_tracking (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, int onOff);  /* file_info.c */

/**
 * Deletes all entries in the URITRACK tracking cache.
 */
void GNUNET_URITRACK_clear (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg);       /* file_info.c */

/**
 * Get the URITRACK URI tracking status.
 *
 * @return GNUNET_YES of tracking is enabled, GNUNET_NO if not
 */
int GNUNET_URITRACK_get_tracking_status (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg);  /* file_info.c */

/**
 * Makes a URI available for directory building.  This function is
 * automatically called by all URITRACK functions and only in the
 * interface for clients that call ECRS directly.
 */
void GNUNET_URITRACK_track (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, const GNUNET_ECRS_FileInfo * fi);      /* file_info.c */

/**
 * List all URIs.
 *
 * @param need_metadata GNUNET_YES if metadata should be
 *        provided, GNUNET_NO if metadata is not needed (faster)
 */
int GNUNET_URITRACK_list (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, int need_metadata, GNUNET_ECRS_SearchResultProcessor iterator, void *closure);   /* file_info.c */

/**
 * Register a handler that is called whenever
 * a URI is tracked.  If URIs are already in
 * the database, the callback will be called
 * for all existing URIs as well.
 */
int GNUNET_URITRACK_register_track_callback (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, GNUNET_ECRS_SearchResultProcessor iterator, void *closure);   /* callbacks.c */

/**
 * Unregister a URI callback.
 */
int GNUNET_URITRACK_unregister_track_callback (GNUNET_ECRS_SearchResultProcessor iterator, void *closure);      /* callbacks.c */

/**
 * Possible ways in which a given URI has been used or encountered.
 * Note that we only have 8-bits when storing this on the disk,
 * so do not add additional entries (without changing uri_info).
 */
enum GNUNET_URITRACK_STATE
{
  GNUNET_URITRACK_FRESH = 0,
  GNUNET_URITRACK_INSERTED = 1,
  GNUNET_URITRACK_INDEXED = 2,
  GNUNET_URITRACK_DIRECTORY_ADDED = 4,
  GNUNET_URITRACK_DOWNLOAD_STARTED = 8,
  GNUNET_URITRACK_DOWNLOAD_ABORTED = 16,
  GNUNET_URITRACK_DOWNLOAD_COMPLETED = 32,
  GNUNET_URITRACK_SEARCH_RESULT = 64,
  GNUNET_URITRACK_DIRECTORY_FOUND = 128,
};

/**
 * Find out what we know about a given URI's past.  Note that we only
 * track the states for a (finite) number of URIs and that the
 * information that we give back maybe inaccurate (returning
 * GNUNET_URITRACK_FRESH if the URI did not fit into our bounded-size map,
 * even if the URI is not fresh anymore; also, if the URI has a
 * GNUNET_hash-collision in the map, there is a 1:256 chance that we will
 * return information from the wrong URI without detecting it).
 */
enum GNUNET_URITRACK_STATE
GNUNET_URITRACK_get_state (struct GNUNET_GE_Context *ectx,
                           struct GNUNET_GC_Configuration *cfg,
                           const struct GNUNET_ECRS_URI *uri);

/**
 * Add additional information about a given URI's past.
 */
void GNUNET_URITRACK_add_state (struct GNUNET_GE_Context *ectx,
                                struct GNUNET_GC_Configuration *cfg,
                                const struct GNUNET_ECRS_URI *uri,
                                enum GNUNET_URITRACK_STATE state);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
