/*
     This file is part of GNUnet

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
 * @file applications/afs/gtkui/download.h
 * @author Christian Grothoff
 **/

#ifndef GTKUI_DOWNLOAD_H
#define GTKUI_DOWNLOAD_H

/**
 * @brief state associated with a GTK download window
 **/
typedef struct {
  RootNode root;
  char * fileName;
  PTHREAD_T downloadThread;
  RequestManager * rm;
  Semaphore * doneSem;
  TIME_T downloadStartTime;
  int successfulStart;
  int downloadStatus;
  TIME_T lastDisplayTime;
  GtkWidget * dlList;
} DownloadModel;

typedef struct {
  char pos[16], kbs[14], perc[14], areq[14], cra[14], tr[14];
  DownloadModel *dlm;
  ProgressStats *stats;
} DLStats;

typedef struct {
  DownloadModel *dlm;
  GdkColor *color;
  gchar *text;
} SetDownloadEntry;

/**
 * Open the download window and start the download of a file in the
 * background. The method executes during a signal handler, so a GTK
 * lock is not required to to GUI operations.
 *
 * @param filename the name of the file to download
 * (must copy, will be freed by caller)
 * @param dlm some information about what to download 
 * (will be freed by caller, must copy!)
 **/
void startDownload(const gchar * filename,
		   RootNode * root);

void downloadAFSuri(char *uri, char *fn);

void fetchURI(GtkWidget * widget,
	      gpointer data);

extern GtkWidget * dlWindow;
		
#endif
