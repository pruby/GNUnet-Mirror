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
 * @file src/applications/afs/gtkui/saveas.c
 * @brief open a save-as window.
 * @author Christian Grothoff
 * @author Igor Wronsky
 */

#include "gnunet_afs_esed2.h"
#include "helper.h"
#include "download.h"
#include "saveas.h"

/**
 * @brief state of the SaveAs window
 */
typedef struct {
  RootNode root;
  GtkWidget * w;
  char * filename;
} SaveAs;

/**
 * Destroy the DownloadModel data structure of the
 * saveas dialog.
 *
 * @param widget not used
 * @param saveas state associated with the SaveAs window
 */
static gint destroySaveAs(GtkWidget * widget,
			  SaveAs * saveas) {
  LOG(LOG_DEBUG, 
      "Destroying saveas window (%p).\n", 
      saveas);
  FREENONNULL(saveas->filename);
  FREE(saveas);
  return TRUE;
}
 
/**
 * Get the selected filename and start downloading 
 *
 * @param okButton not used
 * @param saveas state of the saveas window
 */
static gint file_ok_sel(GtkWidget * okButton,
			SaveAs * saveas) {
  const gchar * filename;

  filename
    = gtk_file_selection_get_filename(GTK_FILE_SELECTION(saveas->w));
  startDownload(filename, &saveas->root);
  gtk_widget_destroy(saveas->w);
  /* destroySaveAs does: "FREE(saveas);" */
  return FALSE;
}

/**
 * Open the window that prompts the user for the filename.  This
 * method must open the window, copy the arguments and return.  After
 * the method returns, the arguments passed to it will be freed, so
 * pointer should not be retained.  The method executes during a
 * signal handler, so a GTK lock is not required to to GUI operations.
 * 
 * @param root search result of the file to download
 */
void openSaveAs(RootNode * root) {
  SaveAs * saveas;
  int i;
  
  saveas = MALLOC(sizeof(SaveAs));
  memcpy(&saveas->root,
	 root,
	 sizeof(RootNode));
  saveas->filename = NULL;

  /* if the search result specified a suggested
     filename, fill it in! */
  switch (ntohs(root->header.major_formatVersion)) {
  case ROOT_MAJOR_VERSION:
    /* if it is a GNUnet directory, replace suffix '/' with ".gnd" */
    if (0 == strcmp(root->header.mimetype,
		    GNUNET_DIRECTORY_MIME)) {
      saveas->filename = expandDirectoryName(root->header.filename);
    } else 
      saveas->filename = STRDUP(root->header.filename);
    break;
  case SBLOCK_MAJOR_VERSION:
    if (0 == strcmp(&((SBlock*)root)->mimetype[0],
		    GNUNET_DIRECTORY_MIME)) {      
      saveas->filename = expandDirectoryName(root->header.filename);
    } else 
      saveas->filename = STRDUP(((SBlock*)root)->filename);
    break;
  case NBLOCK_MAJOR_VERSION:
    BREAK(); /* should never be downloaded! */
    break;
  default:
    LOG(LOG_WARNING,
	_("Unknown format version: %d.\n"),
	ntohs(root->header.major_formatVersion));
    /* how did we get here!? */
    break;
  }

  if ( (saveas->filename == NULL) ||
       (saveas->filename[0] == 0) ||
       (testConfigurationString("GNUNET-GTK",
				"ALWAYS-ASK-SAVEAS",
				"YES")) ) {
    GtkWidget * window;

    window = gtk_file_selection_new("save as");
    saveas->w = window;
        
    /* callbacks (destroy, ok, cancel) */
    gtk_signal_connect(GTK_OBJECT(window),
		       "destroy",
		       GTK_SIGNAL_FUNC(destroySaveAs),
		       saveas);
    /* Connect the ok_button to file_ok_sel function */
    gtk_signal_connect(GTK_OBJECT(GTK_FILE_SELECTION(window)->ok_button),
		       "clicked", 
		       GTK_SIGNAL_FUNC(file_ok_sel), 
		       saveas);
    /* Connect the cancel_button to destroy the widget */
    gtk_signal_connect(GTK_OBJECT(GTK_FILE_SELECTION(window)->cancel_button),
		       "clicked", 
		       GTK_SIGNAL_FUNC(destroyWidget), 
		       window);
    gtk_widget_show(window);
  } else {
    char * tmp;
    char * downloadDir;

    /* sanity check the filename */
    for(i=0;i<strlen(saveas->filename);i++) {
      switch(saveas->filename[i]) {
      case '*':
      case '/':
      case '\\':
      case '?':
      case ':':
	saveas->filename[i]='_';
	break;
      default:
	break;
      }
    }

    downloadDir = getConfigurationString("AFS",
  				          "DOWNLOADDIR");
    if(downloadDir != NULL) {
      char * expanded;
  
      expanded = expandFileName(downloadDir);
      if ((SYSERR == mkdirp(expanded)))
        LOG_FILE_STRERROR(LOG_WARNING, "mkdirp", expanded);
      CHDIR(expanded);
      FREE(expanded);
    }
    FREENONNULL(downloadDir);

    tmp = expandFileName(saveas->filename);
    FREE(saveas->filename);
    startDownload(tmp,
		  &saveas->root);
    FREE(saveas);
    FREE(tmp);
  }
}

/* end of saveas.c */
