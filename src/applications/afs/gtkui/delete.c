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
 * @file src/applications/afs/gtkui/delete.c
 * @brief handles file deletions
 * @author Igor Wronsky
 */

#include "gnunet_afs_esed2.h"
#include "helper.h"
#include "main.h"
#include "insertprogress.h"
#include "delete.h"

static gint setProgressValue(SaveCall *call) {
  gtk_progress_set_value(GTK_PROGRESS(((SetProgress *)call->args)->bar),
  		 	 ((SetProgress *)call->args)->val);
  gtkSaveCallDone(call->sem);
  
  return FALSE;
}

static void deleteModelCallback(ProgressStats * stats,
 	 	  	        InsertModel * ilm) {
  SetProgress progress;
 	
  progress.val = stats->progress;
  progress.bar = ilm->progressBar; 	
  gtkSaveCall((GtkFunction) setProgressValue, &progress);
}

static gint destroyProgressBar(SaveCall *call) {
  gtk_widget_destroy((GtkWidget *) call->args);
  gtkSaveCallDone(call->sem);
  
  return FALSE;
}

static void deleteFileGtkThread(InsertModel * ilm) {
  int res;
  GNUNET_TCP_SOCKET * sock;
  
  SEMAPHORE_DOWN(refuseToDie);
  sock = getClientSocket();
  if (sock == NULL) {
    guiMessage(_("Failed to connect to gnunetd.  Consult logs."));
    SEMAPHORE_UP(refuseToDie);
    return;
  }
  
  LOG(LOG_DEBUG, 
      "Attempting to unindex file '%s'.\n",
      ilm->fileName);	

  res = deleteFile(sock,
   		   ilm->fileName,
		   (ProgressModel)&deleteModelCallback,
		   ilm);

  gtkSaveCall((GtkFunction) destroyProgressBar, ilm->progressBarWindow);
  refreshMenuSensitivity();
  
  if(res != OK) 
    guiMessage(_("Failed to unindex file '%s'\n"), 
	       ilm->fileName);
  else
    guiMessage(_("File '%s' unindexed (no longer shared).\n"),
	       ilm->fileName);

  releaseClientSocket(sock);

  SEMAPHORE_UP(refuseToDie);
  
  FREE(ilm->fileName);
  FREE(ilm);
}

/**
 * Callback for the file selection window. Launches the
 * thread to delete the selected file.
 *
 * @param okButton not used
 * @param window the file selection window
 */
static gint file_selected(GtkWidget * okButton, 
			  GtkWidget * window) {
  const gchar * filename;
  InsertModel * ilm;
  PTHREAD_T deleteThread;

  filename 
    = gtk_file_selection_get_filename(GTK_FILE_SELECTION(window));
  if ( (filename == NULL) ||
       (0 == assertIsFile(filename)) ) {
    guiMessage(_("Please select a file!\n"));
    gtk_widget_destroy(window);
    return FALSE;
  }

  GNUNET_ASSERT(filename[0] == '/');
  ilm = MALLOC(sizeof(InsertModel));
  ilm->fileName = expandFileName(filename);

  strcpy(ilm->opDescription, _("deleted"));
  createInsertProgressBar(ilm);
  /* start the delete thread */
  if (0 != PTHREAD_CREATE(&deleteThread,
  			  (PThreadMain) deleteFileGtkThread,
			  ilm,
			  16 * 1024))
    DIE_STRERROR("pthread_create");
  PTHREAD_DETACH(&deleteThread);
  
  /* destroy the file selector */
  gtk_widget_destroy(window);
 
  return FALSE;
}


/**
 * Close the open-file window.
 */
static gint destroyOpenFile(GtkWidget * widget,
			    GtkWidget * window) {
  LOG(LOG_DEBUG, 
      "destroying open-file window (%p)\n", 
      window);
  return TRUE;
}

/**
 * Pops up a file selector for the user. Callback starts
 * the file deletion thread.
 *
 */
void openDeleteFile(void) {
  GtkWidget * window;

  window = gtk_file_selection_new(_("Choose file to be unindexed"));
  gtk_signal_connect(GTK_OBJECT(window), 
		     "destroy",
		     GTK_SIGNAL_FUNC(destroyOpenFile),
		     window);
  gtk_signal_connect(GTK_OBJECT(GTK_FILE_SELECTION(window)->ok_button),
		     "clicked", 
		     GTK_SIGNAL_FUNC(file_selected),
		     window);
  gtk_signal_connect(GTK_OBJECT(GTK_FILE_SELECTION(window)->cancel_button),
		     "clicked", 
		     GTK_SIGNAL_FUNC(destroyWidget),
		     window);
  gtk_widget_show(window);
}

/* end of delete.c */
