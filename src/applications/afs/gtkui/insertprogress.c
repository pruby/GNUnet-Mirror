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
 * @file src/applications/afs/gtkui/insertprogress.c
 * @brief handles file insertions in the GTK GUI
 * @author Igor Wronsky
 * @author Christian Grothoff (refactoring, added bugs)
 */

#include "gnunet_afs_esed2.h"
#include "platform.h"
#if USE_LIBEXTRACTOR
#include <extractor.h>
#endif
#include "helper.h"
#include "insertprogress.h"
#include "insert.h"
#include "main.h"

typedef struct {
  GtkWidget *bar;
  unsigned long long progress;
} SetStat;


static gint setInsertProgressVal(SaveCall *call) {
  gtk_progress_set_value(GTK_PROGRESS(((SetStat *)call->args)->bar),
			 ((SetStat *)call->args)->progress);

  gtkSaveCallDone(call->sem);
  
  return FALSE;
}

typedef struct {
  GtkWidget * bar;
  unsigned long long value;
} SetAdj;


static gint updateAdjustment(SaveCall * call) {
  GtkObject * adj;

  adj = gtk_adjustment_new(0, 0,
			   ((SetAdj *)call->args)->value,
			   1, 0, 0);
  gtk_progress_set_adjustment(GTK_PROGRESS(((SetAdj *)call->args)->bar),
			      GTK_ADJUSTMENT(adj));
  gtkSaveCallDone(call->sem);
  
  return FALSE;
}



/**
 * Callback function to update the insert progressbar.
 *
 * @param stats Statistics related to insert progression
 * @param ilm Data related to the insertion
 */
static void insertModelCallback(ProgressStats * stats,
				InsertModel * ilm) {
  SetStat stat;
  
  stat.bar = ilm->progressBar;
  stat.progress = stats->progress;
  gtkSaveCall((GtkFunction) setInsertProgressVal, &stat);
}


/**
 * Callback function to update the insert progressbar.
 *
 * @param stats Statistics related to insert progression
 * @param ilm Data related to the insertion
 */
static void insertDirectoryModelCallback(ProgressStats * stats,
					 InsertDirectoryModel * ilm) {
  SetStat stat;
  
  stat.bar = ilm->progressBar;
  stat.progress = stats->progress;
  gtkSaveCall((GtkFunction) setInsertProgressVal, &stat);
}

static gint destroyInsertProgressBar(SaveCall *call) {
  gtk_widget_destroy((GtkWidget *) call->args);  

  gtkSaveCallDone(call->sem);

  return FALSE;
}

/**
 * A function to be run by the insert thread. Does the
 * actual insertion.
 *
 * @param ilm Collected data related to the insertion
 */
void insertFileGtkThread(InsertModel * ilm) {
  int res;
  GNUNET_TCP_SOCKET * sock;
  Block * top;
  int i;
  
  SEMAPHORE_DOWN(refuseToDie);
  if (ilm->indexContent == YES) {
    FREENONNULL(setConfigurationString("GNUNET-INSERT",
				       "INDEX-CONTENT",
				       "YES"));

    FREENONNULL(setConfigurationString("GNUNET-INSERT",
                                       "LINK",
                                       ilm->copyFile == YES ? "NO" : "YES"));

  } else {
    FREENONNULL(setConfigurationString("GNUNET-INSERT",
				       "INDEX-CONTENT",
				       "NO"));
  }
  sock = getClientSocket();
  if (sock == NULL) {
    SEMAPHORE_UP(refuseToDie);
    return; /* warning should have been printed */
  }
  top = insertFile(sock,
		   ilm->fileName,
		   (ProgressModel)&insertModelCallback,
		   ilm);
  if (top != NULL) {
    res = insertRoot(sock,
		     top, 
		     ilm->description,
		     ilm->fileNameRoot,
		     ilm->mimetype,
		     ilm->num_keywords,
		     (const char**)ilm->keywords,
		     NULL);
  } else {
    res = SYSERR;
  }
  gtkSaveCall((GtkFunction) destroyInsertProgressBar, 
	      ilm->progressBarWindow);
  refreshMenuSensitivity();
  if (res == OK) {
    FileIdentifier fid;
    char * fstring;

    memcpy(&fid.chk, &top->chk, sizeof(CHK_Hashes));
    fid.crc = htonl(crc32N(top->data, top->len));
    {
      unsigned int fs = (unsigned int) top->filesize;
      fid.file_length = htonl(fs);
    }
    
    fstring = createFileURI(&fid);
    
    infoMessage(NO,
		_("Successfully processed file '%s'.\n\tURI is '%s'\n"), 
		ilm->fileName,
		fstring);
    LOG(LOG_DEBUG,
        _("Successfully processed file '%s'. URI is '%s'.\n"),
        ilm->fileName,
        fstring);
    FREE(fstring);
  } else {
    guiMessage(_("Insertion of file '%s' failed!\n"), 
	       ilm->fileName);
  }
  if(top != NULL)
    top->vtbl->done(top, NULL);
  releaseClientSocket(sock);

  /* insert complete */
  SEMAPHORE_UP(refuseToDie);
  for (i=0;i<ilm->num_keywords;i++)
    FREE(ilm->keywords[i]);
  FREENONNULL(ilm->keywords);
  if(ilm->deleteAfterInsert == YES) 
    UNLINK(ilm->fileName);
  FREE(ilm->fileName);
  FREE(ilm->mimetype);
  FREE(ilm->description);
  FREE(ilm->fileNameRoot);
  FREE(ilm);
}

/**
 * Callback for handling "delete_event": keep the window OPEN.
 */
static gint refuseDeleteEvent(GtkWidget * widget,
			      GdkEvent * event,
			      gpointer data) {
  LOG(LOG_DEBUG, 
      "In '%s'.\n",
      __FUNCTION__);
  return TRUE;
}


void createInsertProgressBar(InsertModel * ilm) {
  GtkWidget * window;
  GtkWidget * box;
  GtkObject * adjustment;
  char format[128];
  int fileLength;

  /* create a new window for a progressbar */
  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  ilm->progressBarWindow = window;
  gtk_window_set_title(GTK_WINDOW(window), 
		       ilm->fileName);
  box = gtk_hbox_new(FALSE, 0);
  gtk_container_add(GTK_CONTAINER(window), 
		    box);
  gtk_signal_connect(GTK_OBJECT(window),
		     "delete_event",
		     GTK_SIGNAL_FUNC(refuseDeleteEvent),
		     NULL);
  gtk_container_set_border_width(GTK_CONTAINER(window), 
				 10);

  SNPRINTF(format, 
	   128,
	   "%%v bytes %s",
	   ilm->opDescription);
 
  /* create the actual progressbar */
  fileLength = getFileSize(ilm->fileName);
  ilm->progressBar = gtk_progress_bar_new();
  gtk_progress_set_show_text(GTK_PROGRESS(ilm->progressBar),
			     1);
  gtk_progress_set_format_string(GTK_PROGRESS(ilm->progressBar),
				 (gchar*)format);
  adjustment = gtk_adjustment_new(0,
				  0,
				  fileLength,
				  1,
				  0,
				  0);
  gtk_progress_set_adjustment(GTK_PROGRESS(ilm->progressBar),
			      GTK_ADJUSTMENT(adjustment));
  gtk_box_pack_start(GTK_BOX(box),
		     ilm->progressBar, 
		     TRUE, 
		     TRUE, 
		     0);
  gtk_progress_bar_set_orientation(GTK_PROGRESS_BAR(ilm->progressBar),
				   GTK_PROGRESS_LEFT_TO_RIGHT);
  gtk_widget_show(ilm->progressBar);
  gtk_widget_show(box);
  gtk_widget_show(window);
}


void createInsertDirectoryProgressBar(InsertDirectoryModel * ilm) {
  GtkWidget * window;
  GtkWidget * box;
  char format[128];
  double fileLength;

  /* create a new window for a progressbar */
  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  ilm->progressBarWindow = window;
  gtk_window_set_title(GTK_WINDOW(window), 
		       ilm->fileName);
  box = gtk_vbox_new(FALSE, 0);
  gtk_container_add(GTK_CONTAINER(window), 
		    box);
  gtk_signal_connect(GTK_OBJECT(window),
		     "delete_event",
		     GTK_SIGNAL_FUNC(refuseDeleteEvent),
		     NULL);
  gtk_container_set_border_width(GTK_CONTAINER(window), 
				 10);

  SNPRINTF(format, 
	   128,
	   _("%%v bytes %s"), /* translations MUST keep the %%v! */
	   ilm->opDescription);
 
  /* create the actual progressbar */
  fileLength = getFileSize(ilm->fileName);
  ilm->progressBar = gtk_progress_bar_new();
  gtk_progress_set_show_text(GTK_PROGRESS(ilm->progressBar),
			     1);
  gtk_progress_set_format_string(GTK_PROGRESS(ilm->progressBar),
				 (gchar*)format);
  ilm->adjustment = gtk_adjustment_new(0,
				       0,
				       10000,
				       1,
				       0,
				       0);
  gtk_progress_set_adjustment(GTK_PROGRESS(ilm->progressBar),
			      GTK_ADJUSTMENT(ilm->adjustment));
  gtk_box_pack_start(GTK_BOX(box),
		     ilm->progressBar, 
		     TRUE, 
		     TRUE, 
		     0);
  gtk_progress_bar_set_orientation(GTK_PROGRESS_BAR(ilm->progressBar),
				   GTK_PROGRESS_LEFT_TO_RIGHT);
  gtk_widget_show(ilm->progressBar);

  ilm->progressBar2 = gtk_progress_bar_new();
  gtk_progress_set_show_text(GTK_PROGRESS(ilm->progressBar2),
			     1);
  gtk_progress_set_format_string(GTK_PROGRESS(ilm->progressBar2),
				 (gchar*)format);
  ilm->adjustment2 = gtk_adjustment_new(0,
					0,
					fileLength,
					1,
					0,
					0);
  gtk_progress_set_adjustment(GTK_PROGRESS(ilm->progressBar2),
			      GTK_ADJUSTMENT(ilm->adjustment2));
  gtk_box_pack_start(GTK_BOX(box),
		     ilm->progressBar2, 
		     TRUE, 
		     TRUE, 
		     0);
  gtk_progress_bar_set_orientation(GTK_PROGRESS_BAR(ilm->progressBar2),
				   GTK_PROGRESS_LEFT_TO_RIGHT);
  gtk_widget_show(ilm->progressBar2);
  gtk_widget_show(box);
  gtk_widget_show(window);
}




/**
 * Insert a single file.
 *
 * @param filename the name of the file to insert
 * @param fid resulting file identifier for the node
 * @returns OK on success, SYSERR on error
 */
static int gtkInsertDirectoryWrapper(GNUNET_TCP_SOCKET * sock,
				     char * filename,
				     FileIdentifier * fid,
				     InsertDirectoryModel * ilm) {
  Block * top;
  cron_t startTime;
  InsertModel ifm;
  SetAdj adj;

  ifm.fileName = filename;
  ifm.fileNameRoot = NULL;
  ifm.description = NULL;
  ifm.mimetype = NULL;
  ifm.keywords = NULL;
  ifm.num_keywords = 0;
  memcpy(ifm.opDescription,
	 ilm->opDescription,
	 sizeof(ilm->opDescription));
  ifm.indexContent = ilm->indexContent;
  ifm.progressBar = ilm->progressBar;
  ifm.progressBarWindow = ilm->progressBarWindow;
  ifm.deleteAfterInsert = ilm->deleteAfterInsert;

  adj.bar = ilm->progressBar;
  adj.value = getFileSize(filename);
  
  gtkSaveCall((GtkFunction) updateAdjustment,
	      &adj);
 
  cronTime(&startTime);
  top = insertFile(sock,
		   filename, 
		   (ProgressModel) &insertDirectoryModelCallback,
		   &ifm);
  if (top == NULL) {
    /* print error message here?  Probably better once
       at the top-level... */
    return SYSERR;
  } else {
    SetStat stat;

    memcpy(&fid->chk, 
	   &top->chk, 
	   sizeof(CHK_Hashes));
    fid->crc = htonl(crc32N(top->data, top->len));
    fid->file_length = htonl(top->filesize);
    if (NO == isDirectory(filename)) {
      if (top->filesize != getFileSize(filename))
	abort();
      ilm->pos += top->filesize;
      stat.bar = ilm->progressBar2;
      stat.progress = ilm->pos;
      gtkSaveCall((GtkFunction) setInsertProgressVal,
		  &stat);
    }
    top->vtbl->done(top, NULL);
    return OK;
  }
}


/**
 * A function to be run by the insert thread. Does the
 * actual insertion.
 *
 * @param ilm Collected data related to the insertion
 */
void insertDirectoryGtkThread(InsertDirectoryModel * ilm) {
  int res;
  GNUNET_TCP_SOCKET * sock;
  RootNode * top;
  int i;
  SetStat stat;
  FileIdentifier fid;
#if USE_LIBEXTRACTOR
  EXTRACTOR_ExtractorList * extractors;
#endif
  
  SEMAPHORE_DOWN(refuseToDie);
  ilm->pos = 0;
  stat.bar = ilm->progressBar2;
  stat.progress = ilm->pos;
  gtkSaveCall((GtkFunction) setInsertProgressVal,
	      &stat);
  FREENONNULL(setConfigurationString("GNUNET-INSERT",
				     "BUILDDIR",
				     "YES"));
  FREENONNULL(setConfigurationString("GNUNET-INSERT",
				     "RECURSIVE",
				     "YES"));

  if (ilm->indexContent == YES) {
    FREENONNULL(setConfigurationString("GNUNET-INSERT",
				       "INDEX-CONTENT",
				       "YES"));

    FREENONNULL(setConfigurationString("GNUNET-INSERT",
                                       "LINK",
                                       ilm->copyFile == YES ? "NO" : "YES"));
  } else {
    FREENONNULL(setConfigurationString("GNUNET-INSERT",
				       "INDEX-CONTENT",
				       "NO"));
  }
  sock = getClientSocket();
  if (sock == NULL) {
    SEMAPHORE_UP(refuseToDie);
    return; /* warning should have been printed */
  }


#if USE_LIBEXTRACTOR
  extractors = getExtractors();
#endif
  top = insertRecursively(sock,
			  ilm->fileName,
			  &fid,
			  (const char**) ilm->gkeywords,
			  ilm->num_gkeywords,	
#if USE_LIBEXTRACTOR
			  extractors,
#else
			  NULL,
#endif
			  (ProgressModel)&insertModelCallback,
			  ilm,
			  (InsertWrapper)&gtkInsertDirectoryWrapper,
			  ilm);
#if USE_LIBEXTRACTOR
  EXTRACTOR_removeAll(extractors);
#endif
  if (top != NULL) {
    unsigned int priority;

    priority = getConfigurationInt("GNUNET-INSERT",
				   "CONTENT-PRIORITY");
    res = OK;
    for (i=0;i<ilm->num_keywords;i++) {
      if (SYSERR == insertRootWithKeyword(sock,
					  top, 
					  ilm->keywords[i], 
					  priority))
	res = SYSERR;
    }
    makeRootNodeAvailable(top, DIR_CONTEXT_INSERT);
    publishToCollection(top);
  } else {
    res = SYSERR;
  }

  gtkSaveCall((GtkFunction) destroyInsertProgressBar, 
	      ilm->progressBarWindow);

  refreshMenuSensitivity();
  if (res == OK) {
    char * fstring;

    fstring = createFileURI(&top->header.fileIdentifier);    
    infoMessage(NO,
		_("Successfully processed file '%s'.\n\tURI is '%s'\n"), 
		ilm->fileName,
		fstring);
    LOG(LOG_DEBUG,
        "Successfully processed file '%s'. URI is '%s'.\n",
        ilm->fileName,
        fstring);
    FREE(fstring);
  } else {
    guiMessage(_("Insertion of file '%s' failed!\n"), 
	       ilm->fileName);
  }
  FREENONNULL(top);
  releaseClientSocket(sock);

  /* insert complete */
  SEMAPHORE_UP(refuseToDie);
  for (i=0;i<ilm->num_keywords;i++)
    FREE(ilm->keywords[i]);
  FREENONNULL(ilm->keywords);
  if(ilm->deleteAfterInsert == YES) 
    UNLINK(ilm->fileName);
  FREE(ilm->fileName);
  FREE(ilm->mimetype);
  FREE(ilm->description);
  FREE(ilm->fileNameRoot);
  FREE(ilm);
}



/* end of insertprogress.c */
