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
 * @file src/applications/afs/gtkui/download.c
 * @brief code that handles the download window
 * @author Christian Grothoff
 * @author Igor Wronsky
 *
 * FIXME:
 * - shutdown of gnunet-gtk does NOT terminate
 *   each of the pending downloads.  There
 *   should be a handler function that is invoked
 *   whenever gnunet-gtk shuts down and that
 *   stops all pending downloads.  This used to
 *   be implemented but got lost when Igor added
 *   the download window.
 */

#include "gnunet_afs_esed2.h"
#include "helper.h"
#include "directorydisplay.h"
#include "download.h"
#include "main.h"

GtkWidget * dlWindow = NULL;

#define DEBUG_WRITE_CPSDATA NO

/* Suitable values of DownloadModel.downloadStatus */
#define DOWNLOAD_COMPLETE 0
#define DOWNLOAD_FAILED   1
#define DOWNLOAD_ABORTED  2
#define DOWNLOAD_PENDING  3

/* colors taken from x-chat source, regards */
GdkColor textColors[] = {
        {0, 0xcf3c, 0xcf3c, 0xcf3c}, /* 0  white */
        {0, 0x0000, 0x0000, 0x0000}, /* 1  black */
        {0, 0x0000, 0x0000, 0xcccc}, /* 2  blue */
        {0, 0x0000, 0xcccc, 0x0000}, /* 3  green */
        {0, 0xdddd, 0x0000, 0x0000}, /* 4  red */
        {0, 0xaaaa, 0x0000, 0x0000}, /* 5  light red */
        {0, 0xbbbb, 0x0000, 0xbbbb}, /* 6  purple */
        {0, 0xffff, 0xaaaa, 0x0000}, /* 7  orange */
        {0, 0xeeee, 0xdddd, 0x2222}, /* 8  yellow */
        {0, 0x3333, 0xdede, 0x5555}, /* 9  green */
        {0, 0x0000, 0xcccc, 0xcccc}, /* 10 aqua */
        {0, 0x3333, 0xeeee, 0xffff}, /* 11 light aqua */
        {0, 0x0000, 0x0000, 0xffff}, /* 12 blue */
        {0, 0xeeee, 0x2222, 0xeeee}, /* 13 light purple */
        {0, 0x7777, 0x7777, 0x7777}, /* 14 grey */
        {0, 0x9999, 0x9999, 0x9999}, /* 15 light grey */
        {0, 0xa4a4, 0xdfdf, 0xffff}, /* 16 marktext Back (blue) */
        {0, 0x0000, 0x0000, 0x0000}, /* 17 marktext Fore (black) */
        {0, 0xdf3c, 0xdf3c, 0xdf3c}, /* 18 foreground (white) */
        {0, 0x0000, 0x0000, 0x0000}, /* 19 background (black) */
        {0, 0x8c8c, 0x1010, 0x1010}, /* 20 tab New Data (dark red) */
        {0, 0x0000, 0x0000, 0xffff}, /* 21 tab Nick Mentioned (blue) */
        {0, 0xf5f5, 0x0000, 0x0000}, /* 22 tab New Message (red) */
};

static void selectAll(void);
static void unSelectAll(void);
static void removeFinished(void);
static void abortHelper(void);
static void hideHelper(void);
static gint abortSelectedDownloads(GtkWidget * widget,
 	                    GtkWidget * clist);

static GtkItemFactoryEntry dlWindowMenu[] = {
 { gettext_noop("/Select all"),       NULL,    selectAll,           0, "<Item>" },
 { gettext_noop("/Unselect all"),     NULL,    unSelectAll,         0, "<Item>" },
 { "/sep1",             NULL,    NULL,                0, "<Separator>" },
 { gettext_noop("/Remove selected"),  NULL,    abortHelper,         0, "<Item>" },
 { gettext_noop("/Remove finished"),  NULL,    removeFinished,      0, "<Item>" },
 { "/sep2",             NULL,    NULL,                0, "<Separator>" },
 { gettext_noop("/Hide window"),   NULL,    hideHelper,          0, "<Item>" }
};

static gint dlWindowMenuItems 
  = sizeof (dlWindowMenu) / sizeof (dlWindowMenu[0]);

static void selectAll(void) 
{
    GtkWidget * clist;
    
    clist = gtk_object_get_data(GTK_OBJECT(dlWindow),
                                "LIST");
    gtk_clist_select_all(GTK_CLIST(clist));				    
}

static void unSelectAll(void) 
{
    GtkWidget * clist;
    
    clist = gtk_object_get_data(GTK_OBJECT(dlWindow),
                                "LIST");
    gtk_clist_unselect_all(GTK_CLIST(clist));				    
}

static void removeFinished(void)
{
    GtkCList * clist;
    int i;
    gchar * string;

    unSelectAll();

    clist = GTK_CLIST(gtk_object_get_data(GTK_OBJECT(dlWindow),
                                           "LIST"));
    gtk_clist_freeze(clist);

    for(i=0;i<clist->rows;i++) {
      gtk_clist_get_text(clist, 
                         i,
			 1,
			 &string);
      if (strcmp(string, _("DONE"))==0)
        gtk_clist_select_row(clist,
			     i,
			     1);
      else
	gtk_clist_unselect_row(clist,
			     i,
			     1);
    }
      
    gtk_clist_thaw(clist);
    
    abortSelectedDownloads(NULL, GTK_WIDGET(clist));
}

static void hideHelper(void)
{
  if(dlWindow)
    gtk_widget_hide(dlWindow);
}
  
static void abortHelper(void)
{
    GtkWidget * clist;
    
    clist = gtk_object_get_data(GTK_OBJECT(dlWindow),
                                "LIST");
    abortSelectedDownloads(NULL, clist);
}

/**
 * Changes the current sort column and sorts the list.
 */
static void sort_column_callback(GtkCList * clist,
                                 gint column,
                                 gpointer data) {
  static int sortOrder[8]={0,0,0,0,0,0,0,0};

  sortOrder[column]^=1;

  if(sortOrder[column]==1)
    gtk_clist_set_sort_type(clist,
    			    GTK_SORT_ASCENDING);
  else
    gtk_clist_set_sort_type(clist,
    			    GTK_SORT_DESCENDING);
  
  /* Sort column 0 as string, 1 as percent and rest as numbers */
  switch(column) {
    case 0: 
      gtk_clist_set_compare_func(clist,
                                 (GtkCListCompareFunc)alphaComp);
      break; 
    case 1:
      gtk_clist_set_compare_func(clist,
                                 (GtkCListCompareFunc)percentComp);
      break;
    default:
      gtk_clist_set_compare_func(clist,
                                 (GtkCListCompareFunc)numericComp);
      break;
  }
  gtk_clist_set_sort_column(clist, column);
  gtk_clist_freeze(clist);
  gtk_clist_sort(clist);
  gtk_clist_thaw(clist);
}

/**
 * "delete_event" handler for a download. Sets the 
 * download state as aborted, and releases the wait semaphore for 
 * the thread awaiting download completion. Returns TRUE so that 
 * gtk doesn't destroy the widget (its never destroyed).
 *
 * @param widget not used
 * @param clist the list of downloads
 */
static gint abortSelectedDownloads(GtkWidget * widget,
			           GtkWidget * clist) {
  DownloadModel * dlm;
  int row;
  GList * tmp;

  LOG(LOG_DEBUG,
      "In '%s'(%p, %p)\n",
      __FUNCTION__,
      clist, widget);
  if(!GTK_CLIST(clist))
    return TRUE;
  
  gtk_clist_freeze(GTK_CLIST(clist));

  tmp = GTK_CLIST(clist)->selection;
  while (tmp) {
    row = (int)tmp->data;
    tmp = tmp->next;

    /* if dlm is not NULL, abort the download */
    dlm = gtk_clist_get_row_data(GTK_CLIST(clist),
	   	  	         row);
    if(dlm) {
      char *uri;

      dlm->downloadStatus = DOWNLOAD_ABORTED;
      
      uri = createFileURI(&dlm->root.header.fileIdentifier);
      removeResumeInfo(uri);
      FREE(uri);
          
      SEMAPHORE_UP(dlm->doneSem);
    } 
    
    /* remove list entry */
    gtk_clist_remove(GTK_CLIST(clist),
		     row);
  }

  gtk_clist_thaw(GTK_CLIST(clist));
  
  return TRUE;
}

static gint displayStats(SaveCall *call) {
  DLStats *dlStats = (DLStats *) call->args;
  DownloadModel *dlm = dlStats->dlm;
  gint row;

  gtk_clist_freeze(GTK_CLIST(dlm->dlList));
  row = gtk_clist_find_row_from_data(GTK_CLIST(dlm->dlList),
				     dlStats->dlm);
  gtk_clist_set_text(GTK_CLIST(dlm->dlList),
		     row,
		     1,
		     dlStats->perc);
  gtk_clist_set_text(GTK_CLIST(dlm->dlList),
		     row,
		     2,
		     dlStats->pos);
  gtk_clist_set_text(GTK_CLIST(dlm->dlList),
		     row,
		     4,
		     dlStats->areq);
  gtk_clist_set_text(GTK_CLIST(dlm->dlList),
		     row,
		     5,
		     dlStats->cra);
  gtk_clist_set_text(GTK_CLIST(dlm->dlList),
		     row,
		     6,
		     dlStats->tr);
  gtk_clist_set_text(GTK_CLIST(dlm->dlList),
		     row,
		     7,
		     dlStats->kbs);
  if(dlm->successfulStart == NO && dlStats->stats->progress > 0) {
      gtk_clist_set_foreground(GTK_CLIST(dlm->dlList), 
                               row,
                               &textColors[1]);
      dlm->successfulStart = YES;
  } 
  gtk_clist_thaw(GTK_CLIST(dlm->dlList));

  if (dlStats->stats->filesize == dlStats->stats->progress) {
    /* reset the request counters (just cosmetic) */
    SNPRINTF(dlStats->areq, sizeof(dlStats->areq), "0");
    SNPRINTF(dlStats->cra, sizeof(dlStats->cra), "0.0");
    
    gtk_clist_freeze(GTK_CLIST(dlm->dlList));
    gtk_clist_set_text(GTK_CLIST(dlm->dlList),
 	  	       row,
		         4,
		         dlStats->areq);
    gtk_clist_set_text(GTK_CLIST(dlm->dlList),
  	  	       row,
		           5,
		           dlStats->cra);
    gtk_clist_thaw(GTK_CLIST(dlm->dlList));
    refreshMenuSensitivity();

    if (dlStats->stats->filesize == 0)       
      dlm->downloadStatus = DOWNLOAD_FAILED;
    else
      dlm->downloadStatus = DOWNLOAD_COMPLETE;
    SEMAPHORE_UP(dlm->doneSem); /* signal: we're done with download */
    gdk_flush();
    gtkSaveCallDone(call->sem);
    
    return FALSE;
  }
  gdk_flush();
  gtkSaveCallDone(call->sem);
    
  return FALSE;  
}

/**
 * This method is called by the download code to notify the user
 * interface of the download progress.
 *
 * @param stats the new statistical values
 * @param dlm the accessor to the GTK window
 */
static void modelCallback(ProgressStats * stats,
			  DownloadModel * dlm) {
  double currentRetryAvg, averageBps, percentage;
  DLStats dlStats;
  TIME_T now;
#if DEBUG_WRITE_CPSDATA
  char scratch[128];
  FILE * fp;
#endif
  
  if (dlm->downloadStatus != DOWNLOAD_PENDING) 
    return;

  /* don't display more often than once/sec */
  TIME(&now);
  if ((now-(dlm->lastDisplayTime)) < 1 &&
      (stats->filesize != stats->progress))
    return;
  else
    dlm->lastDisplayTime = now;
 
  if(stats->requestsSent > 0)
    currentRetryAvg = 
      (double)stats->currentRetries / 
      (double)stats->requestsSent;
  else
    currentRetryAvg = 0;
  
  if (now - dlm->downloadStartTime > 0)
    averageBps =
      (double)(stats->progress) / 
      ((double)(now - dlm->downloadStartTime));
  else
    averageBps = 0;

#if DEBUG_WRITE_CPSDATA
  SNPRINTF(scratch,
	   128,
	   "/tmp/cps-%x.txt", 
	   dlm->root.header.fileIdentifier.crc);
  fp = FOPEN(scratch, "a+");
  fprintf(fp, "%d %d %d %f\n", (int)(now-(dlm->downloadStartTime)),
	  stats->progress,
	  stats->totalRetries,
          averageBps);
  fclose(fp);
#endif
  
  if(stats->filesize>0)
    percentage = 100.0*((double)stats->progress/(double)stats->filesize);
  else
    percentage = 0;

  SNPRINTF(dlStats.pos, sizeof(dlStats.pos), "%d", stats->progress);
  SNPRINTF(dlStats.kbs, sizeof(dlStats.kbs), "%.1f", averageBps);
  SNPRINTF(dlStats.perc, sizeof(dlStats.perc), "%3.1f%%", percentage);
  SNPRINTF(dlStats.areq, sizeof(dlStats.areq), "%d", stats->requestsSent);
  SNPRINTF(dlStats.cra, sizeof(dlStats.cra), "%3.1f", currentRetryAvg);
  SNPRINTF(dlStats.tr, sizeof(dlStats.tr), "%d", stats->totalRetries);
  dlStats.stats = stats; 
  dlStats.dlm = dlm;
  
  gtkSaveCall((GtkFunction) displayStats, &dlStats);
}

gint setDownloadEntry(SaveCall *call) {
  gint row;
  DownloadModel *dlm = ((SetDownloadEntry *) call->args)->dlm;

  gtk_clist_freeze(GTK_CLIST(dlm->dlList));
  row = gtk_clist_find_row_from_data(GTK_CLIST(dlm->dlList),
		       dlm);
  gtk_clist_set_foreground(GTK_CLIST(dlm->dlList), 
                           row,
                           ((SetDownloadEntry *) call->args)->color);
  gtk_clist_set_text(GTK_CLIST(dlm->dlList),
	  	       row,
             1,
             ((SetDownloadEntry *) call->args)->text);
  gtk_clist_thaw(GTK_CLIST(dlm->dlList));
  gdk_flush();
  gtkSaveCallDone(call->sem);
  
  return FALSE;
}

gint disentangleFromCLIST(SaveCall *call) {
  gint row;
  DownloadModel *dlm = (DownloadModel *) call->args;

  gtk_clist_freeze(GTK_CLIST(dlm->dlList));
  row = gtk_clist_find_row_from_data(GTK_CLIST(dlm->dlList),
				     dlm);
  gtk_clist_set_row_data(GTK_CLIST(dlm->dlList),
                         row,
			                   NULL);
  gtk_clist_thaw(GTK_CLIST(dlm->dlList));
  gdk_flush();
  gtkSaveCallDone(call->sem);

  return FALSE;
}

/**
 * Main function of the download thread. This function terminates
 * automagically once the download is complete or if the download
 * entry is removed while dl.  It is responsible for stopping the
 * requestmanager.
 * 
 * @param dlm the download model
 */
static void downloadFile_(DownloadModel * dlm) {
  char * mime, * uri;
  SetDownloadEntry entry;

  LOG(LOG_DEBUG,
      "Entering '%s' for file '%s' (%p)\n", 
      __FUNCTION__,
      dlm->fileName,
      dlm);

  /* initiate download */
  TIME(&dlm->downloadStartTime);
  
  /* this starts the "real" download thread in the background,
     with "modelCallback" called back to tell us about the progress */
  dlm->rm = downloadFile(&dlm->root.header.fileIdentifier,
			 dlm->fileName,
			 (ProgressModel)&modelCallback,
			 dlm);
  if (dlm->rm == NULL) {
    guiMessage(_("Could not download file '%s'.\nConsult logs.\n"),
	       dlm->fileName);
    SEMAPHORE_FREE(dlm->doneSem);
    FREE(dlm->fileName);
    FREE(dlm);
    return;
  }
  /* Wait here until download is complete or
     the window is closed or gnunet-gtk is terminated */
  LOG(LOG_DEBUG,
      "Waiting for download completion (%p).\n",
      dlm);
  SEMAPHORE_DOWN(dlm->doneSem);
  LOG(LOG_DEBUG,
      "Download complete (%d) calling '%s' (%p).\n",
      dlm->downloadStatus,
      "destroyRequestManager",
      dlm);

  /* stop the RequestManager */
  if (dlm->rm != NULL) {
    destroyRequestManager(dlm->rm); 
  } else {
    /* this can happen if the requestmanager initialization
     * failed for reason or another (e.g. write permission denied) */
    BREAK();
  }

  /*
    ok, now why are we here? 4 possibilities:
     a) download aborted (user closed window)
     b) gnunet-gtk terminated (same as download aborted)
     c) download failed (gnunetd exit, out-of-space)
     d) download completed 

     In case "d" we show the "YAY" window
     and wait for another signal.
     In case "c" we show the "BAH" window
     and wait for another signal.
  */

  switch (dlm->downloadStatus) {
  case DOWNLOAD_COMPLETE:
    /* color successful dl green */
    entry.dlm = dlm;
    entry.color = &textColors[3];
    entry.text = _("DONE");
    gtkSaveCall((GtkFunction) setDownloadEntry, &entry);

    uri = createFileURI(&dlm->root.header.fileIdentifier);
    removeResumeInfo(uri);
    FREE(uri);
    
    mime = getMimetypeFromNode(&dlm->root);
    if (0 == strcmp(mime,
		    GNUNET_DIRECTORY_MIME)) {
      displayDirectory(dlm->fileName,
		       &dlm->root);
    }
    FREE(mime);
    SEMAPHORE_DOWN(dlm->doneSem); /* wait for window closing */
    break;
  case DOWNLOAD_FAILED:
    /* color failed dl red */ 
    entry.dlm = dlm;
    entry.color = &textColors[4];
    entry.text = _("FAIL");
    gtkSaveCall((GtkFunction) setDownloadEntry, &entry);
  
    SEMAPHORE_DOWN(dlm->doneSem); /* wait for window closing */    
    break;
  default:
    /* do nothing */
    break;
  }

  /* finally, disentangle from the clist and free dlm resources */
  gtkSaveCall((GtkFunction) disentangleFromCLIST, dlm);
  SEMAPHORE_FREE(dlm->doneSem);
  FREE(dlm->fileName);
  FREE(dlm);
}

/**
 * Open the download window and start the download of a file in the
 * background. The method executes during a signal handler, so a GTK
 * lock is not required to to GUI operations.
 *
 * @param filename the name of the file to download
 *        (must copy, will be freed by caller)
 * @param root information about what to download 
 *        (will be freed by caller, must copy!)
 */
void startDownload(const gchar * filename,
		   RootNode * root) {
  GtkWidget * clist;
  char * fileNameRoot;
  int i;
  gint row;
  DownloadModel * dlm;
  gchar * fileInfo[8];
  char * fstring;

  dlm = MALLOC(sizeof(DownloadModel));
  memset(dlm, 
	 0, 
	 sizeof(DownloadModel));
  dlm->fileName = STRDUP(filename);
  memcpy(&dlm->root,
	 root,
	 sizeof(RootNode));

  fileNameRoot = dlm->fileName;
  for (i=strlen(dlm->fileName)-1;i>=0;i--) {
    if (dlm->fileName[i] == DIR_SEPARATOR) {
      fileNameRoot = &dlm->fileName[i+1];
      break;
    }
  }
  
  /* create new download window? */
  if (!dlWindow) {
    GtkWidget * scrolled_window;
    GtkWidget * button;
    GtkWidget * box;
    GtkWidget * entry;
    GtkWidget * menu;
    GtkItemFactory *popupFactory;
    static gchar * descriptions[] = {
      gettext_noop("filename"),
      "%",              /* Completion percentage */
      gettext_noop("position"),	/* Bytes dl'ed so far */
      gettext_noop("size"),
      gettext_noop("active requests"),		/* Active block requests */
      gettext_noop("retrie per active request"),           /* Current Retries per Active requests */
      gettext_noop("total retries"),           /* Total Retries */
      gettext_noop("BPS"),            /* Current bytes per second -estimate */
    };
    static int widths[] = {
      300, 50,  50, 50, 50,  50, 50, 50
    };

    dlWindow = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(dlWindow), 
  	  	         _("gnunet-gtk: Downloads"));
    gtk_widget_set_usize(GTK_WIDGET(dlWindow),
                         780, /* x-size */
                         300); /* y-size */
    gtk_signal_connect_object(GTK_OBJECT(dlWindow), 
			      "delete_event",
                              GTK_SIGNAL_FUNC(hideWindow),
                              GTK_OBJECT(dlWindow));
    gtk_signal_connect_object(GTK_OBJECT(dlWindow), 
			      "destroy",
                              GTK_SIGNAL_FUNC(hideWindow),
                              GTK_OBJECT(dlWindow));


    box = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(dlWindow), 
  	  	      box);
    gtk_container_set_border_width(GTK_CONTAINER(dlWindow), 
 				   8);
   
    /* scrolled window for the dl list */
    scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
                                   GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_ALWAYS);
    gtk_box_pack_start(GTK_BOX(box),
                       scrolled_window,
                       TRUE,
                       TRUE,
                       0);
    gtk_widget_show(scrolled_window);
    /* create a list to hold the downloads in */
    clist = gtk_clist_new_with_titles(8, descriptions);
    gtk_clist_set_selection_mode
              (GTK_CLIST(clist),
	       GTK_SELECTION_EXTENDED);
    for (i=0;i<8;i++) {
      gtk_clist_set_column_width(GTK_CLIST(clist),
                                 i,
                                 widths[i]);
      gtk_clist_column_title_active(GTK_CLIST(clist),
                                 i);
    }
    gtk_signal_connect(GTK_OBJECT(clist),
                       "click-column",
                       GTK_SIGNAL_FUNC(sort_column_callback),
                       NULL);
    gtk_container_add(GTK_CONTAINER(scrolled_window),
    		      clist);
    gtk_object_set_data(GTK_OBJECT(dlWindow),
    			"LIST",
			clist);
    gtk_widget_show(box);
    gtk_widget_show(scrolled_window);
    /* cancel/remove button */
    button = gtk_button_new_with_label(_("Remove selected entries"));
    gtk_signal_connect (GTK_OBJECT(button),
                      "clicked",
                      GTK_SIGNAL_FUNC(abortSelectedDownloads),
                      clist);
    gtk_box_pack_start(GTK_BOX(box),
                       button,
                       FALSE,
                       FALSE,
                       0);
    gtk_widget_show(button);

    /* activate the pulldown menu option now */
    entry = gtk_item_factory_get_widget(itemFactory,
                                        gettext_noop("/File/Show downloads"));
    gtk_widget_set_sensitive(entry, TRUE);

    /* add popup menu */
    popupFactory = gtk_item_factory_new (GTK_TYPE_MENU, "<main>",
                                         NULL);
    gtk_item_factory_create_items(popupFactory, 
                                  dlWindowMenuItems,
				  dlWindowMenu,
				  NULL);
    menu = gtk_item_factory_get_widget (popupFactory, "<main>");
    gtk_signal_connect(GTK_OBJECT(dlWindow),
                     "event",
                     GTK_SIGNAL_FUNC(popupCallback),
                     menu);
  } else {
    /* use existing dlWindow and list */
    clist = gtk_object_get_data(GTK_OBJECT(dlWindow),
    				"LIST");
  }

  /* set default disp. values for new download */
  fileInfo[0]=STRDUP(fileNameRoot);
  fileInfo[1]="0%";
  fileInfo[2]="-";
  fileInfo[3]=MALLOC(32);
  fileInfo[4]="-";
  fileInfo[5]="-";
  fileInfo[6]="-";
  fileInfo[7]="-";
  SNPRINTF(fileInfo[3], 
	   32, 
	   "%u", 
	   (unsigned int) ntohl(dlm->root.header.fileIdentifier.file_length));

  TIME(&dlm->lastDisplayTime);

  gtk_clist_freeze(GTK_CLIST(clist));  
  row = gtk_clist_append(GTK_CLIST(clist),
			 fileInfo);
  FREE(fileInfo[0]);
  FREE(fileInfo[3]);
  gtk_clist_set_foreground(GTK_CLIST(clist), 
			   row,
                          &textColors[15]);
  gtk_clist_set_row_data(GTK_CLIST(clist),
  			 row,
			 dlm);
  gtk_clist_thaw(GTK_CLIST(clist));
			 
  /* remember clist for updates in the DLM struct */
  dlm->dlList = clist;
  dlm->downloadStatus = DOWNLOAD_PENDING;
  dlm->doneSem = SEMAPHORE_NEW(0);
  
  /* display download window */
  gtk_widget_show(clist);
  gtk_widget_show(dlWindow);

  /* append an info note */
  fstring = createFileURI(&dlm->root.header.fileIdentifier);
  infoMessage(NO, 
	      "gnunet-download -o \"%s\" %s\n",
  	      dlm->fileName,
	      fstring);

  /* save file information to resume downloads later */
  if (strlen(dlm->fileName) > MAX_FILENAME_LEN)
    guiMessage(_("Can't record resume information: filename too long!"));
  else
    storeResumeInfo(fstring, dlm->fileName);
  
  FREE(fstring);  

  /* create thread that runs the download */
  if (0 != PTHREAD_CREATE(&dlm->downloadThread,
			  (PThreadMain) &downloadFile_,
			  dlm,
			  64 * 1024))
    DIE_STRERROR("pthread_create");
  PTHREAD_DETACH(&dlm->downloadThread);  
}

void downloadAFSuri(char *uri, char *fn) {
  RootNode root;
  char *downloadDir;

  if(!uri)
    return;

  if (OK != parseFileURI(uri,
			 &root.header.fileIdentifier)) {
    guiMessage(_("Invalid gnunet AFS URI '%s'."),
	       uri);
    return;
  }

  root.header.major_formatVersion = ROOT_MAJOR_VERSION;
  root.header.minor_formatVersion = ROOT_MINOR_VERSION;
  strcpy(root.header.mimetype,
    "unknown");

  if (strlen(fn) > sizeof(root.header.filename)) {
    guiMessage(_("Can't download AFS content: filename too long"));
    return;
  }
  
  strcpy(root.header.filename, fn);

  downloadDir = getConfigurationString("AFS",
                  "DOWNLOADDIR");

  if(downloadDir != NULL) {
    char * expanded;

    expanded = expandFileName(downloadDir);

    if ((SYSERR == mkdirp(expanded)))
      LOG_FILE_STRERROR(LOG_WARNING, "mkdirp", expanded);
    CHDIR(expanded);
    FREE(expanded);
    FREE(downloadDir);
  }
  
  startDownload(root.header.filename,
                &root);
}

/**
 * Starts a file download when user has filled in the fields
 */ 
void fetchURICallback(GtkWidget * widget,
		      gpointer data) {
  const gchar * uri;
  GtkWidget * entry;
  char *fn;
  
  entry = gtk_object_get_data(GTK_OBJECT(data),
			      "entry");

  uri = gtk_entry_get_text(GTK_ENTRY(entry));
    
  /* FIXME: prompt for filename! */
  fn = (char *) MALLOC(MAX_FILENAME_LEN);
  SNPRINTF(fn,
	   MAX_FILENAME_LEN,
	   "unknown.%ld", 
	   (unsigned long)time(NULL));  
  
  downloadAFSuri((char *) uri, fn);
  FREE(fn);
  
  gtk_widget_destroy(data);
}

void fetchURI(GtkWidget * widget,
	      gpointer data) {
  GtkWidget * window;
  GtkWidget * vbox;
  GtkWidget * label;
  GtkWidget * entry;
  GtkWidget * hbox;
  GtkWidget * button_ok;
  GtkWidget * button_cancel;

  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_widget_set_usize(GTK_WIDGET(window),
  		       780,
		       100);
  gtk_window_set_title(GTK_WINDOW(window),
  		       _("Download URI"));
  /* add container for window elements */
  vbox = gtk_vbox_new(FALSE, 15);
  gtk_container_add(GTK_CONTAINER(window),
                    vbox);
  gtk_widget_show(vbox);

  /* when user clicks on close box, always "destroy" */
  gtk_signal_connect(GTK_OBJECT(window),
                     "destroy",
                     GTK_SIGNAL_FUNC(destroyWidget),
                     window);

  gtk_container_set_border_width(GTK_CONTAINER(window),
                                 10);
  
  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     TRUE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
 
  label = gtk_label_new(_("GNUnet AFS URI: "));
  gtk_box_pack_start(GTK_BOX(hbox),
		     label,
		     FALSE,
		     FALSE,
		     0);
  gtk_widget_show(label);
  entry = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(hbox),
		     entry,
                     TRUE,
		     TRUE,	
		     0);
  gtk_signal_connect(GTK_OBJECT(entry),
                     "activate",
                     GTK_SIGNAL_FUNC(fetchURICallback),
                     window);
  gtk_object_set_data(GTK_OBJECT(window),
		      "entry",
		      entry);
  gtk_widget_show(entry);

  button_ok = gtk_button_new_with_label(_("Ok"));
  button_cancel = gtk_button_new_with_label(_("Cancel"));

  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
                     hbox,
                     FALSE,
                     FALSE,
                     0);
  gtk_box_pack_start(GTK_BOX(hbox),
		     button_ok,
		     TRUE,
		     TRUE,
		     0);
  gtk_box_pack_start(GTK_BOX(hbox),
		     button_cancel,
		     TRUE,
		     TRUE,
		     0);
  gtk_signal_connect(GTK_OBJECT(button_cancel),
		     "clicked",
		     GTK_SIGNAL_FUNC(destroyWidget),
		     window);
  gtk_signal_connect(GTK_OBJECT(button_ok),
		     "clicked",
		     GTK_SIGNAL_FUNC(fetchURICallback),
		     window);
  gtk_widget_show(hbox);
  gtk_widget_show(button_ok);
  gtk_widget_show(button_cancel);
  gtk_widget_show(window);
}
		 

/* end of download.c */
