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
 * @file src/applications/afs/gtkui/search.c
 * @brief box displaying search results for the gtk+ client.
 * @author Christian Grothoff
 * @author Igor Wronsky
 */

#include "gnunet_afs_esed2.h"
#include "helper.h"
#include "download.h"
#include "saveas.h"
#include "search.h"
#include "main.h"

static void searchSelectAll(void);
static void searchSelectNone(void);
static void searchSelectByName(void);
static void searchSelectByDesc(void);
static void searchSelectByMime(void);
static void searchClose(void);
static void searchDownloadSelected(void); 

static GtkItemFactoryEntry searchWindowMenu[] = {
  { gettext_noop("/Select all"),            NULL,   searchSelectAll,      0, "<Item>" },
  { gettext_noop("/Unselect all"),          NULL,   searchSelectNone,     0, "<Item>" },
  { "/sep1",                                NULL,   NULL,                 0, "<Separator>" },
  { gettext_noop("/Select by filename"),    NULL,   searchSelectByName,   0, "<Item>" },
  { gettext_noop("/Select by description"), NULL,   searchSelectByDesc,   0, "<Item>" },
  { gettext_noop("/Select by mimetype"),    NULL,   searchSelectByMime,   0, "<Item>" },
  { "/sep2",                                NULL,   NULL,                 0, "<Separator>" },
  { gettext_noop("/Download selected"),     NULL,   searchDownloadSelected,  0, "<Item>" },
  { "/sep3",                                NULL,   NULL,                 0, "<Separator>" },
  { gettext_noop("/Abort search"),          NULL,   searchClose,          0, "<Item>" }
};

static gint searchWindowMenuItems
  = sizeof (searchWindowMenu) / sizeof (searchWindowMenu[0]);

/**
 * Selects all search results from the current search page.
 */
static void searchSelectAll(void)
{
  gint pagenr;
  GtkWidget * page;
  ListModel * model;

  pagenr = gtk_notebook_get_current_page(notebook);
  if(pagenr<0)
    return;
  page = gtk_notebook_get_nth_page(notebook,
                                   pagenr);
  if(!page)
    return;
  model = gtk_object_get_data(GTK_OBJECT(page),
                              "MODEL");
  if(model)
    gtk_clist_select_all(GTK_CLIST(model->search_result_list));
}

/**
 * Unselects all search results from the current search page.
 */
static void searchSelectNone(void)
{
  gint pagenr;
  GtkWidget * page;
  ListModel * model;

  pagenr = gtk_notebook_get_current_page(notebook);
  if(pagenr<0)
    return;
  page = gtk_notebook_get_nth_page(notebook,
                                   pagenr);
  if(!page)
    return;
  model = gtk_object_get_data(GTK_OBJECT(page),
                              "MODEL");
  if(model)
    gtk_clist_unselect_all(GTK_CLIST(model->search_result_list));
}

static void selectByCallback(GtkWidget * dummy,
		             GtkWidget * entry) {
  const gchar * nameString;
  gint pagenr;
  GtkWidget * page;
  GtkCList * clist;
  ListModel * model;
  int i;
  int j; 
  int * data;
  int column;

  data = gtk_object_get_data(GTK_OBJECT(entry),
	 	             "COLUMNID");
  column = *data;
  FREE(data);

  nameString = gtk_entry_get_text(GTK_ENTRY(entry));
  if(nameString == NULL) {
    BREAK();
    return;
  }
  if (nameString[0] == 0) {
    BREAK();
    return;
  }
 
  pagenr = gtk_notebook_get_current_page(notebook);
  if(pagenr<0)
    return;
  page = gtk_notebook_get_nth_page(notebook,
                                   pagenr);
  if(!page)                        
    return;
  model = gtk_object_get_data(GTK_OBJECT(page),
                              "MODEL");
  if(model) {
    gchar * tmp;
    gchar * haystack;
    gchar * needle;  
    int hits = 0;

    needle = STRDUP(nameString);
    for(i=0;i<strlen(needle);i++)
      needle[i]=tolower(needle[i]);

    clist = GTK_CLIST(model->search_result_list);

    gtk_clist_freeze(clist);
    for(i=0;i<clist->rows;i++) {
      gtk_clist_get_text(clist,
                         i,
                         column,
                         &tmp);
      haystack = STRDUP(tmp);
      for(j=0;j<strlen(haystack);j++)
        haystack[j]=tolower(haystack[j]);
 
      if(strstr(haystack, needle)!=NULL) {
         gtk_clist_select_row(clist,
                              i,
                              1);
         hits++;
      }
      FREE(haystack);
    }
     
    gtk_clist_thaw(clist);
    if (hits==0)
      guiMessage(_("No matches."));
    FREE(needle);
  }
}


static void searchSelectByColumn(int column)
{
  GtkWidget *window;
  GtkWidget *vbox;
  GtkWidget *label; 
  GtkWidget *entry;
  GtkWidget *button;
  int * data;

  data = MALLOC(sizeof(int));
  *data = column;

  window = gtk_window_new(GTK_WINDOW_POPUP);
  vbox = gtk_vbox_new(FALSE, 0);
  gtk_container_add(GTK_CONTAINER(window),
                    vbox);
  label = gtk_label_new(_("Pattern? "));
  gtk_container_add (GTK_CONTAINER(vbox),
                     label);
  entry = gtk_entry_new();
  gtk_object_set_data(GTK_OBJECT(entry),
		      "COLUMNID",
		      data);
  gtk_entry_set_text(GTK_ENTRY(entry), 
  		     "");
  gtk_signal_connect(GTK_OBJECT(entry),
  		     "activate",
		     GTK_SIGNAL_FUNC(selectByCallback),
		     entry);
  gtk_signal_connect(GTK_OBJECT(entry),
  		     "activate",
		     GTK_SIGNAL_FUNC(destroyWidget),
		     window);
  gtk_container_add(GTK_CONTAINER(vbox),
  		    entry);
  button = gtk_button_new_with_label(_("Ok"));
  gtk_container_add(GTK_CONTAINER(vbox),
		    button);
  gtk_signal_connect(GTK_OBJECT(button),
		     "clicked",
		     GTK_SIGNAL_FUNC(selectByCallback),
		     entry);
  gtk_signal_connect(GTK_OBJECT(button),
  		     "clicked",
		     GTK_SIGNAL_FUNC(destroyWidget),
		     window);
  gtk_window_set_position(GTK_WINDOW(window),
 			  GTK_WIN_POS_MOUSE);
  gtk_widget_show_all(window);
  gtk_widget_grab_focus(entry);

}

static void searchSelectByName(void)
{
  searchSelectByColumn(2);
}

static void searchSelectByDesc(void)
{
  searchSelectByColumn(0);
}

static void searchSelectByMime(void) {
  searchSelectByColumn(6);
}

/**
 * Remove the active page from the search results notebook.
 * The respective search will be stopped as well
 * (by a callback assigned to the page earlier on).
 */
void searchClose(void) {
  gint pagenr;
  
  pagenr = gtk_notebook_get_current_page(notebook);
  gtk_notebook_remove_page(notebook, pagenr);
  /* Need to refresh the widget --
     This forces the widget to redraw itself. */
  gtk_widget_draw(GTK_WIDGET(notebook), NULL);
}

/**
 * This method is called whenever the user clicks the
 * download button.  It opens the "save-as" dialog.
 *
 * @param widget not used
 * @param listModel Data related to the search
 */
static void downloadGTK(GtkWidget * widget,
			ListModel * listModel);


static void searchDownloadSelected(void) {
  gint pagenr;
  GtkWidget * page;
  ListModel * model;

  pagenr = gtk_notebook_get_current_page(notebook);
  if(pagenr<0)
    return;
  page = gtk_notebook_get_nth_page(notebook,
                                   pagenr);
  if(!page)
    return;
  model = gtk_object_get_data(GTK_OBJECT(page),
                              "MODEL");
  if(model)
    downloadGTK(NULL, model);
}

/**
 * This method is called whenever the user clicks the
 * download button.  It opens the "save-as" dialog.
 *
 * @param widget not used
 * @param listModel Data related to the search
 */
static void downloadGTK(GtkWidget * widget,
			ListModel * listModel) {  
  gint row;
  GList * tmp;
  
  tmp=GTK_CLIST(listModel->search_result_list)->selection;
	  
  if ( !tmp ) {
    guiMessage(_("Nothing selected!\n"));
    return;
  }
    
  gtk_clist_freeze(GTK_CLIST(listModel->search_result_list));

  /* download all selected entries */
  while (tmp) {
    RootNode * rootNode;
    
    row = (int)tmp->data;
    tmp = tmp->next;
    rootNode = (RootNode *)
      gtk_clist_get_row_data(GTK_CLIST(listModel->search_result_list),
                             row);
    openSaveAs(rootNode);
  
    /* Remove entry from search results.  Yes,
       if the user cancel's the download, the
       entry does not re-appear.  That's intended,
       after all, if you cancel, it's probably because
       it took too long to download anyway... 
       If you really need it back, just search again! */
    gtk_clist_remove(GTK_CLIST(listModel->search_result_list),
      	  	     row);

    FREE(rootNode);
  }
  gtk_clist_thaw(GTK_CLIST(listModel->search_result_list));
}

static void freeSearchList(GtkWidget * dummy,
			   GtkCList * clist) {
  int i;

  /* Free clist stored rootNode data */
  gtk_clist_freeze(clist);
  for(i=0;i<clist->rows;i++) {
    RootNode * rootNode;
    
    rootNode = (RootNode *)
      gtk_clist_get_row_data(clist,
                             i);
    FREE(rootNode);
  }
  gtk_clist_clear(clist);
  gtk_clist_thaw(clist);
}

static gint doDisplayResult(SaveCall *call) {
  int newrow;
  GtkWidget *search_result_list = ((Result *) call->args)->search_result_list;

  gtk_clist_freeze(GTK_CLIST(search_result_list));
  newrow = gtk_clist_append(GTK_CLIST(search_result_list),
	  	                      ((Result *) call->args)->results);
  gtk_clist_set_row_data(GTK_CLIST(search_result_list),
  			                 newrow,
			                   ((Result *) call->args)->rootCopy);
  gtk_clist_thaw(GTK_CLIST(search_result_list));

  gtkSaveCallDone(call->sem);
  
  return FALSE;
}

/**
 * Display results.  This is a callback from receiveResults that is
 * called on every new result.
 *
 * @param rootNode Data about a file
 * @param model Data related to the search
 */
void displayResultGTK(RootNode * rootNode,
		      ListModel * model) {
  RootNode * rootCopy;
  SBlock * sb;
  gchar * results[5];
  Result result;
  int i;
  char * verb, * p, c;
  
  if(model->doTerminate == YES)
    return;

  rootCopy = MALLOC(sizeof(RootNode));
  memcpy(rootCopy,
         rootNode,
   	 sizeof(RootNode));

  switch (ntohs(rootNode->header.major_formatVersion)) {
  case ROOT_MAJOR_VERSION:
    /* ensure well-formed strings */
    rootNode->header.description[MAX_DESC_LEN-1] = 0;
    rootNode->header.filename[MAX_FILENAME_LEN-1] = 0;
    rootNode->header.mimetype[MAX_MIMETYPE_LEN-1] = 0;
    
    results[0] = STRDUP(rootNode->header.description);

    /* suppress line breaks */
    p = results[0];
    while((c = *p)) {
      if (c == '\r' || c == '\n' || c == '\t')
        *p = ' ';
      p++;
    }

    results[1] = MALLOC(32);
    SNPRINTF(results[1],
	     32,
	     "%u", 
	     (unsigned int) ntohl(rootNode->header.fileIdentifier.file_length));
    if ( (0 == strcmp(rootNode->header.mimetype,
		      GNUNET_DIRECTORY_MIME)) &&
	 (rootNode->header.filename[strlen(rootNode->header.filename)-1] != DIR_SEPARATOR) ) {
      results[2] = MALLOC(strlen(rootNode->header.filename)+2);
      strcpy(results[2], rootNode->header.filename);
      strcat(results[2], "/");      
    } else
      results[2] = STRDUP(rootNode->header.filename);
    results[3] = STRDUP(rootNode->header.mimetype);
    results[4] = createFileURI(&rootNode->header.fileIdentifier);
    break;
  case SBLOCK_MAJOR_VERSION:
    sb = (SBlock*) rootNode;
    sb->description[MAX_DESC_LEN-1] = 0;
    sb->filename[MAX_FILENAME_LEN/2-1] = 0;
    sb->mimetype[MAX_MIMETYPE_LEN/2-1] = 0;
    
    results[0] = STRDUP(rootNode->header.description);
    results[1] = MALLOC(32);
    SNPRINTF(results[1], 
	     32,
	     "%u", 
	     (unsigned int) ntohl(sb->fileIdentifier.file_length));
    results[2] = STRDUP(sb->filename);
    results[3] = STRDUP(sb->mimetype);    
    results[4] = createFileURI(&rootNode->header.fileIdentifier);
    break;
  case NBLOCK_MAJOR_VERSION:
    addNamespace((const NBlock*) rootNode);
    verb = rootNodeToString(rootNode);
    infoMessage(NO, 
		_("Discovered namespace:\n%s\n"),
		verb);
    FREE(verb);
    return;
  default:
    LOG(LOG_ERROR,
	_("Search result received of unsupported type %d.\n"),
	ntohs(rootNode->header.major_formatVersion));
    return;
  }
  result.search_result_list = model->search_result_list;
  result.rootCopy = rootCopy;
  memcpy(&result.results, &results, sizeof(results));
  gtkSaveCall((GtkFunction) doDisplayResult, &result);
  if (model->skipMenuRefresh != YES)
    refreshMenuSensitivity();

  for (i=0;i<5;i++)
    FREE(results[i]);
}

/**
 * Struct to pass a couple of arguments to a new
 * thread "receiveResults_".
 */
typedef struct {
  char * searchString;
  ListModel * model;
} _receiveResultArgs_;

/**
 * Should the receive thread abort? (has the window been closed?)
 * This is a callback for the receiveResults method (since
 * not every "error" on the socket corresponds to a closed
 * window!).
 *
 * @return YES if we should abort
 */
int testTermination(ListModel * model) {
  return model->doTerminate;
}

/**
 * Main method of the receiveResults-threads.
 * Runs the receiveResults method and frees some
 * data structures once the search is aborted.
 * See also "stopSearch".
 */
static void * receiveResults_(_receiveResultArgs_ * args) {
  char ** keywords;
  int num_Words;
  int inWord;
  char * c;


  num_Words = 0;
  for (inWord = 0, c = args->searchString; *c != '\0'; ++c) {
    if (isspace(*c)) {
      inWord = 0;
    } else if (!inWord) {
      inWord = 1;
      ++num_Words;
    }
  }

  if (num_Words == 0) {
    FREENONNULL(args->searchString);
    FREE(args);
    LOG(LOG_FAILURE, 
	_("No keywords specified!\n"));
    return NULL;
  }
  keywords = MALLOC(num_Words * sizeof(char *));
  num_Words = 0;
  for (inWord = 0, c = args->searchString; *c != '\0'; ++c) {
    if (isspace(*c)) {
      inWord = 0;
      *c = '\0';
    } else if (!inWord) {
      keywords[num_Words] = c;
      inWord = 1;
      ++num_Words;
    }
  }
  searchRBlock(args->model->SEARCH_socket_,
	       keywords,
	       num_Words,
	       (SearchResultCallback) &displayResultGTK,
	       args->model,
	       (TestTerminateThread)&testTermination,
	       args->model);  
  FREE(args->searchString);
  FREE(keywords);
  FREE(args);
  return NULL;
}

/**
 * The main method of the search-thread.
 *
 * @param searchString What to look for
 * @param model Data related to the search
 * @return OK on success, SYSERR on error
 */
static int startSearchThread(char * searchString,
			     ListModel * model) {
  _receiveResultArgs_ * receiveArgs;

  receiveArgs = MALLOC(sizeof(_receiveResultArgs_));
  receiveArgs->searchString = STRDUP(searchString);
  receiveArgs->model = model;  
  if (0 != PTHREAD_CREATE(&model->thread,
			  (PThreadMain) &receiveResults_,
			  receiveArgs,
			  16 * 1024)) 
    DIE_STRERROR("pthread_create");  
  return OK;
}

/**
 * Cron job that stops the search.
 */
static void stopSearch_(ListModel * model) {
  void * unused;

  switch (model->type) {
  case LM_TYPE_DIRECTORY:
    break;
  case LM_TYPE_SEARCH:
    /* the terminated search thread ups this semaphore
       once it is done and we can free data structures */
    model->doTerminate = YES;
    
    /* this signals the download thread to terminate */
    closeSocketTemporarily(model->SEARCH_socket_);
    
    /* wait for download thread signal */
    PTHREAD_JOIN(&model->thread,
		 &unused);
    
    /* Now we can finally free the shared data structures.
       Note that the terminated search thread freed 
       some of the memory that was allocated in
       startSearchThread (see receiveResults_)
       we free the rest. */
    releaseClientSocket(model->SEARCH_socket_);  
    break;
  case LM_TYPE_NSSEARCH:
    model->doTerminate = YES;
    /* this signals the download thread to terminate */
    closeSocketTemporarily(model->SEARCH_socket_);    
    /* wait for download thread signal */
    PTHREAD_JOIN(&model->thread,
		 &unused);
    releaseClientSocket(model->SEARCH_socket_);
    break;
  default:
    BREAK();
    break;
  }
  if (model->sem != NULL)
    SEMAPHORE_UP(model->sem);
  FREE(model);  
}

/**
 * Stop the search thread and free the model.  This method MUST always
 * be called when the search ends, either because the search was
 * aborted or because gnunet-gtk exists as a whole.  
 *
 * @param widget the window (not used)
 * @param model the model with the socket 
 */
static void stopSearch(GtkWidget * widget,
		       ListModel * model) { 
  Semaphore * cs;
  LOG(LOG_DEBUG, 
      "stopSearch called\n");
  /* this must be done as a cron-job, since otherwise
     it may deadlock (this is called from the
     gtk event thread, and cron may be waiting for
     the gtk event lock, so we can't delete a cron
     job in this thread */
  model->doTerminate = YES;
  cs = SEMAPHORE_NEW(0);
  model->sem = cs;
  addCronJob((CronJob) &stopSearch_,
	     0, 0, model);
  /* this is always the gtk-thread, so we must
     not block; instead, run gtk-savecalls! */
  while (SYSERR == SEMAPHORE_DOWN_NONBLOCKING(cs)){
    if (! gtkRunSomeSaveCalls())
      gnunet_util_sleep(50 * cronMILLIS);
  }
  SEMAPHORE_FREE(cs);
}

/**
 * Changes the current sort column and sorts the list.
 */
static void sort_column_callback(GtkCList * clist,
				 gint column,
				 gpointer data) {
  static int sortOrder[5]={0,0,0,0,0};

  sortOrder[column]^=1;

  if(sortOrder[column]==1)
    gtk_clist_set_sort_type(clist,
                            GTK_SORT_ASCENDING);
  else
    gtk_clist_set_sort_type(clist,
                            GTK_SORT_DESCENDING);

  /* Sort all columns as strings except 1 (size) */
  if (column == 1)
    gtk_clist_set_compare_func(clist, 
			       (GtkCListCompareFunc)numericComp);
  else
    gtk_clist_set_compare_func(clist, 
			       (GtkCListCompareFunc)alphaComp);  
  gtk_clist_set_sort_column(clist, column);
  gtk_clist_freeze(clist);
  gtk_clist_sort(clist);
  gtk_clist_thaw(clist);
}

static gint doInitSearchResultList(SaveCall *call) {
  ListModel *model;
  GtkWidget * scrolled_window;
  GtkWidget * button;
  GtkWidget * box;
  GtkWidget * search_result_list;
  GtkWidget * menu;
  GtkItemFactory * popupFactory;
  static gchar * descriptions[] = {
    gettext_noop("Description"),
    gettext_noop("Size"),
    gettext_noop("Filename"),
    gettext_noop("Mimetype"),
    gettext_noop("URI"),
  };
  /* widths of the colums in the search results */
  static int widths[] = {
    470, 70, 200, 100, 800,
  };
  int i;
  
  model = ((InitResultList *)call->args)->model;

  box = gtk_vbox_new(FALSE, 0); 
  /* scrolled window for the list */
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
  
  /* result set list */
  search_result_list 
    = gtk_clist_new_with_titles(5, descriptions);
  model->search_result_list 
    = search_result_list;
  gtk_signal_connect(GTK_OBJECT(search_result_list), 
                     "destroy",
		     GTK_SIGNAL_FUNC(freeSearchList), 
		     search_result_list); 
  gtk_container_add(GTK_CONTAINER(scrolled_window), 
		    search_result_list);
  gtk_widget_show(search_result_list);

  gtk_clist_set_selection_mode
    (GTK_CLIST(search_result_list),
     GTK_SELECTION_EXTENDED);
  /* set passive titles as default */
  gtk_clist_column_titles_passive
    (GTK_CLIST(search_result_list));

  /* allow sorting by description, size, filename and mimetype */
  gtk_clist_column_title_active(GTK_CLIST(search_result_list),
				0);
  gtk_clist_column_title_active(GTK_CLIST(search_result_list),
				1);
  gtk_clist_column_title_active(GTK_CLIST(search_result_list),
				2);
  gtk_clist_column_title_active(GTK_CLIST(search_result_list),
				3);
  gtk_signal_connect(GTK_OBJECT(search_result_list),
		     "click-column",
		     GTK_SIGNAL_FUNC(sort_column_callback),
		     NULL);

  /* description left, size right justification */
  gtk_clist_set_column_justification
    (GTK_CLIST(search_result_list),
     0,
     GTK_JUSTIFY_LEFT);
  gtk_clist_set_column_justification
    (GTK_CLIST(search_result_list),
     1,
     GTK_JUSTIFY_RIGHT);

  /* set column widths */
  for (i=0;i<5;i++)
    gtk_clist_set_column_width(GTK_CLIST(search_result_list), 
			       i,
			       widths[i]);

  /* download button */
  button = gtk_button_new_with_label(_("Download"));
  gtk_signal_connect (GTK_OBJECT(button), 
		      "clicked",
		      GTK_SIGNAL_FUNC(downloadGTK), 
		      model);
  gtk_box_pack_start(GTK_BOX(box), 
		     button,
		     FALSE,
		     FALSE,
		     0);
  gtk_widget_show(button);
  /* generic: on delete request, just do it (always OK) */
  gtk_signal_connect(GTK_OBJECT(scrolled_window), 
                     "delete_event",
                     GTK_SIGNAL_FUNC(deleteEvent), 
                     NULL);
  /* when we are destroyed (e.g. search aborted), stop the search thread */
  gtk_signal_connect(GTK_OBJECT(scrolled_window), 
                     "destroy",
                     GTK_SIGNAL_FUNC(stopSearch), 
                     model); 
  /* store a pointer to the model for main-menu access */
  gtk_object_set_data(GTK_OBJECT(box),
		      "MODEL",
		      model);

  /* add a right button popup menu */
  popupFactory = gtk_item_factory_new (GTK_TYPE_MENU, "<main>",
                                       NULL);
  gtk_item_factory_create_items(popupFactory,
                                searchWindowMenuItems,
                                searchWindowMenu,
                                NULL);
  menu = gtk_item_factory_get_widget (popupFactory, "<main>");
  gtk_signal_connect(GTK_OBJECT(box),
                     "event",
                     GTK_SIGNAL_FUNC(popupCallback),
                     menu);

  ((InitResultList *)call->args)->ret = box;

  gtkSaveCallDone(call->sem);
  
  return FALSE;
}

GtkWidget * initializeSearchResultList(ListModel * model) {
  InitResultList init;
  
  init.model = model;
  gtkSaveCall((GtkFunction) doInitSearchResultList,
	      &init);
  return init.ret;
}

/** 
 * Returns a box containing the search results list.
 */
GtkWidget * getSearchWindow(gchar * title) {
  GtkWidget * box;
  ListModel * model;  
  int ok;

  model = (ListModel*) MALLOC(sizeof(ListModel));
  model->sem = NULL;
  model->type = LM_TYPE_SEARCH;
  model->doTerminate = NO;
  model->skipMenuRefresh = NO;
  model->SEARCH_socket_
    = getClientSocket();
  if (model->SEARCH_socket_ == NULL) {
    FREE(model);
    return NULL;
  }

  box = initializeSearchResultList(model);

  /* start searching */
  ok = startSearchThread(title,
			 model);
  if (ok == SYSERR) {
    releaseClientSocket(model->SEARCH_socket_);
    gtk_widget_destroy(box);
    FREE(model);
    return NULL;
  } else {
    /* return complete box such that it gets displayed */
    return box;
  }
}

/* end of search.c */
