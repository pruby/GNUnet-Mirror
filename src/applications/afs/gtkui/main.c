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
 * @file src/applications/afs/gtkui/main.c
 * @brief This is the main file for the gtk+ user interface.
 * @author Christian Grothoff
 * @author Igor Wronsky
 *
 *
 * Basic structure of the code is this:
 * main
 * -> search -> saveas -> download
 * -> insert
 * -> directory -> insert
 * -> pseudonyms (create|delete)
 * -> namespace insert/update
 * -> about
 *
 */

#include "gnunet_afs_esed2.h"
#include "helper.h"
#include "search.h"
#include "insert.h"
#include "delete.h"
#include "about.h"
#include "directory.h"
#include "download.h"
#include "namespace.h"
#include "pseudonyms.h"
#include "main.h"
#include "statistics.h"

/**
 * This semaphore can be used to prevent the main window
 * from killing GTK at an unhealty time. It is used by
 * the un-interruptable but GUI-updating insert thread.
 */
Semaphore * refuseToDie;

/**
 * Provides access to toggling pulldown menu shadings
 */
GtkItemFactory * itemFactory = NULL;

static GtkWidget * main_window_input_line = NULL;

static debug_flag = NO;

/**
 * Shows the info window 
 */
static void show_infowindow(GtkButton * button,
  	  	  	    gpointer dummy) {
  if(infoWindow)
    gtk_widget_show(infoWindow);
  else
    infoMessage(YES, 
		_("This window will show messages and the URIs of inserted content\n"
		  " and other information that might be useful elsewhere.\n"));
}

/**
 * Shows the download window if some dl has been started 
 */
static void show_dlwindow(GtkButton * button,
			  gpointer dummy) {
  if(dlWindow)
    gtk_widget_show(dlWindow);
}


/**
 * This method is called whenever the user clicks the
 * search button of the main window. 
 * 
 * @param widget not used
 * @param notebook the notebook where the opened result window will be put.
 */
static void search(GtkWidget * widget,
		   GtkNotebook * notebook) {
  const gchar * searchStringConst;
  gchar * searchString;
  gchar * searchStringStart;
  GtkWidget * tmp;
  int i; 

  searchStringConst
    = gtk_entry_get_text(GTK_ENTRY(main_window_input_line));
  if (searchStringConst == NULL) {
    BREAK();
    return;
  }
  searchString = STRDUP(searchStringConst);

  /* Remove heading spaces (parsing bugs if not) */  
  i = strlen(searchString)-1;
  while ( (i>=0) &&
	  (searchString[i]==' ') ) {
    searchString[i] = '\0';
    i--;
  }
  searchStringStart = searchString;
  while (*searchStringStart == ' ')
    searchStringStart++;
  if (*searchStringStart=='\0') {
    guiMessage(_("You must enter a non-empty search key!\n"));
    FREE(searchString);
    return;
  }

  /* add a new page in the notebook with the
     search results. getSearchWindow returns
     the page */
  tmp = getSearchWindow(searchStringStart);
  if (tmp != NULL) 
    addToNotebook(searchStringStart,
		  tmp);

  /* reset search line to empty */
  gtk_entry_set_text(GTK_ENTRY(main_window_input_line), 
		     ""); 
  FREE(searchString);
}

/**
 * Exit the application (called when the main window
 * is closed or the user selects File-Quit).
 */
static void destroyMain(GtkWidget * widget,
			gpointer data) {
  gdk_threads_leave(); /* avoid deadlock! */
  stopCron();
  delCronJob((CronJob)&cronCheckDaemon,
	     30 * cronSECONDS,
	     NULL);
  startCron();
  gdk_threads_enter();
  if (notebook != NULL) {
    int i = 0;    
    while(gtk_notebook_get_nth_page(notebook, 0) != NULL) {
      LOG(LOG_DEBUG, 
	  "Removing search page %d\n", 
	  i++);
      gtk_notebook_remove_page(notebook, 0);
    }
  }
  gdk_threads_leave(); /* avoid deadlock! */
  SEMAPHORE_DOWN(refuseToDie);
  gdk_threads_enter();
  gtk_main_quit(); /* back to main method! */
}

/**
 * Remove all of the root-nodes of a particular type
 * from the directory database.
 *
 * @param unused GTK handle that is not used
 * @param contexts bitmask of the databases that should be emptied.
 */ 
static void emptyDirectoryDatabaseInd(GtkWidget * unused,
				      unsigned int contexts) {
  emptyDirectoryDatabase(contexts);
  refreshMenuSensitivity();
}


/**
 * Method called from menu bar "File-Quit". Wrapper around
 * destroy.
 */ 
static void destroy_stub(void) {
  destroyMain(NULL, NULL);
}

/**
 * The pulldown menus.
 */
static GtkItemFactoryEntry menu_items[] = {
  { gettext_noop("/_File"),         
    NULL, 
    NULL,
    0,
    "<Branch>" },
  { gettext_noop("/File/_Insert"),  
    "<control>I", 
    openSelectFile, 
    0, 
    NULL },
#ifdef MINGW
  { gettext_noop("/File/_Insert directory"),  
    NULL, 
    openSelectDir, 
    0, 
    NULL },
#endif
  { gettext_noop( "/File/_Download URI"),  
    "<control>D", 
    fetchURI, 
    0, 
    NULL },
  {  gettext_noop("/File/Import di_rectory"),  
    "<control>r", 
    importDirectory, 
    0, 
    NULL },
  {  gettext_noop("/File/sep1"),     
    NULL, 
    NULL, 
    0,
    "<Separator>" },
  { gettext_noop("/File/_Unindex file"), 
    "<control>U", 
    openDeleteFile, 
    0, 
    NULL },
  { gettext_noop("/File/sep1"),     
    NULL, 
    NULL, 
    0,
    "<Separator>" },
  { gettext_noop("/File/Show downloads"),      
    "<control>w", 
    show_dlwindow, 
    0, 
    NULL },
  { gettext_noop("/File/Show messages"), 
    "<control>m", 
    show_infowindow, 
    0, 
    NULL },
  { gettext_noop("/File/Show gnunetd stats"), 
    NULL,
    showStats, 
    0, 
    NULL },
  { gettext_noop("/File/_Plot gnunetd stats"), 
    NULL,
    NULL,
    0,
    "<Branch>" },
  { gettext_noop("/File/Plot gnunetd stats/_Connectivity"), 
    NULL,
    displayStatistics, 
    STAT_CONNECTIVITY,
    NULL },
  { gettext_noop("/File/Plot gnunetd stats/C_PU Load"), 
    NULL,
    displayStatistics, 
    STAT_CPU_LOAD,
    NULL },
  { gettext_noop("/File/Plot gnunetd stats/_Inbound Traffic"), 
    NULL,
    displayStatistics, 
    STAT_IN_TRAFFIC,
    NULL },
  { gettext_noop("/File/Plot gnunetd stats/_Outbound Traffic"), 
    NULL,
    displayStatistics, 
    STAT_OUT_TRAFFIC,
    NULL },
  { gettext_noop("/File/sep1"),     
    NULL, 
    NULL, 
    0,
    "<Separator>" },
  { gettext_noop("/File/_Quit"),     
    "<control>Q", 
    destroy_stub,
    0, 
    NULL },
  { gettext_noop("/_Advanced"),
    NULL,
    NULL,
    0,
    "<Branch>" },

  { gettext_noop("/Advanced/_Assemble Directory"),
    NULL,
    NULL,
    0,
    "<Branch>" },
  { gettext_noop("/Advanced/Assemble Directory/from _search results"),
    NULL,
    openAssembleDirectoryDialog,
    DIR_CONTEXT_SEARCH,
    NULL },
  { gettext_noop("/Advanced/Assemble Directory/from _inserted files"),
    NULL,
    openAssembleDirectoryDialog,
    DIR_CONTEXT_INSERT,
    NULL },
  { gettext_noop("/Advanced/Assemble Directory/from local _namespaces"),
    NULL,
    openAssembleDirectoryDialog,
    DIR_CONTEXT_INSERT_SB,
    NULL },
  { gettext_noop("/Advanced/Assemble Directory/from file identifiers from downloaded _directories"),
    NULL,
    openAssembleDirectoryDialog,
    DIR_CONTEXT_DIRECTORY,
    NULL }, 
  { gettext_noop("/Advanced/Assemble Directory/sepx1"),     
    NULL, 
    NULL, 
    0,
    "<Separator>" },
  { gettext_noop("/Advanced/Assemble Directory/from _all known file identifiers"),
    NULL,
    openAssembleDirectoryDialog,
    DIR_CONTEXT_ALL,
    NULL },

  { gettext_noop("/Advanced/sep1"),     
    NULL, 
    NULL, 
    0,
    "<Separator>" },

  { gettext_noop("/Advanced/Manage _Pseudonyms"),     
    NULL,  
    NULL, 
    0,
    "<Branch>" },
  { gettext_noop("/Advanced/Manage Pseudonyms/_Create new pseudonym"),     
    NULL,  
    &openCreatePseudonymDialog,
    0,
    NULL },
  { gettext_noop("/Advanced/Manage Pseudonyms/_Delete pseudonym"),     
    NULL,  
    &openDeletePseudonymDialog,
    0,
    NULL },
  { gettext_noop("/Advanced/_Insert into Namespace"),     
    NULL,  
    NULL,
    0,
    "<Branch>" },
  { gettext_noop("/Advanced/Insert into Namespace/Select from _search results"),     
    NULL,  
    &openAssembleNamespaceDialog, 
    DIR_CONTEXT_SEARCH,
    NULL },
  { gettext_noop("/Advanced/Insert into Namespace/Select from _inserted files"),     
    NULL,  
    &openAssembleNamespaceDialog, 
    DIR_CONTEXT_INSERT,
    NULL },
  { gettext_noop("/Advanced/Insert into Namespace/Select from results from downloaded _directories"),     
    NULL,  
    &openAssembleNamespaceDialog, 
    DIR_CONTEXT_INSERT,
    NULL },
  { gettext_noop("/Advanced/Insert into Namespace/Select from results from local _namespaces"),     
    NULL,  
    &openAssembleNamespaceDialog, 
    DIR_CONTEXT_INSERT_SB,
    NULL },
  { gettext_noop("/Advanced/Insert into Namespace/sepx2"),     
    NULL, 
    NULL, 
    0,
    "<Separator>" },
  { gettext_noop("/Advanced/Insert into Namespace/Select from _all known file identifiers"),     
    NULL,  
    &openAssembleNamespaceDialog, 
    DIR_CONTEXT_ALL,
    NULL },
  /*  { "/Advanced/_Update content in Namespace"),     
    NULL,  
    NULL,  
    0,
    NULL }, */
  { gettext_noop("/Advanced/_Search Namespace"),     
    "<control>S",  
    &searchNamespace,  
    0,
    NULL }, 

  { gettext_noop("/Advanced/sep2"),     
    NULL, 
    NULL, 
    0,
    "<Separator>" },

  { gettext_noop("/Advanced/_Reset File Identifiers"),
    NULL,
    NULL,
    0,
    "<Branch>" },
  { gettext_noop("/Advanced/Reset File Identifiers/List of _search results"),
    NULL,
    emptyDirectoryDatabaseInd,
    DIR_CONTEXT_SEARCH,
    NULL },
  { gettext_noop("/Advanced/Reset File Identifiers/List of _inserted files"),
    NULL,
    emptyDirectoryDatabaseInd,
    DIR_CONTEXT_INSERT,
    NULL },
  { gettext_noop("/Advanced/Reset File Identifiers/List of entries in local _namespaces"),
    NULL,
    emptyDirectoryDatabaseInd,
    DIR_CONTEXT_INSERT_SB,
    NULL },
  { gettext_noop("/Advanced/Reset File Identifiers/List of files from downloaded _directories"),
    NULL,
    emptyDirectoryDatabaseInd,
    DIR_CONTEXT_DIRECTORY,
    NULL }, 
  { gettext_noop("/Advanced/Reset File Identifiers/sepx3"),     
    NULL, 
    NULL, 
    0,
    "<Separator>" },
  { gettext_noop("/Advanced/Reset File Identifiers/_All known file identifiers"),
    NULL,
    emptyDirectoryDatabaseInd,
    DIR_CONTEXT_ALL,
    NULL },
  
  { gettext_noop("/Advanced/sep3"),     
    NULL, 
    NULL, 
    0,
    "<Separator>" },
  
  { gettext_noop("/Advanced/Launch gnunetd"),     
    NULL, 
    launchDaemon, 
    0,
    NULL },
  
  { gettext_noop("/Advanced/Kill gnunetd"),     
    NULL, 
    killDaemon, 
    0,
    NULL },

/*
  { "/_Options",     
    NULL,  
    NULL, 
    0,
    "<Branch>" },
  { "/Options/Preferences(not impl)",
    NULL,  
    NULL, 
    0, 
    NULL },
*/
  { gettext_noop("/_Help"),     
    NULL,  
    NULL,
    0,
    "<LastBranch>" },
  { gettext_noop("/Help/_About"),   
    NULL,
    about,
    0, 
    NULL },
};

gint doRefreshMenuSensitivity(SaveCall *call) {
  int havePseudo;
  int haveSearch;
  int haveInsert;
  int haveDirect;
  int haveNamesp;
  int haveAny;
  int value;
  GtkWidget * entry;  

  havePseudo = havePseudonyms(); 
  if (NO == havePseudo)
    value = FALSE;
  else
    value = TRUE;
  haveSearch = 0 < iterateDirectoryDatabase(DIR_CONTEXT_SEARCH, NULL, NULL);
  haveInsert = 0 < iterateDirectoryDatabase(DIR_CONTEXT_INSERT, NULL, NULL);
  haveDirect = 0 < iterateDirectoryDatabase(DIR_CONTEXT_DIRECTORY, NULL, NULL);
  haveNamesp = 0 < iterateDirectoryDatabase(DIR_CONTEXT_INSERT_SB, NULL, NULL);
  haveAny = 0 < iterateDirectoryDatabase(DIR_CONTEXT_ALL, NULL, NULL);

  entry = gtk_item_factory_get_widget(itemFactory,
				      "/Advanced/Manage Pseudonyms/"
				      "Delete pseudonym");
  gtk_widget_set_sensitive(entry, value);
  
  
  if ( (NO == havePseudo) || (NO == haveSearch) )
    value = FALSE;
  else
    value = TRUE;
  entry = gtk_item_factory_get_widget(itemFactory,
				      "/Advanced/Insert into Namespace/"
				      "Select from search results");
  gtk_widget_set_sensitive(entry, value);  

  if ( (NO == havePseudo) || (NO == haveInsert) )
    value = FALSE;
  else
    value = TRUE;
  entry = gtk_item_factory_get_widget(itemFactory,
				      "/Advanced/Insert into Namespace/"
				      "Select from inserted files");
  gtk_widget_set_sensitive(entry, value);  
  if ( (NO == havePseudo) || (NO == haveDirect) )
    value = FALSE;
  else
    value = TRUE;
  entry = gtk_item_factory_get_widget(itemFactory,
				      "/Advanced/Insert into Namespace/"
				      "Select from results from downloaded directories");
  gtk_widget_set_sensitive(entry, value);  

  if ( (NO == havePseudo) || (NO == haveNamesp) )
    value = FALSE;
  else
    value = TRUE;
  entry = gtk_item_factory_get_widget(itemFactory,
				      "/Advanced/Insert into Namespace/"
				      "Select from results from local namespaces");
  gtk_widget_set_sensitive(entry, value);  

  if ( (NO == havePseudo) || (NO == haveAny) )
    value = FALSE;
  else
    value = TRUE;
  entry = gtk_item_factory_get_widget(itemFactory,
				      "/Advanced/Insert into Namespace/"
				      "Select from all known file identifiers");
  gtk_widget_set_sensitive(entry, value);  
  if ( NO == haveAny) 
    value = FALSE;
  else
    value = TRUE;
  
  entry = gtk_item_factory_get_widget(itemFactory,
				      "/Advanced/Assemble Directory/"
				      "from all known file identifiers");
  gtk_widget_set_sensitive(entry, value);  
  entry = gtk_item_factory_get_widget(itemFactory,
				      "/Advanced/Reset File Identifiers/"
				      "All known file identifiers");
  gtk_widget_set_sensitive(entry, value);  


  if ( NO == haveSearch) 
    value = FALSE;
  else
    value = TRUE;
  entry = gtk_item_factory_get_widget(itemFactory,
				      "/Advanced/Assemble Directory/"
				      "from search results");
  gtk_widget_set_sensitive(entry, value);  
  entry = gtk_item_factory_get_widget(itemFactory,
				      "/Advanced/Reset File Identifiers/"
				      "List of search results");
  gtk_widget_set_sensitive(entry, value);  

  if ( NO == haveInsert) 
    value = FALSE;
  else
    value = TRUE;

  entry = gtk_item_factory_get_widget(itemFactory,
				      "/Advanced/Assemble Directory/"
				      "from inserted files");
  gtk_widget_set_sensitive(entry, value);  
  entry = gtk_item_factory_get_widget(itemFactory,
				      "/Advanced/Reset File Identifiers/"
				      "List of inserted files");
  gtk_widget_set_sensitive(entry, value);  


  if ( NO == haveDirect) 
     value = FALSE;
  else
    value = TRUE;
  entry = gtk_item_factory_get_widget(itemFactory,
				      "/Advanced/Assemble Directory/"
				      "from file identifiers from downloaded directories");
  gtk_widget_set_sensitive(entry, value);  
  entry = gtk_item_factory_get_widget(itemFactory,
				      "/Advanced/Reset File Identifiers/"
				      "List of files from downloaded directories");
  gtk_widget_set_sensitive(entry, value);  


  if ( NO == haveNamesp) 
    value = FALSE;
  else
    value = TRUE;
  entry = gtk_item_factory_get_widget(itemFactory,
				      "/Advanced/Assemble Directory/"
				      "from local namespaces");
  gtk_widget_set_sensitive(entry, value);  
  entry = gtk_item_factory_get_widget(itemFactory,
				      "/Advanced/Insert into Namespace/"
				      "Select from results from local namespaces");
  gtk_widget_set_sensitive(entry, value);  
  entry = gtk_item_factory_get_widget(itemFactory,
				      "/Advanced/Reset File Identifiers/"
				      "List of entries in local namespaces");
  gtk_widget_set_sensitive(entry, value);  

  gtkSaveCallDone(call->sem);

  return FALSE;
}

void refreshMenuSensitivity() {
  gtkSaveCall((GtkFunction) doRefreshMenuSensitivity, NULL);
}

/**
 * This creates the main window
 */
static void makeMainWindow() {
  GtkWidget * window;
  GtkWidget * button;
  GtkWidget * hbox;
  GtkWidget * vbox;
  GtkWidget * menubar;
  GtkWidget * table;
  GtkWidget * label;
  GtkWidget * entry;
  GtkAccelGroup * accel_group;

  gint nmenu_items = sizeof(menu_items) / sizeof(menu_items[0]);

  /* create main window */
  window = gtk_window_new(GTK_WINDOW_TOPLEVEL); 
  gtk_window_set_title(GTK_WINDOW(window), 
		       "GNUnet: gtk+ GUI");
  gtk_widget_set_usize(GTK_WIDGET(window), 
		       780, /* x-size */
		       300); /* y-size */
  vbox = gtk_vbox_new(FALSE, 1);
  gtk_container_add(GTK_CONTAINER(window), vbox);
  gtk_signal_connect(GTK_OBJECT(window), 
		      "delete_event",
		      GTK_SIGNAL_FUNC(deleteEvent), 
		     NULL);
  gtk_signal_connect(GTK_OBJECT(window), 
		      "destroy",
		      GTK_SIGNAL_FUNC(destroyMain),
		     NULL);
  gtk_widget_show(vbox);

  
  /* create pulldown menues */  
  accel_group = gtk_accel_group_new ();
  itemFactory = gtk_item_factory_new(GTK_TYPE_MENU_BAR, 
 	 		             "<main>",
				     accel_group);
  gtk_item_factory_create_items(itemFactory, 
				nmenu_items,
				menu_items, 
				NULL);
  gtk_window_add_accel_group(GTK_WINDOW (window), 
			     accel_group);
  menubar = gtk_item_factory_get_widget(itemFactory, 
					"<main>");
  gtk_box_pack_start(GTK_BOX (vbox), 
		     menubar,
		     FALSE, 
		     TRUE, 
		     0);
  


  /* set some default options and show */

  
  entry = gtk_item_factory_get_widget(itemFactory,
  				      "/File/Show downloads");
  gtk_widget_set_sensitive(entry, FALSE);
  refreshMenuSensitivity();

  gtk_widget_show(menubar);

  /* a table to put the search results notebook to */
  table = gtk_table_new(6, 6, TRUE);
  gtk_box_pack_start(GTK_BOX (vbox),
		     table,
		     TRUE,
		     TRUE, 0);
  gtk_widget_show(table);
  
  /* add "notebook" for search results */
  notebook = GTK_NOTEBOOK(gtk_notebook_new());
  gtk_notebook_set_scrollable(notebook,
			      TRUE);
  gtk_notebook_set_tab_pos(GTK_NOTEBOOK(notebook),
			   GTK_POS_TOP);
  gtk_table_attach_defaults(GTK_TABLE(table), 
			    GTK_WIDGET(notebook),
			    0, 6, 0, 6);
  gtk_widget_show(GTK_WIDGET(notebook));

  /* BEGIN of SEARCH BOX CODE */
  /* At the bottom, put the search box */
  hbox = gtk_hbox_new(FALSE, 1);
  gtk_box_pack_start(GTK_BOX (vbox),
		     hbox, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(hbox);
 
  /* search entry label */
  label = gtk_label_new(_("Keyword(s):"));
  gtk_box_pack_start(GTK_BOX(hbox),
		     label,
		     FALSE, 
		     FALSE,
		     0);
  gtk_widget_show(label);

  /* search input line */
  main_window_input_line = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(hbox), 
		     main_window_input_line, 
		     TRUE, 
		     TRUE, 
		     0);
  gtk_signal_connect(GTK_OBJECT(main_window_input_line),
		     "activate",
                     GTK_SIGNAL_FUNC(search),
                     notebook);
  gtk_widget_show(main_window_input_line);

  /* search button */
  button = gtk_button_new_with_label("Search");
  gtk_signal_connect(GTK_OBJECT (button), 
		     "clicked",
		     GTK_SIGNAL_FUNC(search), notebook);
  gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
  gtk_widget_show(button);
  /* END of SEARCH BOX CODE */

  /* show the main window */
  gtk_widget_show(window);
}

/**
 * Perform option parsing from the command line. 
 */
static int parseOptions(int argc, 
			char ** argv) {
  int c;

  while (1) {
    int option_index=0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { 0,0,0,0 }
    };
    
    c = GNgetopt_long(argc,
		      argv, 
		      "vhdc:L:H:", 
		      long_options, 
		      &option_index);
    
    if (c == -1) 
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg)) {
      if (c == 'd')
        debug_flag = YES;
      continue;    
    }
    switch(c) {
    case 'v': 
      printf("GNUnet v%s, AFS v%s\n",
	     VERSION,
	     AFS_VERSION);
      return SYSERR;
    case 'h': {
      static Help help[] = {
	HELP_CONFIG,
	HELP_HELP,
	HELP_HOSTNAME,
	HELP_LOGLEVEL,
	HELP_VERSION,
	HELP_END,
      };
      formatHelp("gnunet-gtk [OPTIONS]",
		 _("Run the GNUnet GTK user interface."),
		 help);
      return SYSERR;
    }
    default:
      LOG(LOG_FAILURE,
	  _("Use --help to get a list of options.\n"));
      return SYSERR;    
    } /* end of parsing commandline */
  }
  if (GNoptind < argc) {
    fprintf(stderr,
	    _("Invalid arguments: "));
    while (GNoptind < argc)
      fprintf(stderr,
	      "%s ", 
	      argv[GNoptind++]);
    fprintf(stderr, 
	    "\n");
    return SYSERR;
  }
  return OK;
}

/**
 * The main function.
 */
int main(int argc,
         char * argv[]) {

  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return(0);
  initGTKStatistics();
   
  startCron();
  refuseToDie = SEMAPHORE_NEW(1);

  g_thread_init(NULL);
  /*  gdk_threads_init(); */
  gtk_init(&argc, &argv);
  gtkInitSaveCalls();

  makeMainWindow();
  resumeDownloads(downloadAFSuri);
  
  /* Check if gnunetd is running */
  checkForDaemon();
 
  /* refresh the kill/launch sensitivities once per 30 secs */
  addCronJob((CronJob)&cronCheckDaemon,
  	     0,
	     30 * cronSECONDS,
	     NULL);
  startAFSPriorityTracker();
  gdk_threads_enter();  
  setCustomLogProc(addLogEntry);
#ifdef MINGW
  if (! debug_flag)
    FreeConsole();
#endif
  gtk_main();
  setCustomLogProc(NULL);
  gdk_threads_leave(); 
  gtkDoneSaveCalls();
  stopCron();
  stopAFSPriorityTracker();
  LOG(LOG_DEBUG, "GUI leaving...\n");
  SEMAPHORE_FREE(refuseToDie);

  doneGTKStatistics();
  doneUtil();  
  return 0;
}

/* end of main.c */
