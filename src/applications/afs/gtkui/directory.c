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
 * @file src/applications/afs/gtkui/directory.c
 * @brief Directory dialog for the AFS interface
 * @author Christian Grothoff
 * @author Igor Wronsky
 */
#include "gnunet_afs_esed2.h"
#include "helper.h"
#include "insertprogress.h"
#include "directory.h"
#include "directorydisplay.h"


/**
 * @brief state of the create Directory window
 */
typedef struct {
  char * fileName;
  GtkWidget * editAttributesWindow;
  GtkWidget * fileNameLine;
  GtkWidget * descriptionLine;
  GtkWidget * keywordLine;
  GtkWidget * keywordList;
  GtkWidget * availableList;
  GtkWidget * selectedList;
  RootNode ** availableEntries;
  RootNode ** selectedEntries;
  int availableCount;
  int selectedCount;
} AssembleWindowModel;

/**
 * Collects the results of the assembly dialog, creates an insertion 
 * progressbar and launches the insertion thread.
 *
 * @param dummy not used
 * @param ewm the state of the edit window
 */
static void startAssemble(GtkWidget * dummy, 
			  AssembleWindowModel * ewm) {
  int i;
  RootNode * coll;
  GNUnetDirectory * dir;
  const char * name;
  InsertModel * ilm;
  char * fileName;
  const gchar * txt;
  PTHREAD_T insertThread;
  
  if (ewm->selectedCount == 0) {
    guiMessage(_("Cowardly refusing to build empty directory.\n"));
    LOG(LOG_WARNING,
	_("Cowardly refusing to build empty directory.\n"));
    return;
  }
  ilm = MALLOC(sizeof(InsertModel));

  name = gtk_entry_get_text(GTK_ENTRY(ewm->descriptionLine));
  if (name == NULL)
    name = "No description specified.";

  coll = MALLOC(ewm->selectedCount * sizeof(RootNode));
  for (i=0;i<ewm->selectedCount;i++)
    memcpy(&coll[i],
	   ewm->selectedEntries[i],
	   sizeof(RootNode));
  dir = buildDirectory(ewm->selectedCount,
		       name,
		       coll);
  FREE(coll);

  /* get the published filename */
  txt = gtk_entry_get_text(GTK_ENTRY(ewm->fileNameLine));
  if (txt == NULL)
    ilm->fileNameRoot = STRDUP("directory");
  else
    ilm->fileNameRoot = STRDUP(txt);
 
  fileName = MALLOC(strlen("/tmp/gnunetdir_") + strlen(ilm->fileNameRoot) + strlen(".XXXXXX") + 1);
  strcpy(fileName, "/tmp/gnunetdir_");
  strcat(fileName, ilm->fileNameRoot);
  strcat(fileName, ".XXXXXX");
  mkstemp(fileName);
  
  if (SYSERR == writeGNUnetDirectory(dir, fileName)) {
    LOG(LOG_WARNING,
	_("Could not write directory to temporary file.\n"));
    FREE(fileName);
    FREE(dir);
    FREE(ilm);
    return;
  }
  ilm->fileName = fileName;
  ilm->indexContent = NO;
  ilm->deleteAfterInsert = YES;
  /* get the new description, if any */
  txt = gtk_entry_get_text(GTK_ENTRY(ewm->descriptionLine));
  if (txt == NULL)
    ilm->description = STRDUP("no description specified");
  else
    ilm->description = STRDUP(txt);
  ilm->mimetype = STRDUP(GNUNET_DIRECTORY_MIME);

  /* get list of keywords */
  ilm->num_keywords = GTK_CLIST(ewm->keywordList)->rows;
  if (ilm->num_keywords > 0) {
    ilm->keywords = (char**) MALLOC(ilm->num_keywords * sizeof(char*));
    for(i=0;i<ilm->num_keywords;i++) {     
      gchar * tmp;
      gtk_clist_get_text(GTK_CLIST(ewm->keywordList),
			 i,
			 0,
			 &tmp);
      ilm->keywords[i] = STRDUP(tmp);
    } 
  } else
    ilm->keywords = NULL;
 
  strcpy(ilm->opDescription, _("processed"));
  createInsertProgressBar(ilm);
  /* start the insert thread */
  if (0 != PTHREAD_CREATE(&insertThread,
			  (PThreadMain) insertFileGtkThread,
			  ilm,
			  16 * 1024))
    DIE_STRERROR("pthread_create");
  PTHREAD_DETACH(&insertThread);

  /* destroy the "assemble directory" window */
  gtk_widget_destroy(ewm->editAttributesWindow);
}

/**
 * Exit the application (called when the main window
 * is closed or the user selects File-Quit).
 */
static void destroyAssembleWindow(GtkWidget * widget,
				  AssembleWindowModel * ewm) {
  int i;

  for (i=0;i<ewm->availableCount;i++)
    FREE(ewm->availableEntries[i]);
  for (i=0;i<ewm->selectedCount;i++)
    FREE(ewm->selectedEntries[i]);
  GROW(ewm->availableEntries,
       ewm->availableCount,
       0);
  GROW(ewm->selectedEntries,
       ewm->selectedCount,
       0);
  FREE(ewm);
}

/**
 * The keyword add button was clicked. Add whatever 
 * is in the keyword box to the list of keywords.
 *
 * @param w not used
 * @param ewm the state of the edit window
 */
static void button_add_clicked(GtkWidget * w, 
			       AssembleWindowModel * ewm) {
  const gchar * keyConst;
  gchar * key;
  gchar * newKeyword;
  int i;

  keyConst = gtk_entry_get_text(GTK_ENTRY(ewm->keywordLine));
  if (keyConst == NULL) {
    /* message to enter a string? */
    return;
  }    

  newKeyword = STRDUP(keyConst);
  key = newKeyword;

  /* remove trailing & heading spaces */
  i = strlen(key)-1;
  while ( (newKeyword[i] == ' ') && 
	  (i >= 0) ) {
    newKeyword[i--] = '\0';
  }
  while (*newKeyword == ' ')
    newKeyword++;

  if ( *newKeyword == '\0' ) {
    /* message to enter more than spaces? */    
  } else {
    gtk_clist_append(GTK_CLIST(ewm->keywordList),
		     &newKeyword);
  } 
  FREE(key);
  gtk_entry_set_text(GTK_ENTRY(ewm->keywordLine),
		     "");
}


/**
 * The keyword delete button was clicked. Delete the 
 * currently selected keyword.
 *
 * @param w not used
 * @param ewm state of the edit window
 */
static void button_del_clicked(GtkWidget * w, 
			       AssembleWindowModel * ewm) {
  GList * tmp;

  tmp = GTK_CLIST(ewm->keywordList)->selection;
  if (NULL == tmp) {
    /* message that keyword must be selected to delete one? */
    return;
  }  
  gtk_clist_remove(GTK_CLIST(ewm->keywordList),
		   (int)tmp->data);
}

/**
 * The keyword add button was clicked. Add whatever 
 * is in the keyword box to the list of keywords.
 *
 * @param w not used
 * @param ewm the state of the edit window
 */
static void button_select_clicked(GtkWidget * w, 
				  AssembleWindowModel * ewm) {
  gchar * key[1];
  GList * tmp;
  int row;
  int i;

  tmp = GTK_CLIST(ewm->availableList)->selection;
  if (NULL == tmp) 
    return;  
  row = (int) tmp->data;
  if ( (row < 0) ||
       (row >= ewm->availableCount) )
    return; /* should never happen... */
  key[0] = NULL;
  gtk_clist_get_text(GTK_CLIST(ewm->availableList),
		     row,
		     0,
		     &key[0]);
  gtk_clist_append(GTK_CLIST(ewm->selectedList),
		   &key[0]); 
  gtk_clist_remove(GTK_CLIST(ewm->availableList),
		   row);
  if (row > 0)
    gtk_clist_select_row(GTK_CLIST(ewm->availableList),
			 row-1,
			 0);
  else
    gtk_clist_select_row(GTK_CLIST(ewm->availableList),
			 0,
			 0);
  GROW(ewm->selectedEntries,
       ewm->selectedCount,
       ewm->selectedCount+1);
  ewm->selectedEntries[ewm->selectedCount-1] 
    = ewm->availableEntries[row];
  for (i=row;i<ewm->availableCount-1;i++)
    ewm->availableEntries[i] 
    = ewm->availableEntries[i+1];
  GROW(ewm->availableEntries,
       ewm->availableCount,
       ewm->availableCount-1);
}

/**
 * The keyword add button was clicked. Add whatever 
 * is in the keyword box to the list of keywords.
 *
 * @param w not used
 * @param ewm the state of the edit window
 */
static void button_deselect_clicked(GtkWidget * w, 
				    AssembleWindowModel * ewm) {
  gchar * key[1];
  GList * tmp;
  int row;
  int i;

  tmp = GTK_CLIST(ewm->selectedList)->selection;
  if (NULL == tmp) 
    return;  
  row = (int) tmp->data;
  if ( (row < 0) ||
       (row >= ewm->selectedCount) )
    return; /* should never happen... */
  key[0] = NULL;
  gtk_clist_get_text(GTK_CLIST(ewm->selectedList),
		     row,
		     0,
		     &key[0]);
  gtk_clist_append(GTK_CLIST(ewm->availableList),
		   &key[0]); 
  gtk_clist_remove(GTK_CLIST(ewm->selectedList),
		   row);
  if (row > 0)
    gtk_clist_select_row(GTK_CLIST(ewm->selectedList),
			 row-1,
			 0);
  else
    gtk_clist_select_row(GTK_CLIST(ewm->selectedList),
			 0,
			 0);
  GROW(ewm->availableEntries,
       ewm->availableCount,
       ewm->availableCount+1);
  ewm->availableEntries[ewm->availableCount-1] 
    = ewm->selectedEntries[row];
  for (i=row;i<ewm->selectedCount-1;i++)
    ewm->selectedEntries[i] 
    = ewm->selectedEntries[i+1];
  GROW(ewm->selectedEntries,
       ewm->selectedCount,
       ewm->selectedCount-1);
}


static void appendToCList(RootNode * root,
			  AssembleWindowModel * ewm) {
  gchar * entry[1];

  entry[0] = STRDUP(root->header.description);
  gtk_clist_append(GTK_CLIST(ewm->availableList), 
		   entry);
  FREE(entry[0]);
  GROW(ewm->availableEntries,
       ewm->availableCount,
       ewm->availableCount+1);
  ewm->availableEntries[ewm->availableCount-1]
    = MALLOC(sizeof(RootNode));
  memcpy(ewm->availableEntries[ewm->availableCount-1],
	 root,
	 sizeof(RootNode));
}


/**
 * Open a window to allow the user to build a directory.
 *
 * @param unused GTK handle that is not used
 * @param context selector for a subset of the known RootNodes
 */
void openAssembleDirectoryDialog(GtkWidget * unused,
				 unsigned int context) {
  AssembleWindowModel * ewm;
  GtkWidget * window;
  GtkWidget * vbox, * hbox;
  GtkWidget * clist;
  GtkWidget * scrolled_window;
  GtkWidget * label;
  GtkWidget * separator; 
  GtkWidget * button_add;
  GtkWidget * button_delete;
  GtkWidget * button_ok;
  GtkWidget * button_cancel;
  GtkWidget * keyword_line;
  gchar * titles[1] = { gettext_noop("Keyword(s) used") };
  gchar * titlesAvailable[1] = { gettext_noop("Files available") };
  gchar * titlesSelected[1] = { gettext_noop("Files selected") };
  gchar * directoryMimetype[1] = { GNUNET_DIRECTORY_MIME };

  ewm = MALLOC(sizeof(AssembleWindowModel));
  /* create new window for editing */
  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  ewm->editAttributesWindow = window;
  gtk_widget_set_usize(GTK_WIDGET(window),
		       620,
		       480);
  gtk_window_set_title(GTK_WINDOW(window), 
		       _("Assemble directory"));

  /* add container for window elements */
  vbox = gtk_vbox_new(FALSE, 0);
  gtk_container_add(GTK_CONTAINER(window),
		    vbox);
  gtk_widget_show(vbox);

  /* when user clicks on close box, always "destroy" */
  gtk_signal_connect(GTK_OBJECT(window),
		     "delete_event",
		     GTK_SIGNAL_FUNC(deleteEvent),
		     ewm);
  /* whenever edit window gets destroyed, 
     free *ALL* ewm data */
  gtk_signal_connect(GTK_OBJECT(window),
		     "destroy",
		     GTK_SIGNAL_FUNC(destroyAssembleWindow),
		     ewm);

  gtk_container_set_border_width(GTK_CONTAINER(window), 
				 10);

  /* Create a line to change the published filename */
  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     FALSE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  label = gtk_label_new(_("Published directory name:"));
  gtk_box_pack_start(GTK_BOX(hbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label); 
  ewm->fileNameLine = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->fileNameLine,
		     TRUE,
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(ewm->fileNameLine), 
		     "");
  gtk_widget_show(ewm->fileNameLine);
  
  /* Create a line to change the description */
  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     FALSE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  label = gtk_label_new(_("Description:"));
  gtk_box_pack_start(GTK_BOX(hbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label);  
  ewm->descriptionLine = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->descriptionLine, 
		     TRUE, 
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(ewm->descriptionLine), 
		     _("A GNUnet directory"));
  gtk_widget_show(ewm->descriptionLine);
  
  separator = gtk_hseparator_new();
  gtk_box_pack_start(GTK_BOX(vbox),
		     separator,
		     TRUE, 
		     TRUE,
		     0);
  gtk_widget_show(separator);

  /* add a list of keywords */
  scrolled_window = gtk_scrolled_window_new (NULL, NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
				 GTK_POLICY_AUTOMATIC, 
				 GTK_POLICY_ALWAYS);
  gtk_box_pack_start(GTK_BOX(vbox), 
		     scrolled_window, 
		     TRUE, 
		     TRUE, 
		     0);
  gtk_widget_show(scrolled_window);  
  clist = gtk_clist_new_with_titles(1, titles); 
  /* add mimetype as a keyword */
  gtk_clist_append(GTK_CLIST(clist), directoryMimetype);
  ewm->keywordList = clist;
  gtk_container_add(GTK_CONTAINER(scrolled_window), 
		    clist);
  gtk_widget_show(clist);

  /* add a line to input new keywords */
  keyword_line = gtk_entry_new();
  ewm->keywordLine = keyword_line;
  gtk_box_pack_start(GTK_BOX(vbox),
		     keyword_line, 
		     FALSE,
		     FALSE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(keyword_line), 
		     "");
  gtk_signal_connect(GTK_OBJECT(keyword_line),
		     "activate",
                     GTK_SIGNAL_FUNC(button_add_clicked),
                     ewm);
  gtk_widget_show(keyword_line);

  /* add the buttons to add and delete keywords */
  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     FALSE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  button_add = gtk_button_new_with_label(_("Add keyword"));
  button_delete = gtk_button_new_with_label(_("Delete keyword"));
  gtk_box_pack_start(GTK_BOX(hbox), 
		     button_add, 
		     TRUE, 
		     TRUE, 
		     0);
  gtk_box_pack_start(GTK_BOX(hbox), 
		     button_delete, 
		     TRUE, 
		     TRUE, 
		     0);
  gtk_signal_connect(GTK_OBJECT(button_add),
		     "clicked",
		     GTK_SIGNAL_FUNC(button_add_clicked),
		     ewm);
  gtk_signal_connect(GTK_OBJECT(button_delete), 
		     "clicked",
		     GTK_SIGNAL_FUNC(button_del_clicked),
		     ewm);
  gtk_widget_show(button_add);
  gtk_widget_show(button_delete);

  separator = gtk_hseparator_new();
  gtk_box_pack_start(GTK_BOX(vbox),
		     separator,
		     TRUE, 
		     TRUE,
		     0);
  gtk_widget_show(separator);

  /* add the box for the two lists */
  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     TRUE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);

  /* add a list of available entries */
  scrolled_window = gtk_scrolled_window_new (NULL, NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
				 GTK_POLICY_AUTOMATIC, 
				 GTK_POLICY_ALWAYS);
  gtk_box_pack_start(GTK_BOX(hbox), 
		     scrolled_window, 
		     TRUE, 
		     TRUE, 
		     0);
  gtk_widget_show(scrolled_window);  
  clist = gtk_clist_new_with_titles(1, titlesAvailable); 
  ewm->availableList = clist;
  gtk_container_add(GTK_CONTAINER(scrolled_window), 
		    clist);
  /* add the known RootNodes to the list */
  gtk_clist_freeze(GTK_CLIST(clist));
  iterateDirectoryDatabase(context,
			   (RootNodeCallback)&appendToCList,
			   ewm);
  gtk_clist_thaw(GTK_CLIST(clist));
  gtk_widget_show(clist);


  /* add a list of selected entries */
  scrolled_window = gtk_scrolled_window_new (NULL, NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
				 GTK_POLICY_AUTOMATIC, 
				 GTK_POLICY_ALWAYS);
  gtk_box_pack_start(GTK_BOX(hbox), 
		     scrolled_window, 
		     TRUE, 
		     TRUE, 
		     0);
  gtk_widget_show(scrolled_window);  
  clist = gtk_clist_new_with_titles(1, titlesSelected); 
  ewm->selectedList = clist;
  gtk_container_add(GTK_CONTAINER(scrolled_window), 
		    clist);
  gtk_widget_show(clist);


  /* add the box for the buttons to move between the
     two lists */
  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     FALSE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);

  button_add = gtk_button_new_with_label("=>");
  button_delete = gtk_button_new_with_label("<=");
  gtk_box_pack_start(GTK_BOX(hbox), 
		     button_add, 
		     TRUE, 
		     TRUE, 
		     0);
  gtk_box_pack_start(GTK_BOX(hbox), 
		     button_delete, 
		     TRUE, 
		     TRUE, 
		     0);
  gtk_signal_connect(GTK_OBJECT(button_add),
		     "clicked",
		     GTK_SIGNAL_FUNC(button_select_clicked),
		     ewm);
  gtk_signal_connect(GTK_OBJECT(button_delete), 
		     "clicked",
		     GTK_SIGNAL_FUNC(button_deselect_clicked),
		     ewm);
  gtk_widget_show(button_add);
  gtk_widget_show(button_delete);



  /* add the insertion ok/cancel buttons */
  separator = gtk_hseparator_new();
  gtk_box_pack_start(GTK_BOX(vbox),
		     separator,
		     TRUE, 
		     TRUE,
		     0);
  gtk_widget_show(separator);

  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox, 
		     FALSE, 
		     TRUE, 
		     0);
  gtk_widget_show(hbox);
  button_ok = gtk_button_new_with_label(_("Ok"));
  button_cancel = gtk_button_new_with_label(_("Cancel"));
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
  gtk_signal_connect(GTK_OBJECT(button_ok), 
		     "clicked",
		     GTK_SIGNAL_FUNC(startAssemble),
		     ewm);
  gtk_signal_connect(GTK_OBJECT(button_cancel),
		     "clicked",
		     GTK_SIGNAL_FUNC(destroyWidget),
		     window);
  gtk_widget_show(button_ok);
  gtk_widget_show(button_cancel);

  /* all clear, show the window */
  gtk_widget_show(window);
}

/**
 * Callback for displaying user-selected directory
 */ 
static gint importDirectoryCallback(GtkWidget * okButton,
				    GtkWidget * window) 
{
  const gchar * filename;

  filename 
    = gtk_file_selection_get_filename(GTK_FILE_SELECTION(window));
  if ( (filename == NULL) ||
       (0 == assertIsFile(filename)) ) {
    guiMessage(_("Please select a file!\n"));
    gtk_widget_destroy(window);
    return FALSE;
  }
 
  displayDirectory(filename,
		   NULL);

  gtk_widget_destroy(window); 

  return FALSE;
}

/**
 * Asks user to select a .gnd directory (from disk) to be displayed
 */
void importDirectory(void) 
{
  GtkWidget * window;
  char pattern[16];
  
  window = gtk_file_selection_new(_("Choose directory to be imported"));

  SNPRINTF(pattern, 16,
	   "*%s", GNUNET_DIRECTORY_EXT);
  gtk_file_selection_complete(GTK_FILE_SELECTION(window),
  			      pattern);
  
  gtk_signal_connect(GTK_OBJECT(window),
                     "destroy",
                     GTK_SIGNAL_FUNC(destroyWidget),
                     window);
  gtk_signal_connect(GTK_OBJECT(GTK_FILE_SELECTION(window)->ok_button),
                     "clicked",
                     GTK_SIGNAL_FUNC(importDirectoryCallback),
                     window);
  gtk_signal_connect(GTK_OBJECT(GTK_FILE_SELECTION(window)->cancel_button),
                     "clicked",
                     GTK_SIGNAL_FUNC(destroyWidget),
                     window);
  gtk_widget_show(window);

}


/* end of directory.c */
