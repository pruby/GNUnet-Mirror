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
 * @file src/applications/afs/gtkui/insert.c
 * @brief handles file insertions in the GTK GUI
 * @author Igor Wronsky
 * @author Christian Grothoff (refactoring, added bugs)
 */

#include "gnunet_afs_esed2.h"
#include "helper.h"
#include "insertprogress.h"
#include "insert.h"
#include "main.h"

/**
 * @brief state of the edit RootNode window
 */
typedef struct {
  char * fileName;
  GtkWidget * editAttributesWindow;
  GtkWidget * fileNameLine;
  GtkWidget * descriptionLine;
  GtkWidget * mimeLine;
  GtkWidget * indexButton;
  GtkWidget * checkCopy;
  GtkWidget * keywordLine;
  GtkWidget * keywordList;
} EditWindowModel;

/**
 * @brief state of the edit RootNode window
 */
typedef struct {
  char * fileName;
  GtkWidget * editAttributesWindow;
  GtkWidget * fileNameLine;
  GtkWidget * descriptionLine;
  GtkWidget * indexButton;
  GtkWidget * checkCopy;
  GtkWidget * keywordLine;
  GtkWidget * keywordList;
  GtkWidget * gkeywordLine;
  GtkWidget * gkeywordList;
} EditDirectoryWindowModel;


/**
 * Collects the results of editAttributes, creates an insertion 
 * progressbar and launches the insertion thread.
 *
 * @param dummy not used
 * @param ewm the state of the edit window
 */
static void startInsert(GtkWidget * dummy, 
			EditWindowModel * ewm) {
  InsertModel * ilm;
  const gchar * txt;
  int i;
  PTHREAD_T insertThread;

  ilm = MALLOC(sizeof(InsertModel));
  ilm->fileName = STRDUP(ewm->fileName);

  /* get content indexing style */
  if (gtk_toggle_button_get_active((GtkToggleButton *)ewm->indexButton) == TRUE)
    ilm->indexContent = YES;
  else
    ilm->indexContent = NO;
  ilm->copyFile = gtk_toggle_button_get_active((GtkToggleButton *)ewm->checkCopy);

  /* get the published filename */
  txt = gtk_entry_get_text(GTK_ENTRY(ewm->fileNameLine));
  if (txt == NULL)
    ilm->fileNameRoot = STRDUP(_("Filename not specified."));
  else
    ilm->fileNameRoot = STRDUP(txt);
  
  /* get the new description, if any */
  txt = gtk_entry_get_text(GTK_ENTRY(ewm->descriptionLine));
  if (txt == NULL)
    ilm->description = STRDUP(_("Description not given."));
  else
    ilm->description = STRDUP(txt);

  txt = gtk_entry_get_text(GTK_ENTRY(ewm->mimeLine));
  if (txt == NULL)
    ilm->mimetype = STRDUP(_("Mime-type unknown."));
  else
    ilm->mimetype = STRDUP(txt);

  /* get new list of keywords */
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

  if(ilm->indexContent == YES)
    strcpy(ilm->opDescription, _("indexed"));
  else
    strcpy(ilm->opDescription, _("inserted"));
  createInsertProgressBar(ilm);
  /* start the insert thread */
  if (0 != PTHREAD_CREATE(&insertThread,
			  (PThreadMain) insertFileGtkThread,
			  ilm,
			  16 * 1024))
    DIE_STRERROR("pthread_create");
  PTHREAD_DETACH(&insertThread);

  /* destroy the "editAttributes" window */
  gtk_widget_destroy(ewm->editAttributesWindow);
}

/**
 * Collects the results of editAttributes, creates an insertion 
 * progressbar and launches the insertion thread.
 *
 * @param dummy not used
 * @param ewm the state of the edit window
 */
static void startInsertDirectory(GtkWidget * dummy, 
				 EditDirectoryWindowModel * ewm) {
  InsertDirectoryModel * ilm;
  const gchar * txt;
  int i;
  PTHREAD_T insertThread;

  ilm = MALLOC(sizeof(InsertDirectoryModel));
  ilm->fileName = STRDUP(ewm->fileName);

  /* get content indexing style */
  if (gtk_toggle_button_get_active((GtkToggleButton *)ewm->indexButton) == TRUE)
    ilm->indexContent = YES;
  else
    ilm->indexContent = NO;
  ilm->copyFile = gtk_toggle_button_get_active((GtkToggleButton *)ewm->checkCopy);
  /* get the published filename */
  txt = gtk_entry_get_text(GTK_ENTRY(ewm->fileNameLine));
  if (txt == NULL)
    ilm->fileNameRoot = STRDUP(_("Filename not specified."));
  else
    ilm->fileNameRoot = STRDUP(txt);
  
  /* get the new description, if any */
  txt = gtk_entry_get_text(GTK_ENTRY(ewm->descriptionLine));
  if (txt == NULL)
    ilm->description = STRDUP(_("No description specified."));
  else
    ilm->description = STRDUP(txt);

  ilm->mimetype = STRDUP(GNUNET_DIRECTORY_MIME);

  /* get new list of keywords */
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

  /* get new list of keywords */
  ilm->num_gkeywords = GTK_CLIST(ewm->gkeywordList)->rows;

  if (ilm->num_gkeywords > 0) {
    ilm->gkeywords = (char**) MALLOC(ilm->num_gkeywords * sizeof(char*));
    for(i=0;i<ilm->num_gkeywords;i++) {     
      gchar * tmp;
      gtk_clist_get_text(GTK_CLIST(ewm->gkeywordList),
			 i,
			 0,
			 &tmp);
      ilm->gkeywords[i] = STRDUP(tmp);
    } 
  } else
    ilm->gkeywords = NULL;

  if(ilm->indexContent == YES)
    strcpy(ilm->opDescription, _("indexed"));
  else
    strcpy(ilm->opDescription, _("inserted"));
  /*
    FIXME: allow setting this as an option in the dialog!
  FREENONNULL(setConfigurationString("GNUNET-INSERT",
				     "EXTRACT-KEYWORDS",
				     "NO"));
  */
  createInsertDirectoryProgressBar(ilm);
  /* start the insert thread */
  if (0 != PTHREAD_CREATE(&insertThread,
			  (PThreadMain) insertDirectoryGtkThread,
			  ilm,
			  16 * 1024))
    DIE_STRERROR("pthread_create");
  PTHREAD_DETACH(&insertThread);
  /* destroy the "editAttributes" window */
  gtk_widget_destroy(ewm->editAttributesWindow);
}

/**
 * The keyword add button was clicked. Add whatever 
 * is in the keyword box to the list of keywords.
 *
 * @param w not used
 * @param ewm the state of the edit window
 */
static void button_add_clicked(GtkWidget * w, 
			       EditWindowModel * ewm) {
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
			       EditWindowModel * ewm) {
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
static void button_dir_add_clicked1(GtkWidget * w, 
				    EditDirectoryWindowModel * ewm) {
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
static void button_dir_del_clicked1(GtkWidget * w, 
				    EditDirectoryWindowModel * ewm) {
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
static void button_dir_add_clicked2(GtkWidget * w, 
				    EditDirectoryWindowModel * ewm) {
  const gchar * keyConst;
  gchar * key;
  gchar * newKeyword;
  int i;

  keyConst = gtk_entry_get_text(GTK_ENTRY(ewm->gkeywordLine));
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
    gtk_clist_append(GTK_CLIST(ewm->gkeywordList),
		     &newKeyword);
  } 
  FREE(key);
  gtk_entry_set_text(GTK_ENTRY(ewm->gkeywordLine),
		     "");
}

/**
 * The keyword delete button was clicked. Delete the 
 * currently selected keyword.
 *
 * @param w not used
 * @param ewm state of the edit window
 */
static void button_dir_del_clicked2(GtkWidget * w, 
				    EditDirectoryWindowModel * ewm) {
  GList * tmp;

  tmp = GTK_CLIST(ewm->gkeywordList)->selection;
  if (NULL == tmp) {
    /* message that keyword must be selected to delete one? */
    return;
  }  
  gtk_clist_remove(GTK_CLIST(ewm->gkeywordList),
		   (int)tmp->data);
}

/**
 * The index/insert file button was clicked.
 *
 * @param w the button
 * @param ewm state of the edit window
 */
static void button_index_clicked(GtkWidget * w,
                                 EditWindowModel * ewm) {
  gtk_widget_set_sensitive(ewm->checkCopy, w == ewm->indexButton);
}

/**
 * Exit the application (called when the main window
 * is closed or the user selects File-Quit).
 */
static void destroyEditWindow(GtkWidget * widget,
			      EditWindowModel * ewm) {
  FREE(ewm->fileName);
  FREE(ewm);
}

/**
 * Exit the application (called when the main window
 * is closed or the user selects File-Quit).
 */
static void destroyEditDirectoryWindow(GtkWidget * widget,
				       EditDirectoryWindowModel * ewm) {
  FREE(ewm->fileName);
  FREE(ewm);
}

/**
 * Show user a window to edit information related to this file.
 * After user is done, call startInsert.
 *
 * @param filename the name of the file that is inserted
 * @param fileNameRoot the short name of the file
 * @param description the description of the file
 * @param mimetype the mimetype of the ile
 * @param keywords the extracted keywords of the file
 * @param num_keywords the number of keywords extracted
 */
static void editAttributes(char * filename,
			   char * fileNameRoot,
			   char * description,
			   char * mimetype,
			   char ** keywords,
			   int num_keywords) {
  EditWindowModel * ewm;
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
  GSList * group;
  GtkWidget * indexbutton1;
  GtkWidget * indexbutton2;
  GtkWidget * check_copy;
  int doIndex;
  gchar * titles[1] = { gettext_noop("Keyword(s) used") };
  int i;

  ewm = MALLOC(sizeof(EditWindowModel));
  ewm->fileName = STRDUP(filename);
  /* create new window for editing */
  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  ewm->editAttributesWindow = window;
  gtk_widget_set_usize(GTK_WIDGET(window),
		       400,
		       480);
  gtk_window_set_title(GTK_WINDOW(window), 
		       _("Edit attributes"));

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
		     GTK_SIGNAL_FUNC(destroyEditWindow),
		     ewm);

  gtk_container_set_border_width(GTK_CONTAINER(window), 
				 10);

  /* Create a line to change the published filename */
  label = gtk_label_new(_("Published filename:"));
  gtk_box_pack_start(GTK_BOX(vbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label); 
  ewm->fileNameLine = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(vbox),
		     ewm->fileNameLine,
		     TRUE,
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(ewm->fileNameLine), 
		     fileNameRoot);
  gtk_widget_show(ewm->fileNameLine);
  
  /* Create a line to change the mime type */
  label = gtk_label_new(_("Mimetype:"));
  gtk_box_pack_start(GTK_BOX(vbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label);  
  ewm->mimeLine = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(vbox),
		     ewm->mimeLine, 
		     TRUE, 
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(ewm->mimeLine), 
		     mimetype);
  gtk_widget_show(ewm->mimeLine);

  /* Create a line to change the description */
  label = gtk_label_new(_("Description:"));
  gtk_box_pack_start(GTK_BOX(vbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label);  
  ewm->descriptionLine = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(vbox),
		     ewm->descriptionLine, 
		     TRUE, 
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(ewm->descriptionLine), 
		     description);
  gtk_widget_show(ewm->descriptionLine);
  
  /* add buttons to select the insertion method */
  label = gtk_label_new(_("Insertion method:"));
  gtk_box_pack_start(GTK_BOX(vbox),
		     label,
		     FALSE, 
		     FALSE,
		     0);
  gtk_widget_show(label);  
  hbox = gtk_hbox_new(FALSE,0);
  gtk_box_pack_start(GTK_BOX(vbox), 
		     hbox, 
		     TRUE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  indexbutton1 = gtk_radio_button_new_with_label(NULL,
						 _("Index only"));
  ewm->indexButton = indexbutton1;
  check_copy = gtk_check_button_new_with_label(_("Copy file to shared directory"));
  ewm->checkCopy = check_copy;

  gtk_signal_connect(GTK_OBJECT(indexbutton1),
		     "toggled",
                     GTK_SIGNAL_FUNC(button_index_clicked),
                     ewm);
  gtk_box_pack_start(GTK_BOX (hbox),
		     indexbutton1,
		     TRUE,
		     TRUE,
		     0);
  gtk_widget_show(indexbutton1);  
  group = gtk_radio_button_group(GTK_RADIO_BUTTON(indexbutton1));
  indexbutton2 = gtk_radio_button_new_with_label(group, 
						 _("Full insertion"));
  gtk_signal_connect(GTK_OBJECT(indexbutton2),
		     "toggled",
                     GTK_SIGNAL_FUNC(button_index_clicked),
                     ewm);
  gtk_box_pack_start(GTK_BOX(hbox), 
		     indexbutton2, 
		     TRUE,
		     TRUE,
		     0);
  gtk_widget_show(indexbutton2);
  if (testConfigurationString("GNUNET-INSERT",
  			      "INDEX-CONTENT",
			      "YES") == YES) {
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(indexbutton1), 
				 TRUE);
	  doIndex = 1;
	}
  else {
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(indexbutton2), 
				 TRUE);
    doIndex = 0;
	}
	
  gtk_box_pack_start(GTK_BOX(hbox),
                     check_copy,
                     TRUE,
                     TRUE,
                     0);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(check_copy), 
			       ! testConfigurationString("GNUNET-INSERT",
							 "LINK",
			                                 "YES"));
  gtk_widget_set_sensitive(check_copy, doIndex);
  gtk_widget_show(check_copy);

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
  ewm->keywordList = clist;
  gtk_container_add(GTK_CONTAINER(scrolled_window), 
		    clist);

  /* add the pre-extracted keywords to the list */
  gtk_clist_freeze(GTK_CLIST(clist));
  for(i=0;i<num_keywords;i++) {
    gtk_clist_append(GTK_CLIST(clist), 
		     &keywords[i]);
  }
  gtk_clist_thaw(GTK_CLIST(clist));
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
		     GTK_SIGNAL_FUNC(startInsert),
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
 * Launches the attribute edit routine for the selected file,
 * after keywords have been extracted.
 *
 * @param filename the selected filename
 */
static void file_selected(char *filename) {
  int i;
  char * fileNameRoot;
  char * description;
  char * mimetype;
  char ** keywords;
  int num_keywords; 


  if (getFileSize(filename) > INT_MAX) {
    guiMessage(_("Can't process files larger than 2 GB"));

    return;
  }

  /* if filename is '/home/user/foo', use 'foo' as the filenameRoot */
  fileNameRoot = NULL;
  for (i=strlen(filename)-1;i>=0;i--) {
    if (filename[i] == DIR_SEPARATOR) {
      fileNameRoot = STRDUP(&filename[i+1]);
      break;
    }
  }  
  GNUNET_ASSERT(i != -1);
  /* try to extract keywords */ 
  description = NULL;
  mimetype = NULL; 
  num_keywords = 0;
  keywords = NULL;
  extractKeywords(filename,
		  &description,
		  &mimetype,
		  &keywords,
		  &num_keywords);

  if (description == NULL)
    description = STRDUP("No description supplied");
  if (mimetype == NULL)
    mimetype = STRDUP("unknown");
  
  /* allow the user to edit the insertion related info */
  editAttributes(filename,
		 fileNameRoot,
		 description,
		 mimetype,
		 keywords,
		 num_keywords);

  for (i=0;i<num_keywords;i++)
    FREE(keywords[i]);
  FREENONNULL(keywords);
  FREE(mimetype);
  FREE(description);
  FREE(filename);
  FREE(fileNameRoot);
}



/**
 * Show user a window to edit information related to this file.
 * After user is done, call startInsert.
 *
 * @param filename the name of the file that is inserted
 * @param fileNameRoot the short name of the file
 */
static void editDirectoryAttributes(char * filename,
				    char * fileNameRoot) {
  EditDirectoryWindowModel * ewm;
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
  GSList * group;
  GtkWidget * indexbutton1;
  GtkWidget * indexbutton2;
  GtkWidget * check_copy;
  int doIndex;
  gchar * titles[1] = { gettext_noop("Keyword(s) used for directory") };
  gchar * gtitles[1] = { gettext_noop("Keyword(s) used for all files in directory") };

  ewm = MALLOC(sizeof(EditDirectoryWindowModel));
  ewm->fileName = STRDUP(filename);
  /* create new window for editing */
  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  ewm->editAttributesWindow = window;
  gtk_widget_set_usize(GTK_WIDGET(window),
		       400,
		       480);
  gtk_window_set_title(GTK_WINDOW(window), 
		       _("Edit attributes"));

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
		     GTK_SIGNAL_FUNC(destroyEditDirectoryWindow),
		     ewm);

  gtk_container_set_border_width(GTK_CONTAINER(window), 
				 10);

  /* Create a line to change the published filename */
  label = gtk_label_new(_("Published name of the directory:"));
  gtk_box_pack_start(GTK_BOX(vbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label); 
  ewm->fileNameLine = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(vbox),
		     ewm->fileNameLine,
		     TRUE,
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(ewm->fileNameLine), 
		     fileNameRoot);
  gtk_widget_show(ewm->fileNameLine);
  

  /* Create a line to change the description */
  label = gtk_label_new("Description:");
  gtk_box_pack_start(GTK_BOX(vbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label);  
  ewm->descriptionLine = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(vbox),
		     ewm->descriptionLine, 
		     TRUE, 
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(ewm->descriptionLine), 
		     "No description supplied");
  gtk_widget_show(ewm->descriptionLine);
  
  /* add buttons to select the insertion method */
  label = gtk_label_new(_("Insertion method (for files in directory):"));
  gtk_box_pack_start(GTK_BOX(vbox),
		     label,
		     FALSE, 
		     FALSE,
		     0);
  gtk_widget_show(label);  
  hbox = gtk_hbox_new(FALSE,0);
  gtk_box_pack_start(GTK_BOX(vbox), 
		     hbox, 
		     TRUE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  indexbutton1 = gtk_radio_button_new_with_label(NULL,
						 _("Index only"));
  gtk_signal_connect(GTK_OBJECT(indexbutton1),
		     "toggled",
                     GTK_SIGNAL_FUNC(button_index_clicked),
                     ewm);    
  ewm->indexButton = indexbutton1;
  gtk_box_pack_start(GTK_BOX (hbox),
		     indexbutton1,
		     TRUE,
		     TRUE,
		     0);
  gtk_widget_show(indexbutton1);  
  group = gtk_radio_button_group(GTK_RADIO_BUTTON(indexbutton1));
  indexbutton2 = gtk_radio_button_new_with_label(group, 
						 _("Full insertion"));
  check_copy = gtk_check_button_new_with_label(_("Copy file to shared directory"));
  ewm->checkCopy = check_copy;
  gtk_signal_connect(GTK_OBJECT(indexbutton2),
	                   "toggled",
                     GTK_SIGNAL_FUNC(button_index_clicked),
                     ewm);
  gtk_box_pack_start(GTK_BOX(hbox), 
		     indexbutton2, 
		     TRUE,
		     TRUE,
		     0);
  gtk_widget_show(indexbutton2);
  if (testConfigurationString("GNUNET-INSERT",
  			      "INDEX-CONTENT",
			        "YES") == YES) {
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(indexbutton1), 
				 TRUE);
		doIndex = 1;
  }
  else {
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(indexbutton2), 
				 TRUE);
		doIndex = 0;
  }


  gtk_box_pack_start(GTK_BOX(hbox),
                     check_copy,
                     TRUE,
                     TRUE,
                     0);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(check_copy), 
			       ! testConfigurationString("GNUNET-INSERT",
							 "LINK",
			                                 "YES"));
  gtk_widget_set_sensitive(check_copy, doIndex);
  gtk_widget_show(check_copy);




  /* add list of local keywords */
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
                     GTK_SIGNAL_FUNC(button_dir_add_clicked1),
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
  button_add = gtk_button_new_with_label("Add keyword");
  button_delete = gtk_button_new_with_label("Delete keyword");
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
		     GTK_SIGNAL_FUNC(button_dir_add_clicked1),
		     ewm);
  gtk_signal_connect(GTK_OBJECT(button_delete), 
		     "clicked",
		     GTK_SIGNAL_FUNC(button_dir_del_clicked1),
		     ewm);
  gtk_widget_show(button_add);
  gtk_widget_show(button_delete);



  /* add list of global keywords */
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
  clist = gtk_clist_new_with_titles(1, gtitles); 
  ewm->gkeywordList = clist;
  gtk_container_add(GTK_CONTAINER(scrolled_window), 
		    clist);
  gtk_widget_show(clist);

  /* add a line to input new keywords */
  keyword_line = gtk_entry_new();
  ewm->gkeywordLine = keyword_line;
  gtk_box_pack_start(GTK_BOX(vbox),
		     keyword_line, 
		     FALSE,
		     FALSE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(keyword_line), 
		     "");
  gtk_signal_connect(GTK_OBJECT(keyword_line),
		     "activate",
                     GTK_SIGNAL_FUNC(button_dir_add_clicked2),
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
		     GTK_SIGNAL_FUNC(button_dir_add_clicked2),
		     ewm);
  gtk_signal_connect(GTK_OBJECT(button_delete), 
		     "clicked",
		     GTK_SIGNAL_FUNC(button_dir_del_clicked2),
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
		     GTK_SIGNAL_FUNC(startInsertDirectory),
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
 * Insert a directory.
 */
static void directory_selected(char * filename) {
  int i;
  char * fileNameRoot;

  /* if filename is '/home/user/foo/', use 'foo.gnd' as the filenameRoot */
  fileNameRoot = NULL;
  if (filename[strlen(filename)-1] == DIR_SEPARATOR)
    filename[strlen(filename)-1] = '\0'; 
  for (i=strlen(filename)-1;i>=0;i--) {
    if (filename[i] == DIR_SEPARATOR) {
      fileNameRoot = MALLOC(strlen(&filename[i+1])+1+strlen(GNUNET_DIRECTORY_EXT));
      strcpy(fileNameRoot, &filename[i+1]);
      strcat(fileNameRoot, GNUNET_DIRECTORY_EXT);
      break;
    }
  }  
  if (strlen(filename) == 0) {
    fileNameRoot = STRDUP("");
  } else {
    GNUNET_ASSERT(i != -1);
  }

  /* allow the user to edit the insertion related info */
  editDirectoryAttributes(filename,
			  fileNameRoot);
  FREE(filename);
  FREE(fileNameRoot);
}

/**
 * Callback for the file selection window.
 *
 * @param okButton not used
 * @param window the file selection window
 */
static gint gtk_file_selected(GtkWidget * okButton, 
			      GtkWidget * window) {
  const gchar * filename;
  char * fn;  

  filename 
    = gtk_file_selection_get_filename(GTK_FILE_SELECTION(window));
  if (filename == NULL) {
    gtk_widget_destroy(window);
    return FALSE;
  }
  if ( (NO == isDirectory(filename)) &&
       (0 == assertIsFile(filename)) ) {
    guiMessage(_("'%s' is not a file!\n"),
	       filename);
    gtk_widget_destroy(window);
    return FALSE;
  }

  fn = STRDUP((char *) filename);

  /* destroy the open-file window */
  gtk_widget_destroy(window);
  
  if (isDirectory(fn))
    directory_selected(fn);
  else
    file_selected(fn);

  return FALSE;
}

/**
 * Close the open-file window.
 */
static gint destroyOpenFile(GtkWidget * widget,
			    GtkWidget * window) {
  LOG(LOG_DEBUG, 
      "Destroying open-file window (%p)\n", 
      window);
  return TRUE;
}

#ifdef MINGW
/* Remember the previously selected path */
static char szFilename[_MAX_PATH + 1] = "\0";
#endif

/**
 * Pops up a file selector for the user.
 *
 * Explanation: In insertion, functions will be called in the
 * following order,
 *
 * openSelectFile[OK click->]gtk_file_selected->file_selected->
 * editAttributes[OK click]->startInsert->newthread.insertFile_
 */
void openSelectFile(void) {
#ifndef MINGW
  GtkWidget * window;

  window = gtk_file_selection_new(_("Choose file to be inserted"));
  gtk_signal_connect(GTK_OBJECT(window), 
		     "destroy",
		     GTK_SIGNAL_FUNC(destroyOpenFile),
		     window);
  gtk_signal_connect(GTK_OBJECT(GTK_FILE_SELECTION(window)->ok_button),
		     "clicked", 
		     GTK_SIGNAL_FUNC(gtk_file_selected),
		     window);
  gtk_signal_connect(GTK_OBJECT(GTK_FILE_SELECTION(window)->cancel_button),
		     "clicked", 
		     GTK_SIGNAL_FUNC(destroyWidget),
		     window);
  gtk_widget_show(window);
#else
  OPENFILENAME theDlg;
  
  memset(&theDlg, 0, sizeof(OPENFILENAME));
  szFilename[0] = '\0';
  
  theDlg.lStructSize = sizeof(OPENFILENAME);
  theDlg.hwndOwner = GetActiveWindow();
  theDlg.lpstrFile = szFilename;
  theDlg.nMaxFile = _MAX_PATH;
  theDlg.Flags = OFN_FILEMUSTEXIST | OFN_SHAREAWARE;
  if (GetOpenFileName(&theDlg))
    file_selected(STRDUP(theDlg.lpstrFile));
#endif
}

#ifdef MINGW
/**
 * Pops up a directory selector for the user.
 */
void openSelectDir() {
  BROWSEINFO theDlg;
  LPITEMIDLIST pidl;
  
  memset(&theDlg, 0, sizeof(BROWSEINFO));
  
  theDlg.ulFlags = BIF_NEWDIALOGSTYLE | BIF_BROWSEINCLUDEFILES;
  
  CoInitialize(NULL);
  if ((pidl = SHBrowseForFolder(&theDlg))) {
    SHGetPathFromIDList(pidl, szFilename);
    if (isDirectory(szFilename))
      directory_selected(szFilename);
    else
      file_selected(szFilename);
  }
  CoUninitialize();
}
#endif

/* end of insert.c */
