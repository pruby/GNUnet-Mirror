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
 * @file src/applications/afs/gtkui/pseudonyms.c
 * @brief dialogs for creating and deleting pseudonyms
 * @author Christian Grothoff
 */
#include "gnunet_afs_esed2.h"
#include "helper.h"
#include "insertprogress.h"
#include "pseudonyms.h"
#include "main.h"

/**
 * @brief state of the CreatePseudonym window
 */
typedef struct {
  GtkWidget * window;
  GtkWidget * pseudonymLine;
  GtkWidget * passwordLine;

  GtkWidget * createNBlock;
  GtkWidget * keyword;
  GtkWidget * description;
  GtkWidget * owner;
  GtkWidget * mimetype;
  GtkWidget * uri;
  GtkWidget * contact;
  GtkWidget * root;
} CreatePseudonymWindowModel;

static gint save_gtk_widget_destroy(SaveCall * arg) {
  gtk_widget_destroy(arg->args);
  gtkSaveCallDone(arg->sem);
  return FALSE;
}

static void * createPseudonymThread(CreatePseudonymWindowModel * ewm) {
  const char * name;
  const char * pass;
  PrivateKey ps;

  name = gtk_entry_get_text(GTK_ENTRY(ewm->pseudonymLine));
  pass = gtk_entry_get_text(GTK_ENTRY(ewm->passwordLine)); 
  /* we may want to do this in another thread
     to keep the event manager running (and potentially
     even give feedback in the form of a popup window).
     After all, this can take a while... */
  ps = createPseudonym(name, pass);
  if (ps == NULL) {
    guiMessage(_("Failed to create pseudonym (see logs).\n"));
    gtk_widget_destroy(ewm->window);
    return NULL;
  }
  if (gtk_toggle_button_get_active((GtkToggleButton*) ewm->createNBlock)) {
    NBlock * nb;
    const char * re;
    HashCode160 root;

    re = gtk_entry_get_text(GTK_ENTRY(ewm->root));
    if (re != NULL) {
      if (strlen(re) == 0) {
	re = NULL;
      } else {      
	if (OK != enc2hash(re, &root))
	  hash(re, strlen(re), &root);
      }
    }
    nb = buildNBlock(ps,
		     name,
		     gtk_entry_get_text(GTK_ENTRY(ewm->description)),
		     gtk_entry_get_text(GTK_ENTRY(ewm->owner)),
		     gtk_entry_get_text(GTK_ENTRY(ewm->mimetype)),
		     gtk_entry_get_text(GTK_ENTRY(ewm->uri)),
		     gtk_entry_get_text(GTK_ENTRY(ewm->contact)),
		     (re != NULL) ? &root : NULL);
    if (nb != NULL) {
      GNUNET_TCP_SOCKET * sock;
    
      sock = getClientSocket();
      if (sock == NULL) {
	guiMessage(_("Could not connect to gnunetd, advertisement not published.\n"));
      } else {
	const char * keyword;
	char * info;

	if (OK != insertSBlock(sock,
			       (const SBlock *) nb)) 
	  guiMessage(_("Error inserting NBlock into namespace. "
		       "Is gnunetd running and space available?\n"));
	decryptNBlock(nb);
	addNamespace(nb);
	info = rootNodeToString((const RootNode*)nb);
	infoMessage(NO, _("Created namespace advertisement:\n%s\n"), info);
	FREE(info);

	keyword = gtk_entry_get_text(GTK_ENTRY(ewm->keyword));
	if ( (keyword != NULL) && (strlen(keyword) > 0) ) {
	  if (OK != insertRootWithKeyword(sock,
					  (const RootNode*) nb,
					  keyword,
					  getConfigurationInt("GNUNET-INSERT",
							      "CONTENT-PRIORITY")))
	    guiMessage(_("Error inserting NBlock under keyword '%s'. "
			 "Is gnunetd running and space available?\n"),
		       keyword);
	}
      }
      releaseClientSocket(sock);      
      FREE(nb);
    } else {
      BREAK();
      guiMessage(_("Failed to create NBlock!"));
    }
  }
  freePrivateKey(ps);
  
  gtkSaveCall((GtkFunction)save_gtk_widget_destroy, ewm->window);
  refreshMenuSensitivity();
  return NULL;
}


/**
 * Collects the results of the assembly dialog, creates an insertion 
 * progressbar and launches the insertion thread.
 *
 * @param dummy not used
 * @param ewm the state of the edit window
 */
static void create_ok(GtkWidget * dummy, 
		      CreatePseudonymWindowModel * ewm) {
  const char * name;
  const char * pass;
  PTHREAD_T pt;
  
  name = gtk_entry_get_text(GTK_ENTRY(ewm->pseudonymLine));
  if ( (name == NULL) || (name[0] == '\0') ) {
    guiMessage(_("Refusing to create pseudonym without a nickname.\n"));
    return;
  }
  pass = gtk_entry_get_text(GTK_ENTRY(ewm->passwordLine));
  gtk_widget_hide(ewm->window);
  if (0 != PTHREAD_CREATE(&pt,
			  (PThreadMain) &createPseudonymThread,
			  ewm,
			  8*1024))
    DIE_STRERROR("pthread_create");
  PTHREAD_DETACH(&pt);
}

/**
 * Exit the application (called when the main window
 * is closed or the user selects File-Quit).
 */
static void destroyPCWindow(GtkWidget * widget,
			    CreatePseudonymWindowModel * ewm) {
  FREE(ewm);
}


/**
 * Advertise on/off button was clicked.
 *
 * @param w the button
 * @param ewm state of the edit window
 */
static void button_advertise_clicked(GtkWidget * w,
				     CreatePseudonymWindowModel * ewm) {
  int ret;

  ret = gtk_toggle_button_get_active((GtkToggleButton*) ewm->createNBlock);

  gtk_widget_set_sensitive(ewm->keyword, ret);
  gtk_widget_set_sensitive(ewm->description, ret);
  gtk_widget_set_sensitive(ewm->owner, ret);
  gtk_widget_set_sensitive(ewm->mimetype, ret);
  gtk_widget_set_sensitive(ewm->uri, ret);
  gtk_widget_set_sensitive(ewm->contact, ret);
  gtk_widget_set_sensitive(ewm->root, ret);
}


/**
 * Open a window to allow the user to create a pseudonym
 *
 * @param unused GTK handle that is not used
 * @param unused2 not used
 */
void openCreatePseudonymDialog(GtkWidget * unused,
			       unsigned int unused2) {
  CreatePseudonymWindowModel * ewm;
  GtkWidget * vbox;
  GtkWidget * hbox;
  GtkWidget * label;
  GtkWidget * button_ok;
  GtkWidget * button_cancel;
  GtkWidget * separator;

  ewm = MALLOC(sizeof(CreatePseudonymWindowModel));
  /* create new window for editing */
  ewm->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_widget_set_usize(GTK_WIDGET(ewm->window),
		       500,
		       380);
  gtk_window_set_title(GTK_WINDOW(ewm->window), 
		       _("Create Pseudonym"));

  /* add container for window elements */
  vbox = gtk_vbox_new(FALSE, 0);
  gtk_container_add(GTK_CONTAINER(ewm->window),
		    vbox);
  gtk_widget_show(vbox);

  /* when user clicks on close box, always "destroy" */
  gtk_signal_connect(GTK_OBJECT(ewm->window),
		     "delete_event",
		     GTK_SIGNAL_FUNC(deleteEvent),
		     ewm);
  /* whenever edit window gets destroyed, 
     free *ALL* ewm data */
  gtk_signal_connect(GTK_OBJECT(ewm->window),
		     "destroy",
		     GTK_SIGNAL_FUNC(destroyPCWindow),
		     ewm);

  gtk_container_set_border_width(GTK_CONTAINER(ewm->window), 
				 10);

  /* Create a line to change the pseudonym */
  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     FALSE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  label = gtk_label_new(_("Pseudonym:"));
  gtk_box_pack_start(GTK_BOX(hbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label); 
  ewm->pseudonymLine = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->pseudonymLine,
		     TRUE,
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(ewm->pseudonymLine), 
		     "");
  gtk_widget_show(ewm->pseudonymLine);
  
  /* Create a line to change the description */
  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     FALSE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  label = gtk_label_new(_("Password:"));
  gtk_box_pack_start(GTK_BOX(hbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label);  

  ewm->passwordLine = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->passwordLine, 
		     TRUE, 
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(ewm->passwordLine), 
		     "");
  gtk_widget_show(ewm->passwordLine);
  
  separator = gtk_hseparator_new();
  gtk_box_pack_start(GTK_BOX(vbox),
		     separator,
		     TRUE, 
		     TRUE,
		     0);
  gtk_widget_show(separator);

  /* NBlock data */

  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     FALSE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  ewm->createNBlock = gtk_check_button_new_with_label(_("Create advertisement"));
  gtk_box_pack_start(GTK_BOX(hbox),
                     ewm->createNBlock,
                     TRUE,
                     TRUE,
                     0);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(ewm->createNBlock), 
			       1);
  gtk_widget_set_sensitive(ewm->createNBlock, 1);
  gtk_widget_show(ewm->createNBlock);


  gtk_signal_connect(GTK_OBJECT(ewm->createNBlock),
		     "toggled",
		     GTK_SIGNAL_FUNC(button_advertise_clicked),
		     ewm);
 



  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     FALSE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  label = gtk_label_new(_("Keyword:"));
  gtk_box_pack_start(GTK_BOX(hbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label);
  ewm->keyword = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->keyword, 
		     TRUE, 
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(ewm->keyword), 
		     "namespace");
  gtk_widget_show(ewm->keyword);


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
  ewm->description = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->description, 
		     TRUE, 
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(ewm->description), 
		     "");
  gtk_widget_show(ewm->description);

  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     FALSE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  label = gtk_label_new(_("Owner:"));
  gtk_box_pack_start(GTK_BOX(hbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label);
  ewm->owner = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->owner, 
		     TRUE, 
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(ewm->owner), 
		     "");
  gtk_widget_show(ewm->owner);


  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     FALSE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  label = gtk_label_new(_("Mime-type:"));
  gtk_box_pack_start(GTK_BOX(hbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label);
  ewm->mimetype = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->mimetype, 
		     TRUE, 
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(ewm->mimetype), 
		     "");
  gtk_widget_show(ewm->mimetype);


  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     FALSE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  label = gtk_label_new(_("URI:"));
  gtk_box_pack_start(GTK_BOX(hbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label);
  ewm->uri = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->uri, 
		     TRUE, 
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(ewm->uri), 
		     "");
  gtk_widget_show(ewm->uri);


  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     FALSE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  label = gtk_label_new(_("Contact:"));
  gtk_box_pack_start(GTK_BOX(hbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label);
  ewm->contact = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->contact, 
		     TRUE, 
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(ewm->contact), 
		     "");
  gtk_widget_show(ewm->contact);


  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     FALSE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  label = gtk_label_new(_("Root:"));
  gtk_box_pack_start(GTK_BOX(hbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label);
  ewm->root = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->root, 
		     TRUE, 
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(ewm->root), 
		     "");
  gtk_widget_show(ewm->root);

  /* end NBlock data */


  
  separator = gtk_hseparator_new();
  gtk_box_pack_start(GTK_BOX(vbox),
		     separator,
		     TRUE, 
		     TRUE,
		     0);
  gtk_widget_show(separator);


  /* add the insertion ok/cancel buttons */
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
		     GTK_SIGNAL_FUNC(create_ok),
		     ewm);
  gtk_signal_connect(GTK_OBJECT(button_cancel),
		     "clicked",
		     GTK_SIGNAL_FUNC(destroyWidget),
		     ewm->window);
  gtk_widget_show(button_ok);
  gtk_widget_show(button_cancel);

  /* all clear, show the window */
  gtk_widget_show(ewm->window);
}



/**
 * @brief state of the DeletePseudonym window
 */
typedef struct {
  GtkWidget * window;
  char * selected;
  GtkWidget * pseudonymList;
} DeletePseudonymWindowModel;

/**
 * Exit the application (called when the main window
 * is closed or the user selects File-Quit).
 */
static void destroyDPWindow(GtkWidget * widget,
			    DeletePseudonymWindowModel * ewm) {
  FREE(ewm);
}

/**
 * The keyword delete button was clicked. Delete the 
 * currently selected pseudonym.
 *
 * @param w not used
 * @param ewm state of the edit window
 */
static void button_del_clicked(GtkWidget * w, 
			       DeletePseudonymWindowModel * ewm) {
  GList * tmp;
  gchar * key[1];
  int row;
 
  tmp = GTK_CLIST(ewm->pseudonymList)->selection;
  if (NULL == tmp) {
    /* message that keyword must be selected to delete one? */
    return;
  }  
  row = (int) tmp->data;
  if (row < 0) 
    return; /* should never happen... */
  key[0] = NULL;
  gtk_clist_get_text(GTK_CLIST(ewm->pseudonymList),
		     row,
		     0,
		     &key[0]);
  if (key[0] == NULL)
    return;
  if (OK != deletePseudonym(key[0]))
    guiMessage(_("Failed to delete pseudonym (see logs).\n"));
  gtk_clist_remove(GTK_CLIST(ewm->pseudonymList),
		   row);
  refreshMenuSensitivity();
}

/**
 * Open a window to allow the user to delete a pseudonym
 *
 * @param unused GTK handle that is not used
 * @param unused2 not used
 */
void openDeletePseudonymDialog(GtkWidget * unused,
			       unsigned int unused2) {
  DeletePseudonymWindowModel * ewm;
  GtkWidget * window;
  GtkWidget * vbox, * hbox;
  GtkWidget * clist;
  GtkWidget * scrolled_window;
  GtkWidget * button_delete;
  GtkWidget * button_cancel;
  gchar * titles[1] = { gettext_noop("Pseudonyms") };
  int i;
  int cnt;
  char ** list;

  ewm = MALLOC(sizeof(DeletePseudonymWindowModel));
  /* create new window for editing */
  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  ewm->window = window;
  gtk_widget_set_usize(GTK_WIDGET(window),
		       250,
		       300);
  gtk_window_set_title(GTK_WINDOW(window), 
		       _("Delete Pseudonym"));

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
		     GTK_SIGNAL_FUNC(destroyDPWindow),
		     ewm);

  gtk_container_set_border_width(GTK_CONTAINER(window), 
				 10);

  /* add a list of pseudonyms */
  scrolled_window = gtk_scrolled_window_new(NULL, NULL);
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
  ewm->pseudonymList = clist;
  gtk_container_add(GTK_CONTAINER(scrolled_window), 
		    clist);
  gtk_widget_show(clist);
  /* add the known RootNodes to the list */
  list = NULL;
  cnt = listPseudonyms(&list);
  if (cnt > 0) {
    gtk_clist_freeze(GTK_CLIST(clist));
    for (i=0;i<cnt;i++) {
      gtk_clist_append(GTK_CLIST(clist),
		       &list[i]);
      FREE(list[i]);
    }
    gtk_clist_thaw(GTK_CLIST(clist));
  }
  FREENONNULL(list);

  /* add the buttons to add and delete keywords */
  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     FALSE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  button_delete = gtk_button_new_with_label(_("Delete Pseudonym"));
  gtk_box_pack_start(GTK_BOX(hbox), 
		     button_delete, 
		     TRUE, 
		     TRUE, 
		     0);
  gtk_signal_connect(GTK_OBJECT(button_delete), 
		     "clicked",
		     GTK_SIGNAL_FUNC(button_del_clicked),
		     ewm);
  gtk_widget_show(button_delete);


  button_cancel = gtk_button_new_with_label(_("Cancel"));
  gtk_box_pack_start(GTK_BOX(hbox), 
		     button_cancel, 
		     TRUE,
		     TRUE, 
		     0);
  gtk_signal_connect(GTK_OBJECT(button_cancel),
		     "clicked",
		     GTK_SIGNAL_FUNC(destroyWidget),
		     window);
  gtk_widget_show(button_cancel);

  /* all clear, show the window */
  gtk_widget_show(window);
}


/* end of pseudonyms.c */
