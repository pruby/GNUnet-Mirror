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
 * @file src/applications/afs/gtkui/namespace.c
 * @brief Namespace dialog for the AFS interface
 * @author Christian Grothoff
 */

#include "gnunet_afs_esed2.h"
#include "helper.h"
#include "namespace.h"
#include "search.h"
#include "main.h"

/**
 * @brief state of the insert into namespace window
 */
typedef struct {
  char * fileName;
  GtkWidget * window;
  GtkWidget * passwordLine;
  GtkWidget * pseudonymList;
  GtkWidget * sblockList;
  GtkWidget * availableList;
  GtkWidget * updateInterval;
  GtkWidget * currentKey;
  GtkWidget * nextKey;
  SBlock ** updateableEntries;
  int updateableCount;
  HashCode160 selectedPseudonym;
} NamespaceInsertWindowModel;

static int parseTime(const char * t) {
  int pos;
  int start;
  int ret;
  unsigned int val;
  char * tmp;
  
  ret = 0;
  pos = 0;

  while (t[pos] != '\0') {
    start = pos;
    while ( (t[pos] != ' ') &&
	    (t[pos] != '\0') )
      pos++;
    tmp = STRNDUP(&t[start],
		  pos - start);
    if (1 != sscanf(tmp,
		    "%u",
		    &val) ) 
      return -1; /* parse error */
    FREE(tmp);
    while ( t[pos] == ' ')
      pos++;
    start = pos;
    while ( (t[pos] != ' ') &&
	    (t[pos] != '\0') )
      pos++;
    if (0 == strncasecmp(&t[start],
			 _("minutes"),
			 strlen(_("minutes"))))
      ret += 60 * val;
    else if (0 == strncasecmp(&t[start],
			      _("seconds"),
			      strlen(_("seconds"))))
      ret += val;
    else if (0 == strncasecmp(&t[start],
			      _("hours"),
			      strlen(_("hours"))))
      ret += 60 * 60 * val;
    else if (0 == strncasecmp(&t[start],
			      _("days"),
			      strlen(_("days"))))
      ret += 24 * 60 * 60 * val;
    else
      return -1; /* parse error */ 
    while ( t[pos] == ' ')
      pos++;
  }  
  return ret;
}

/**
 * Collects the results of the assembly dialog, creates an insertion 
 * progressbar and launches the insertion thread.
 *
 * @param dummy not used
 * @param ewm the state of the edit window
 */
static void buildNSEntry(GtkWidget * dummy, 
			 NamespaceInsertWindowModel * ewm) {
  GList * tmp;
  int row;
  gchar * key[1];
  const char * currentKey;
  const char * nextKey;
  char * name;
  const char * pass;
  char * message;
  PrivateKey pseudo;
  HashCode160 k; /* = key, next - increment */
  HashCode160 n; /* = next or namespace ID depending where in code */
  TIME_T interval;
  GNUNET_TCP_SOCKET * sock;
  SBlock * sb;
  RootNode * rn;
  char * uri;
  const char * updateInterval;
  TIME_T now;
  TIME_T creationTime;
  char * desc;
  char * mime;

  updateInterval = gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(ewm->updateInterval)->entry));
  if ( (updateInterval == NULL) || (updateInterval[0] == '\0') ) {
    guiMessage(_("You must specify an update frequency.\n"));
    return;
  }
  if (strcmp(updateInterval, _("--no updates--")) == 0) {
    interval = 0;    
  } else if (strcmp(updateInterval, _("--sporadic updates--")) == 0) {
    interval = -1;
  } else {
    interval = parseTime(updateInterval);
    if (interval == -1) {
      guiMessage(_("Parsing of time interval failed. "
		   "Use \"(INT [%s|%s|%s])*\" format.\n"),
		 _("seconds"),
		 _("minutes"),
		 _("hours"));
      return;
    }
  } 
  tmp = GTK_CLIST(ewm->pseudonymList)->selection;
  if (NULL == tmp) {
    guiMessage(_("You must select a pseudonym.\n"));    
    return;  
  }
  row = (int) tmp->data;
  if ( row < 0 ) {
    guiMessage(_("You must select a pseudonym.\n"));    
    return; 
  }

  key[0] = NULL;
  gtk_clist_get_text(GTK_CLIST(ewm->pseudonymList),
		     row,
		     0,
		     &key[0]);
  name = key[0];
  if (name == NULL) {
    guiMessage(_("You must select a pseudonym.\n"));    
    BREAK();
    return;  /* should never happen... */
  }
  pass = gtk_entry_get_text(GTK_ENTRY(ewm->passwordLine));
  if (strlen(pass) == 0)
    pass = NULL;
  pseudo = readPseudonym(name, pass);
  if (pseudo == NULL) {
    guiMessage(_("Password specified does not decrypt the pseudonym.\n"));
    return;
  }

  currentKey = gtk_entry_get_text(GTK_ENTRY(ewm->currentKey));
  nextKey = gtk_entry_get_text(GTK_ENTRY(ewm->nextKey));

  tmp = GTK_CLIST(ewm->availableList)->selection;
  if (NULL == tmp) {
    guiMessage(_("You must select a file.\n"));
    return;  
  }
  row = (int) tmp->data;
  if ( row < 0 ) {
    guiMessage(_("You must select a file.\n"));
    freePrivateKey(pseudo);
    return;
  }
  rn = gtk_clist_get_row_data(GTK_CLIST(ewm->availableList),
  			      row);

  /* select/derive current & next IDs! */
  tmp = GTK_CLIST(ewm->sblockList)->selection;
  if ( (NULL == tmp) || 
       ( ((int)tmp->data) == 0) ) {
    /* "--no update--" or nothing selected, pick random IDs */
    if (SYSERR == enc2hash(currentKey, &k))
      hash(currentKey, strlen(currentKey), &k);
    switch(interval) {
      case SBLOCK_UPDATE_NONE:
        /* no updates => next == this */
        memcpy(&n,
	       &k,
	       sizeof(HashCode160));
	break;
      case SBLOCK_UPDATE_SPORADIC:
        /* sporadic update; pick specified ID if given,
           otherwise go random */
	if (SYSERR == enc2hash(nextKey, &n))
	  hash(nextKey, strlen(nextKey), &n);
	break;
      default:
        /* periodic update, the very first next id will be random */
        makeRandomId(&n);
	break;
    } 

    TIME(&creationTime);
  } else {
    SBlock * pred;

    row = ((int) tmp->data) - 1; /* -1: first item is always "no update" */
    if (row >= ewm->updateableCount) {
      BREAK();
      freePrivateKey(pseudo);
      return; 
    }
    pred = ewm->updateableEntries[row];
    /* now, compute CURRENT ID and next ID */
    TIME(&now);
    computeIdAtTime(pred, 
    		    now, 
		    &k);
    if ( (interval != SBLOCK_UPDATE_NONE) &&
	 (interval != SBLOCK_UPDATE_SPORADIC) ) {
      int delta;
      /* periodic update */
      delta = now - ntohl(pred->creationTime);
      delta = delta / ntohl(pred->updateInterval);
      if (delta == 0)
	delta = 1; /* force to be in the future from the updated block! */
      creationTime = ntohl(pred->creationTime) + delta * ntohl(pred->updateInterval);

      /* periodic update, compute _next_ ID as increment! */
      addHashCodes(&k,
		   &pred->identifierIncrement,
		   &n); /* n = k + inc */      
    } else {
      if (interval == SBLOCK_UPDATE_SPORADIC) {
	/* sporadic update, pick random next ID 
	   if not specified! */
	if (SYSERR == enc2hash(nextKey, &n))
	  hash(nextKey, strlen(nextKey), &n);
	TIME(&creationTime);
      } else {
	/* updating non-updateable SBlock!? Should
	   never happen! */
	guiMessage(_("Attempt to update an non-updateble SBlock, this should never happen!\n")); 
	BREAK();
	return;
      }
    }
  } /* end of selecting k and n based on update mechanism */
  
  name = getFilenameFromNode(rn);
  desc = getDescriptionFromNode(rn);
  mime = getMimetypeFromNode(rn);
  sb = buildSBlock(pseudo,
		   &rn->header.fileIdentifier,
		   desc,
		   name,
		   mime,
		   creationTime,
		   interval,
		   &k,
		   &n);
  FREE(desc);
  FREE(mime);
  freePrivateKey(pseudo);
  if (sb == NULL) {
    FREE(name);
    guiMessage(_("Failed to build SBlock. Consult logs."));
    return;
  }
  sock = getClientSocket();
  if (sock == NULL) {
    FREE(sb);
    FREE(name);
    guiMessage(_("Failed to connect to gnunetd."));
    return;
  }
  if (OK != insertSBlock(sock,
			 sb)) {
    guiMessage(_("Failed to insert SBlock. Consult logs."));    
    releaseClientSocket(sock);
    FREE(name);
    FREE(sb);
    return;
  }
  releaseClientSocket(sock);
  /* obtain "n = S", the namespace ID */
  hash(&sb->subspace,
       sizeof(PublicKey),
       &n);
  FREE(sb);
 

  if (NULL != nextKey)
    desc = STRDUP(nextKey);
  else 
    desc = NULL;

  /* destroy the window */
  gtk_widget_destroy(ewm->window);
  refreshMenuSensitivity();

  uri = createSubspaceURI(&n, &k);
  message = MALLOC(128 + strlen(uri));
  SNPRINTF(message,
	   128 + strlen(uri),
	   _("File '%s' inserted into namespace under URI '%s'.\n"),
	   name,
	   uri);
  FREE(uri);
  LOG(LOG_DEBUG,
      "%s\n",
      message);
  infoMessage(NO, message);

  if (desc != NULL) {
    SNPRINTF(message,
	     128,
	     _("Identifier for the next update to this content will be '%s'.\n"),
	     desc);
    FREE(desc);
    infoMessage(NO, message);
  }

  FREE(message);
  FREE(name);  
}  


/**
 * Exit the application (called when the main window
 * is closed or the user selects File-Quit).
 */
static void destroyNamespaceInsertWindow(GtkWidget * widget,
					 NamespaceInsertWindowModel * ewm) {
  int i;
  GList * tmp;
  int row;

  gtk_clist_freeze(GTK_CLIST(ewm->availableList));
  tmp = GTK_CLIST(ewm->availableList)->selection;
  while (tmp) {
    row = (int)tmp->data;
    tmp = tmp->next;

    FREENONNULL(gtk_clist_get_row_data(GTK_CLIST(ewm->availableList),
    				       row));
    gtk_clist_remove(GTK_CLIST(ewm->availableList), 
    		     row);
  }
  gtk_clist_thaw(GTK_CLIST(ewm->availableList));
  
  for (i=0;i<ewm->updateableCount;i++)
    FREE(ewm->updateableEntries[i]);
  GROW(ewm->updateableEntries,
       ewm->updateableCount,
       0);
  FREE(ewm);
}

static void appendToCList(RootNode * root,
			  NamespaceInsertWindowModel * ewm) {
  gchar * entry[1];
  char * name;
  char * desc;
  char * mime;
  RootNode * copy;
  int row;
  size_t n;
 
  n = strlen(root->header.filename)+
    strlen(root->header.description)+
    strlen(root->header.mimetype)+
    128;
  entry[0] = MALLOC(n);
  name = getFilenameFromNode(root);
  desc = getDescriptionFromNode(root);
  mime = getMimetypeFromNode(root);
  SNPRINTF(entry[0],
	   n,
	   "%s, %s (%s, %u bytes)",
	   name,
	   desc,
	   mime,
	   (unsigned int) ntohl(root->header.fileIdentifier.file_length)); 
  FREE(name);
  FREE(desc);
  FREE(mime);
  row = gtk_clist_append(GTK_CLIST(ewm->availableList), 
  		         entry);
  FREE(entry[0]);
  copy = MALLOC(sizeof(RootNode));
  memcpy(copy,
  	 root,
	 sizeof(RootNode));
  /* note: if you wish any clist to be sortable, you must
     store the associated data in the list itself, not in an external
     array! (same goes for all clists, but currently only "Files"
     is sortable of the namespace related lists) - IW */
  gtk_clist_set_row_data(GTK_CLIST(ewm->availableList),
  			 row,
			 copy);
}

static void checkUpdateableSBlocks(SBlock * sb,
				   NamespaceInsertWindowModel * ewm) {
  gchar * entry[1];
  HashCode160 namespace;
  SBlock * tmp;
  int i;
  size_t n;
  
  if (SBLOCK_UPDATE_NONE == ntohl(sb->updateInterval))
    return; /* non-updateable SBlock */

  /* check if namespace *matches* selected Pseudonym! */
  hash(&sb->subspace,
       sizeof(PublicKey),
       &namespace);
  if (! equalsHashCode160(&ewm->selectedPseudonym,
			  &namespace) )
    return;

  /* check if SBlock is valid */
  if (SYSERR == verifySBlock(sb))
    return;
  
  /* skip if duplicate periodical (essentially irrelevant which
   * of the blocks gets updated, the result is the same).
   * FIXME? this causes trouble if two unrelated sblocks have 
   * identical identifierIncrement, which should be unlikely? */
  if(ntohl(sb->updateInterval)>0) {
    for(i=0;i<ewm->updateableCount;i++) {
      tmp = ewm->updateableEntries[i];
      if ((0 == memcmp(&tmp->identifierIncrement,
       	       	       &sb->identifierIncrement,
		       sizeof(HashCode160))) ) {
        LOG(LOG_DEBUG, 
            "Skipping duplicate SBlock entry.\n");
        return;
      }
    }
  }

  /* ok, all checks pass: add */
  sb->filename[MAX_FILENAME_LEN/2-1] = 0;
  sb->description[MAX_DESC_LEN-1] = 0;
  sb->mimetype[MAX_MIMETYPE_LEN/2-1] = 0;
  n = strlen(sb->filename)+
    strlen(sb->description)+
    strlen(sb->mimetype)+
    128;
  entry[0] = MALLOC(n);
  SNPRINTF(entry[0],
	   n,
	   "%s, %s (%s, %u bytes)",
	   sb->filename,
	   sb->description,
	   sb->mimetype,
	   (unsigned int) ntohl(sb->fileIdentifier.file_length)); 
  gtk_clist_append(GTK_CLIST(ewm->sblockList), 
		   entry);
  FREE(entry[0]);
  GROW(ewm->updateableEntries,
       ewm->updateableCount,
       ewm->updateableCount+1);
  ewm->updateableEntries[ewm->updateableCount-1]
    = MALLOC(sizeof(SBlock));
  memcpy(ewm->updateableEntries[ewm->updateableCount-1],
	 sb,
	 sizeof(SBlock));
}

/**
 * Only the ewm argument may be used since
 * we may also be called from enter_callback
 * which is called whenever the user presses
 * ENTER in the password line.
 */
static void pselectCallback(GtkWidget * unused,
			    gint rowX,
			    gint column,
			    GdkEventButton * event,
			    NamespaceInsertWindowModel * ewm) {
  GList * tmp;
  int row;
  gchar * key[1];
  const char * name;
  const char * pass;
  PrivateKey pseudo;
  PublicKey pkey;
  int i;
  gchar * titlesNo[1] = { "--no update--" };

  /* first, clear off the old sblock list */
  gtk_clist_freeze(GTK_CLIST(ewm->sblockList));
  gtk_clist_clear(GTK_CLIST(ewm->sblockList));
  gtk_clist_append(GTK_CLIST(ewm->sblockList),
		   &titlesNo[0]);
  gtk_clist_thaw(GTK_CLIST(ewm->sblockList));   
  
  /* update ewm->selectedPseudonym */
  tmp = GTK_CLIST(ewm->pseudonymList)->selection;
  if (NULL == tmp) {
    return;  
  }
  row = (int) tmp->data;
  if ( row < 0 ) {
    return;   
  }

  key[0] = NULL;
  gtk_clist_get_text(GTK_CLIST(ewm->pseudonymList),
		     row,
		     0,
		     &key[0]);
  name = key[0];
  if (name == NULL) {
    return;   
  }
  pass = gtk_entry_get_text(GTK_ENTRY(ewm->passwordLine));
  if (strlen(pass) == 0)
    pass = NULL;
  pseudo = readPseudonym(name, pass);
  if (pseudo == NULL) {
    return; /* wait for password to be entered... */  
  }
  getPublicKey(pseudo, 
	       &pkey);
  freePrivateKey(pseudo);
  hash(&pkey,
       sizeof(PublicKey),
       &ewm->selectedPseudonym);
  
  /* clear entries from possible previous selection */
  for (i=0;i<ewm->updateableCount;i++)
    FREE(ewm->updateableEntries[i]);
  GROW(ewm->updateableEntries,
       ewm->updateableCount,
       0);
  
  gtk_clist_freeze(GTK_CLIST(ewm->sblockList));
  iterateDirectoryDatabase(DIR_CONTEXT_INSERT_SB,
			   (RootNodeCallback)&checkUpdateableSBlocks,
			   ewm);
  gtk_clist_thaw(GTK_CLIST(ewm->sblockList));   
}
 
static void enter_callback(GtkWidget * unused,
			   NamespaceInsertWindowModel * ewm) {
  pselectCallback(NULL, 0, 0, NULL, ewm);
}

static void selectFrequencyCallback(GtkWidget * unused,
				    NamespaceInsertWindowModel * ewm) {
  const gchar * choice;
  GList * tmp;

  tmp = GTK_CLIST(ewm->sblockList)->selection;
  if ( (NULL == tmp) || 
       ( ((int)tmp->data) == 0) ) {    
    choice = gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(ewm->updateInterval)->entry)); 
    if (strcmp(choice, "--sporadic updates--") == 0) {
      gtk_widget_set_sensitive(ewm->currentKey, TRUE);
      gtk_widget_set_sensitive(ewm->nextKey, TRUE);
    } else if (strcmp(choice, "--no updates--") == 0) {
      gtk_widget_set_sensitive(ewm->currentKey, TRUE);
      gtk_widget_set_sensitive(ewm->nextKey, FALSE);
      gtk_entry_set_text(GTK_ENTRY(ewm->nextKey), 
			 "");
    } else {
      /* periodic */
      gtk_widget_set_sensitive(ewm->currentKey, TRUE);
      gtk_widget_set_sensitive(ewm->nextKey, FALSE);
      gtk_entry_set_text(GTK_ENTRY(ewm->nextKey), 
			 "");
    }
  } else {
    /* determined by SBlock, and SBlock has
       already set the entries correctly */
  }
}

/**
 * The user selected an SBlock for an update.  Set the "update
 * interval" field according to the update interval
 * found in the SBlock.
 */
static void selectSBlockCallback(GtkWidget * unused,
				 gint rowX,
				 gint column,
				 GdkEventButton * event,
				 NamespaceInsertWindowModel * ewm) {
  SBlock * pred;
  TIME_T interval;
  GList * tmp;
  int row;
  unsigned int days, hours, minutes, seconds;
  char * txt;
  EncName enc;
  HashCode160 currentId;
  HashCode160 nextId;
  TIME_T now;
    
  gtk_entry_set_text(GTK_ENTRY(ewm->nextKey), 
	             "");
    
  tmp = GTK_CLIST(ewm->sblockList)->selection;
  if ( (NULL == tmp) || 
       ( ((int)tmp->data) == 0) ) {
    gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(ewm->updateInterval)->entry), 
		       _("--no updates--"));
    gtk_widget_set_sensitive(ewm->currentKey, TRUE);
    gtk_widget_set_sensitive(ewm->nextKey, FALSE);
    gtk_widget_set_sensitive(ewm->updateInterval, TRUE);
    gtk_entry_set_text(GTK_ENTRY(ewm->currentKey), 
		       "");
    gtk_entry_set_text(GTK_ENTRY(ewm->nextKey), 
		       "");    
    return;
  }

  row = ((int) tmp->data) - 1; /* -1: first item is always "no update" */
  if (row >= ewm->updateableCount) {
    guiMessage(" this should never happen.\n");    
    gtk_widget_set_sensitive(ewm->currentKey, FALSE);
    gtk_widget_set_sensitive(ewm->nextKey, FALSE);
    gtk_widget_set_sensitive(ewm->updateInterval, FALSE);
    return; 
  }
  pred = ewm->updateableEntries[row];

  interval = ntohl(pred->updateInterval);
  if (interval == SBLOCK_UPDATE_SPORADIC) {
    gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(ewm->updateInterval)->entry), 
		       _("--sporadic updates--"));
    hash2enc(&pred->nextIdentifier,
	     &enc);
    gtk_entry_set_text(GTK_ENTRY(ewm->currentKey), 
		       (gchar*)&enc);

    gtk_widget_set_sensitive(ewm->currentKey, FALSE);
    gtk_widget_set_sensitive(ewm->nextKey, TRUE);
    gtk_widget_set_sensitive(ewm->updateInterval, FALSE);
    return;
  }
  seconds = interval % 60;
  interval = interval / 60;
  minutes = interval % 60;
  interval = interval / 60;
  hours = interval % 24;
  interval = interval / 24;
  days = interval;
  txt = MALLOC(256);
  SNPRINTF(txt,
	   256,
	   "%u %s %u %s %u %s %u %s",
	   days, 
	   _("days"),
	   hours, 
	   _("hours"),
	   minutes,
	   _("minutes"),
	   seconds,
	   _("seconds"));
  gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(ewm->updateInterval)->entry), 
		     txt);  
  FREE(txt);
  /* periodic: all are pre-determined! */

  TIME(&now);
  computeIdAtTime(pred, now, &currentId);
  computeIdAtTime(pred, now + ntohl(pred->updateInterval), &nextId);
  hash2enc(&currentId,
	   &enc);
  gtk_entry_set_text(GTK_ENTRY(ewm->currentKey), 
		     (gchar*)&enc);
  hash2enc(&nextId,
	   &enc);
  gtk_entry_set_text(GTK_ENTRY(ewm->nextKey), 
		     (gchar*)&enc);
  gtk_widget_set_sensitive(ewm->nextKey, FALSE);
  gtk_widget_set_sensitive(ewm->currentKey, FALSE);
  gtk_widget_set_sensitive(ewm->updateInterval, FALSE);
}


/**
 * Open a window to allow the user to build a namespace entry.
 *
 * @param unused GTK handle that is not used
 * @param context selector for a subset of the known RootNodes
 */
void openAssembleNamespaceDialog(GtkWidget * unused,
				 unsigned int context) {
  NamespaceInsertWindowModel * ewm;
  GtkWidget * window;
  GtkWidget * vbox, *vboxX, * hbox, * hboxX;
  GtkWidget * clist;
  GtkWidget * scrolled_window;
  GtkWidget * label;
  GtkWidget * separator; 
  GtkWidget * button_ok;
  GtkWidget * button_cancel;
  GtkWidget * combo;
  GList * glist;
  int i;
  int cnt;
  char ** list;
  gchar * titles[1] = { gettext_noop("Pseudonyms") };
  gchar * titlesNo[1] = { gettext_noop("--no update--") };
  gchar * titlesSBlocks[1] = { gettext_noop("Updateable SBlocks for pseudonym") };
  gchar * titlesAvailable[1] = { gettext_noop("Files available") };

  ewm = MALLOC(sizeof(NamespaceInsertWindowModel));
  memset(ewm, 0, sizeof(NamespaceInsertWindowModel));

  /* create new window for editing */
  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  ewm->window = window;
  gtk_widget_set_usize(GTK_WIDGET(window),
		       780,
		       580);
  gtk_window_set_title(GTK_WINDOW(window), 
		       _("Insert into Namespace"));

  /* add container for window elements */
  vbox = gtk_vbox_new(FALSE, 15);
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
		     GTK_SIGNAL_FUNC(destroyNamespaceInsertWindow),
		     ewm);

  gtk_container_set_border_width(GTK_CONTAINER(window), 
				 10);


  /* arrange a pseudonym box left to a "select SBlock to update" box */
  hbox = gtk_hbox_new(FALSE, 5);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox, 
		     TRUE, 
		     TRUE, 
		     0);
  gtk_widget_show(hbox);

  /* add a list of pseudonyms */
  vboxX = gtk_vbox_new(FALSE, 0);
  gtk_container_add(GTK_CONTAINER(hbox),
		    vboxX);
  gtk_widget_show(vboxX);

  scrolled_window = gtk_scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
				 GTK_POLICY_AUTOMATIC, 
				 GTK_POLICY_ALWAYS);
  gtk_box_pack_start(GTK_BOX(vboxX), 
		     scrolled_window, 
		     TRUE, 
		     TRUE, 
		     0);
  gtk_widget_show(scrolled_window);  
  clist = gtk_clist_new_with_titles(1, titles); 
  ewm->pseudonymList = clist;
  gtk_clist_set_column_width(GTK_CLIST(clist),
  			     0,
			     150);
  gtk_container_add(GTK_CONTAINER(scrolled_window), 
		    clist);
  gtk_widget_show(clist);
  /* add the known Pseudonyms to the list */
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
  /* add callback: if a pseudonym is
     selected, the "updateable SBlocks" list
     must be updated! */
  gtk_signal_connect(GTK_OBJECT(clist),
		     "select_row",
		     GTK_SIGNAL_FUNC(pselectCallback),
		     ewm);



  /* Create a line to enter the password */
  hboxX = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vboxX),
		     hboxX,
		     FALSE,
		     FALSE,
		     0);
  gtk_widget_show(hboxX);
  label = gtk_label_new(_("Pseudonym Password:"));
  gtk_box_pack_start(GTK_BOX(hboxX),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label); 
  ewm->passwordLine = gtk_entry_new();
  gtk_entry_set_visibility(GTK_ENTRY(ewm->passwordLine), FALSE);
  gtk_box_pack_start(GTK_BOX(hboxX),
		     ewm->passwordLine,
		     TRUE,
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(ewm->passwordLine), 
		     "");
  gtk_widget_show(ewm->passwordLine);
  gtk_signal_connect(GTK_OBJECT(ewm->passwordLine), 
		     "activate",
		     GTK_SIGNAL_FUNC(enter_callback),
		     ewm);

  /* add separator */
  separator = gtk_vseparator_new();
  gtk_box_pack_start(GTK_BOX(hbox),
		     separator,
		     FALSE, 
		     FALSE,
		     0);
  gtk_widget_show(separator);
  /* ok, now another feature in the hbox:
     select which SBlock to update! */

  scrolled_window = gtk_scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
				 GTK_POLICY_AUTOMATIC, 
				 GTK_POLICY_ALWAYS);
  gtk_box_pack_start(GTK_BOX(hbox), 
		     scrolled_window, 
		     TRUE, 
		     TRUE, 
		     0);
  gtk_widget_show(scrolled_window);  
  clist = gtk_clist_new_with_titles(1, titlesSBlocks); 
  ewm->sblockList = clist;
  gtk_container_add(GTK_CONTAINER(scrolled_window), 
		    clist);
  gtk_widget_show(clist);
  /* add the known SBlocks to the list */
  list = NULL;
  gtk_clist_freeze(GTK_CLIST(clist));
  gtk_clist_append(GTK_CLIST(clist),
		   &titlesNo[0]);
  gtk_clist_thaw(GTK_CLIST(clist)); 
  gtk_signal_connect(GTK_OBJECT(clist),
		     "select_row",
		     GTK_SIGNAL_FUNC(selectSBlockCallback),
		     ewm);
  gtk_signal_connect(GTK_OBJECT(clist),
		     "unselect_row",
		     GTK_SIGNAL_FUNC(selectSBlockCallback),
		     ewm);
  
  /* add separator */
  separator = gtk_hseparator_new();
  gtk_box_pack_start(GTK_BOX(vbox),
		     separator,
		     FALSE, 
		     FALSE,
		     0);
  gtk_widget_show(separator);

  /* add interval / non-periodic selection */
  hbox = gtk_hbox_new(FALSE, 10);
  gtk_box_pack_start(GTK_BOX(vbox),
  		     hbox,
		     FALSE,
		     FALSE,
		     0);
  gtk_widget_show(hbox);
  label = gtk_label_new(_("Update frequency:"));
  gtk_box_pack_start(GTK_BOX(hbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label); 

  combo = gtk_combo_new(); 
  ewm->updateInterval = combo;
  gtk_container_add(GTK_CONTAINER(hbox),
		    combo);
  gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(combo)->entry), 
		     "--no updates--");
  glist = NULL;
  glist = g_list_append(glist, _("--no updates--"));
  glist = g_list_append(glist, _("--sporadic updates--"));
  glist = g_list_append(glist, _("12 hours")); 
  glist = g_list_append(glist, _("1 days")); 
  glist = g_list_append(glist, _("2 days")); 
  glist = g_list_append(glist, _("7 days")); 
  glist = g_list_append(glist, _("30 days")); 
  glist = g_list_append(glist, _("2 hours 30 minutes")); 

  gtk_combo_set_popdown_strings(GTK_COMBO(combo), 
				glist) ;
  gtk_signal_connect(GTK_OBJECT(GTK_COMBO(combo)->entry),
		     "changed",
		     GTK_SIGNAL_FUNC(selectFrequencyCallback),
		     ewm);
  gtk_widget_show(combo);
  
  /* add keyword boxes */ 
  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
  		     hbox,
		     FALSE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  label = gtk_label_new(_("Current keyword: "));
  gtk_box_pack_start(GTK_BOX(hbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label);
  ewm->currentKey = gtk_entry_new();
  gtk_entry_set_text(GTK_ENTRY(ewm->currentKey), 
		     "");
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->currentKey, 
		     TRUE, 
		     TRUE, 
		     0);
  gtk_widget_show(ewm->currentKey);
  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
  		     hbox,
		     FALSE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  label = gtk_label_new(_("Future keyword: "));
  gtk_box_pack_start(GTK_BOX(hbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label);
  ewm->nextKey = gtk_entry_new();
  gtk_entry_set_text(GTK_ENTRY(ewm->nextKey), 
		     "");
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->nextKey, 
		     TRUE, 
		     TRUE, 
		     0);
  gtk_widget_set_sensitive(ewm->nextKey, FALSE);
  gtk_widget_show(ewm->nextKey);

  /* add separator */
  separator = gtk_hseparator_new();
  gtk_box_pack_start(GTK_BOX(vbox),
		     separator,
		     FALSE, 
		     FALSE,
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
  gtk_clist_set_sort_column(GTK_CLIST(clist),0);
  gtk_clist_set_auto_sort(GTK_CLIST(clist),TRUE);
  /* add the known RootNodes to the list */
  gtk_clist_freeze(GTK_CLIST(clist));
  iterateDirectoryDatabase(context,
			   (RootNodeCallback)&appendToCList,
			   ewm);
  gtk_clist_thaw(GTK_CLIST(clist));
  gtk_widget_show(clist);


  /* add the insertion ok/cancel buttons */
  separator = gtk_hseparator_new();
  gtk_box_pack_start(GTK_BOX(vbox),
		     separator,
		     FALSE, 
		     FALSE,
		     0);
  gtk_widget_show(separator);

  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox, 
		     FALSE, 
		     FALSE, 
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
		     GTK_SIGNAL_FUNC(buildNSEntry),
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


/* ********************** SEARCH ******************** */
/* ********************** SEARCH ******************** */
/* ********************** SEARCH ******************** */

/**
 * @brief state of the namespace search window
 */
typedef struct {
  GtkWidget * window;
  GtkWidget * namespaceCombo;
  GtkWidget * searchkeyLine;

  GtkWidget * description;
  GtkWidget * realname;
  GtkWidget * mimetype;
  GtkWidget * uri;
  GtkWidget * contact;
  GtkWidget * rating;
} NamespaceSearchWindowModel;


/**
 * Exit the application (called when the main window
 * is closed or the user selects File-Quit).
 */
static void destroyNamespaceSearchWindow(GtkWidget * widget,
					 NamespaceSearchWindowModel * ewm) {
  FREE(ewm);
}

typedef struct {
  HashCode160 n;
  HashCode160 k;
  ListModel * model;
  HashCode160 * seen;
  int seenCount;
  HashCode160 * results;
  int resultCount;
} NSSearchThreadData;

/**
 * The main method of the search-thread.
 *
 * @param n namespace to search
 * @param k code to search for
 * @param model Data related to the search
 * @return OK on success, SYSERR on error
 */
static int startNamespaceSearchThread(HashCode160 * n,
				      HashCode160 * k,
				      ListModel * model);

/**
 * Run the namespace search.  Starts the search
 * thread and adds a new tab to the window list.
 */
static void startSearch(HashCode160 * n,
			HashCode160 * k,
			const char * kname) {
  ListModel * model;  
  int ok;
  GtkWidget * box;

  /* start search! */
  model = (ListModel*) MALLOC(sizeof(ListModel));
  model->type = LM_TYPE_NSSEARCH;
  model->doTerminate = NO;
  model->skipMenuRefresh = NO;
  model->SEARCH_socket_ = NULL;

  box = initializeSearchResultList(model);

  /* start searching */
  ok = startNamespaceSearchThread(n, 
				  k,
				  model);
  if (ok == SYSERR) {
    LOG(LOG_DEBUG,
        "'%s' failed\n",
	"startNamespaceSearchThread");
    releaseClientSocket(model->SEARCH_socket_);
    gtkSaveCall((GtkFunction) doDestroyWidget, box);
    FREE(model);
  } else {
    char * label;
    char * nick;
    EncName enc;
    size_t ne;

    nick = getUniqueNickname(n);
    if (kname != NULL) 
      ne = strlen(nick) + 4 + strlen(kname);
    else
      ne = strlen(nick) + sizeof(EncName) + 4;
    label = MALLOC(ne);
    if (kname != NULL) {
      SNPRINTF(label, ne, "%s/%s", nick, kname);
    } else {
      hash2enc(k, &enc);
      SNPRINTF(label, ne, "%s/%s", nick, &enc);
    }
    FREE(nick);
    addToNotebook(label,
		  box);   
    LOG(LOG_DEBUG, 
	"Namespace search initiated for '%s'.\n",
	label);
    FREE(label);
  }
}

static void displayResultGTK_(SBlock * sb,
			      NSSearchThreadData * sqc) {
  HashCode160 curK;
  int i;
  EncName enc;
  char * verb;
  
  switch (ntohs(sb->major_formatVersion)) {
  case ROOT_MAJOR_VERSION:
    LOG(LOG_WARNING,
	_("Received RBlock in namespace search.\n"));
    break;
  case SBLOCK_MAJOR_VERSION:
    hash(sb, sizeof(SBlock), &curK);
    hash2enc(&curK,
	     &enc);
    LOG(LOG_DEBUG, 
	"Got namespace result for identifier '%s'.\n", 
	&enc);
    for (i=0;i<sqc->resultCount;i++)
      if (equalsHashCode160(&curK,
			    &sqc->results[i])) {
	LOG(LOG_DEBUG, 
	    "'%s' skipping previously seen entry '%s'.\n",
	    __FUNCTION__,
	    &enc);
	return; /* displayed already */
      }
    GROW(sqc->results,
	 sqc->resultCount,
	 sqc->resultCount+1);
    memcpy(&sqc->results[sqc->resultCount-1],
	   &curK,
	 sizeof(HashCode160));
    displayResultGTK((RootNode*)sb, 
		     sqc->model);
    refreshMenuSensitivity();
    GROW(sqc->seen,
	 sqc->seenCount,
	 sqc->seenCount+1);
    memcpy(&sqc->seen[sqc->seenCount-1], 
	   &sqc->k, 
	   sizeof(HashCode160));
    
    /* now search for update if possible! */
    computeIdAtTime(sb,
		    TIME(NULL),
		    &curK);
    for (i=0;i<sqc->seenCount;i++)	  
      if (equalsHashCode160(&curK,
			    &sqc->seen[i])) {
      HashCode160 ns;      
      hash(&sb->subspace,
	   sizeof(PublicKey),
	   &ns);
      hash2enc(&ns,
	       &enc);
      guiMessage(_("Found the most recent version for a hit "
		   "in your original search in namespace '%s'."),
	         &enc);
      LOG(LOG_DEBUG, 
          _("Namespace result '%s' is the most recent.\n"),
	  &enc);
      return; /* found most up-to-date / all versions! */
    }
    /* else: start new parallel search! */
    LOG(LOG_DEBUG, 
	_("Starting parallel search for the latest version of '%s'\n"),
	&enc);
    startSearch(&sqc->n,
		&curK, 
		NULL);
    break;
  case NBLOCK_MAJOR_VERSION:
    addNamespace((const NBlock*) sb);
    verb = rootNodeToString((const RootNode*) sb);
    infoMessage(NO, 
		_("Found namespace description block:\n%s\n"),
		verb);
    FREE(verb);
  default:
    LOG(LOG_WARNING,
	_("Received reply of unsupported type %d in namespace search.\n"),
	ntohs(sb->major_formatVersion));
    break;    
  }
}

int searchSBlock_(NSSearchThreadData * sqc) {
  LOG(LOG_DEBUG, 
      "Entering function '%s'\n",
      __FUNCTION__);
  
  sqc->seen = NULL;
  sqc->seenCount = 0;
  sqc->results = NULL;
  sqc->resultCount = 0;
  sqc->model->SEARCH_socket_ = getClientSocket();
  if (sqc->model->SEARCH_socket_ != NULL) {
    searchSBlock(sqc->model->SEARCH_socket_,
		 &sqc->n,
		 &sqc->k,
		 (TestTerminateThread)&testTermination,
		 sqc->model,
		 (NSSearchResultCallback)&displayResultGTK_,
		 sqc);
  } else {
    LOG(LOG_DEBUG, 
        "Socket was NULL in %s.\n",
	__FUNCTION__);
  }
  GROW(sqc->seen,
       sqc->seenCount,
       0);
  GROW(sqc->results,
       sqc->resultCount,
       0);
  FREE(sqc);
  return 0;
}

/**
 * The main method of the search-thread.
 *
 * @param n namespace to search
 * @param k code to search for
 * @param model Data related to the search
 * @return OK on success, SYSERR on error
 */
static int startNamespaceSearchThread(HashCode160 * n,
				      HashCode160 * k,
				      ListModel * model) {
  NSSearchThreadData * sqc;

  sqc = MALLOC(sizeof(NSSearchThreadData));
  memcpy(&sqc->n,
	 n,
	 sizeof(HashCode160));
  memcpy(&sqc->k,
	 k,
	 sizeof(HashCode160));
  sqc->model = model;
  if (0 != PTHREAD_CREATE(&model->thread,
			  (PThreadMain) &searchSBlock_,
			  sqc,
			  16 * 1024)) 
    DIE_STRERROR("pthread_create");
  return OK;
}


/**
 * Start the namespace search.  This method obtains
 * n and k from the input window and then calls
 * the actual startSearch function.
 *
 * @param dummy not used
 * @param ewm the state of the search window
 */
static void searchNS(GtkWidget * dummy, 
		     NamespaceSearchWindowModel * ewm) {
  HashCode160 n;
  HashCode160 k;
  const char * c;

  c = gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(ewm->namespaceCombo)->entry));
  if (SYSERR == enc2hash(c, &n)) {
    NBlock * list;
    int cnt;
    int i;
    int found;
    
    found = NO;
    list = NULL;
    cnt = listNamespaces(&list);
    for (i=0;i<cnt;i++) {
      char * nick = getUniqueNickname(&list[i].namespace);
      if (0 == strcmp(nick, c)) {
	n = list[i].namespace;
	found = YES;
      }
    }
    FREENONNULL(list);
    if (found == NO) {
      guiMessage(_("You must specify a valid ENC code or nickname for the namespace.")); 
      return;
    }
  }
  c = gtk_entry_get_text(GTK_ENTRY(ewm->searchkeyLine));
  if ( (c == NULL) || (strlen(c) == 0)) {
    guiMessage(_("You must specify a non-empty string (or ENC code) for the search key.")); 
    return;
  }  
  if (SYSERR == enc2hash(c, &k))
    hash(c, strlen(c), &k);

  /* destroy the window */
  startSearch(&n, &k, c);
  gtk_widget_destroy(ewm->window);
}

/**
 * The user edited the namespace name.  Update descriptions 
 * accordingly.
 */
static void namespace_combo_changed(GtkWidget * unused,
				    NamespaceSearchWindowModel * ewm) {
  const char * nickname;
  HashCode160 ns;
  HashCode160 z;
  int i;
  int size;
  NBlock * list;
  char * desc;
  char * real;
  char * ur;
  char * cont;
  char * mm;
  char * rat;
  EncName enc;

  memset(&z, 0, sizeof(HashCode160));
  ns = z;
  nickname = gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(ewm->namespaceCombo)->entry));
  list = NULL;
  size = listNamespaces(&list);
  for (i=0;i<size;i++) {
    char * nick;

    nick = getUniqueNickname(&list[i].namespace);
    if (0 == strcmp(nick,
		    nickname)) {
      /* set all descriptions according to 'list[i]' */
      desc = STRNDUP(list[i].description, MAX_DESC_LEN);
      real = STRNDUP(list[i].nickname, MAX_NAME_LEN);
      ur = STRNDUP(list[i].uri, MAX_CONTACT_LEN);
      mm = STRNDUP(list[i].mimetype, MAX_MIMETYPE_LEN/2);
      cont = STRNDUP(list[i].contact, MAX_CONTACT_LEN);
      ns = list[i].rootEntry;
      rat = MALLOC(20);
      SNPRINTF(rat, 20, "%d", evaluateNamespace(&list[i].namespace,
						0));
      FREE(nick);
      break;
    }          
    FREE(nick);
  }
  if (i == size || size == -1) { /* not found */
    desc = STRDUP("");
    real = STRDUP("");
    ur = STRDUP("");
    mm = STRDUP("");
    cont = STRDUP("");
    rat = STRDUP("0");
  }
  FREENONNULL(list);
  hash2enc(&ns, &enc);
  /* set all descriptions */  
  gtk_label_set_text(GTK_LABEL(ewm->description),
		     desc);
  gtk_label_set_text(GTK_LABEL(ewm->realname),
		     real);
  gtk_label_set_text(GTK_LABEL(ewm->mimetype),
		     mm);
  gtk_label_set_text(GTK_LABEL(ewm->uri),
		     ur);
  gtk_label_set_text(GTK_LABEL(ewm->contact),
		     cont);
  gtk_label_set_text(GTK_LABEL(ewm->rating),
		     rat);  
  if (equalsHashCode160(&ns, &z))
    gtk_entry_set_text(GTK_ENTRY(ewm->searchkeyLine), 
		       "");
  else
    gtk_entry_set_text(GTK_ENTRY(ewm->searchkeyLine),
		       (const char*) &enc);

  FREE(desc);
  FREE(real);
  FREE(ur);
  FREE(mm);
  FREE(cont);
  FREE(rat);
}

/**
 * Open a window to allow the user to search a namespace
 *
 * TODO: 
 * - automatically set the content identifier to the
 *   root (if given) from the NBlock
 * - add an area in the dialog where the NBlock/namespace
 *   meta-data is displayed (if available) [update whenever
 *   the user changes the namespace ID]
 *
 * @param unused GTK handle that is not used
 * @param unused2 argument that is always 0
 */
void searchNamespace(GtkWidget * unused,
		     unsigned int unused2) {
  NamespaceSearchWindowModel * ewm;
  GtkWidget * window;
  GtkWidget * separator;
  GtkWidget * vbox;
  GtkWidget * hbox;
  GtkWidget * label;
  GtkWidget * button_ok;
  GtkWidget * button_cancel;
  GList * glist;
  NBlock * list;
  int ret;
  int i;

  ewm = MALLOC(sizeof(NamespaceSearchWindowModel));
  
  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  ewm->window = window;
  gtk_widget_set_usize(GTK_WIDGET(window),
		       650,
		       360);
  gtk_window_set_title(GTK_WINDOW(window), 
		       _("Search Namespace"));

  /* add container for window elements */
  vbox = gtk_vbox_new(FALSE, 10);
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
		     GTK_SIGNAL_FUNC(destroyNamespaceSearchWindow),
		     ewm);

  gtk_container_set_border_width(GTK_CONTAINER(window), 
				 10);


  /* Create a line to enter the namespace identifier */
  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     TRUE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  label = gtk_label_new(_("Namespace identifier:"));
  gtk_box_pack_start(GTK_BOX(hbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label); 

  ewm->namespaceCombo = gtk_combo_new();
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->namespaceCombo,
		     TRUE,
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(ewm->namespaceCombo)->entry), 
		     "");
  glist = NULL;
  glist = g_list_append(glist, 
			"");
  list = NULL;
  ret = listNamespaces(&list);

  for (i=0;i<ret;i++) {
    char * nick;

    nick = getUniqueNickname(&list[i].namespace);
    LOG(LOG_DEBUG, 
        "Appending namespace identifier '%s'.\n", 
        nick);
    glist = g_list_append(glist, 
 	 	          nick);
    /* FIXME: nick possibly not freed anywhere?
       But we can't free it here, must wait until
       dialog is closed? */
  }
  FREENONNULL(list);
  gtk_combo_set_popdown_strings(GTK_COMBO(ewm->namespaceCombo), 
				glist);
  gtk_signal_connect(GTK_OBJECT(GTK_COMBO(ewm->namespaceCombo)->entry),
		     "changed",
		     GTK_SIGNAL_FUNC(namespace_combo_changed),
		     ewm);
  gtk_widget_show(ewm->namespaceCombo);


  /* Create a line to enter the search key identifier */
  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     TRUE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  label = gtk_label_new(_("Search key identifier:"));
  gtk_box_pack_start(GTK_BOX(hbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label); 
  ewm->searchkeyLine = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->searchkeyLine,
		     TRUE,
		     TRUE,
		     0);
  gtk_entry_set_text(GTK_ENTRY(ewm->searchkeyLine), 
		     "");
  gtk_signal_connect(GTK_OBJECT(ewm->searchkeyLine),
                     "activate",
		     GTK_SIGNAL_FUNC(searchNS),
		     ewm);
  gtk_widget_show(ewm->searchkeyLine);
 
  /* namespace information */
 
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
		     TRUE,
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
  ewm->description = gtk_label_new("");
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->description, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(ewm->description); 



  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     TRUE,
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
  ewm->realname = gtk_label_new("");
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->realname, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(ewm->realname); 


  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     TRUE,
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
  ewm->mimetype = gtk_label_new("");
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->mimetype, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(ewm->mimetype); 


  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     TRUE,
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
  ewm->uri = gtk_label_new("");
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->uri, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(ewm->uri); 


  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     TRUE,
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
  ewm->contact = gtk_label_new("");
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->contact, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(ewm->contact); 


  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox,
		     TRUE,
		     TRUE,
		     0);
  gtk_widget_show(hbox);
  label = gtk_label_new(_("Rating:"));
  gtk_box_pack_start(GTK_BOX(hbox),
		     label, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(label); 
  ewm->rating = gtk_label_new("0");
  gtk_box_pack_start(GTK_BOX(hbox),
		     ewm->rating, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(ewm->rating); 

  /* end namespace information */
 
  separator = gtk_hseparator_new();
  gtk_box_pack_start(GTK_BOX(vbox),
		     separator,
		     TRUE, 
		     TRUE,
		     0);
  gtk_widget_show(separator);



  /* add the ok/cancel buttons */

  hbox = gtk_hbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox),
		     hbox, 
		     FALSE, 
		     FALSE, 
		     0);
  gtk_widget_show(hbox);
  button_ok = gtk_button_new_with_label(_("Search"));
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
		     GTK_SIGNAL_FUNC(searchNS),
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


/* end of namespace.c */
