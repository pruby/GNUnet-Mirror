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
 * @file src/applications/afs/gtkui/helper.c
 * @brief This file contains some GUI helper functions
 * @author Igor Wronsky
 */

#include "gnunet_afs_esed2.h"
#include "helper.h"
#include <stdlib.h>
#ifndef MINGW
 #include <sys/wait.h>
#endif
#include "main.h"

#define HELPER_DEBUG NO

GtkWidget * infoWindow = NULL;
static GtkWidget * infoText = NULL;

/* are we waiting for gnunetd to start? */
static int pollForLaunch = FALSE;

/* the main thread */
static PTHREAD_T mainThread;



static SaveCall ** psc;
static unsigned int pscCount;
static Mutex sclock;

/**
 * Call a callback function from the mainloop/main thread ("SaveCall").
 * Since GTK doesn't work with multi-threaded applications under Windows,
 * all GTK operations have to be done in the main thread
 */
void gtkSaveCall(GtkFunction func, void *args) {
  SaveCall call;
  int i;

  call.args = args;
  call.func = func;
  MUTEX_LOCK(&sclock);
  if (! PTHREAD_SELF_TEST(&mainThread)) {
    call.sem = SEMAPHORE_NEW(0);
    GROW(psc,
	 pscCount,
	 pscCount+1);
    psc[pscCount-1] = &call;
    MUTEX_UNLOCK(&sclock);
    gtk_idle_add(func, &call);
    SEMAPHORE_DOWN(call.sem);
    /* remove from psc list */
    MUTEX_LOCK(&sclock);
    for (i=0;i<pscCount;i++)
      if (psc[i] == &call) {
	psc[i] = psc[pscCount-1];
	break;
      }
    GNUNET_ASSERT(i != pscCount);
    GROW(psc,
	 pscCount,
	 pscCount-1);
    MUTEX_UNLOCK(&sclock);
    SEMAPHORE_FREE(call.sem);
  } else {
    MUTEX_UNLOCK(&sclock);
    call.sem = NULL;
    func(&call);
  }
}

/**
 * Initialize "SaveCalls"
 */
void gtkInitSaveCalls() {
  MUTEX_CREATE_RECURSIVE(&sclock);
  PTHREAD_GET_SELF(&mainThread);
}

int gtkRunSomeSaveCalls() {
  int i;

  if (! PTHREAD_SELF_TEST(&mainThread))
    return NO;
  MUTEX_LOCK(&sclock);
  if (pscCount == 0) {
    MUTEX_UNLOCK(&sclock);
    return NULL;
  }
  i = randomi(pscCount);
  if (TRUE == g_idle_remove_by_data(psc[i]))
    psc[i]->func(psc[i]);
  MUTEX_UNLOCK(&sclock);
  gnunet_util_sleep(50 * cronMILLIS);
  /* sleep here is somewhat important, first of
     all, after completion we need to give the
     semaphore-mechanism time to remove the save-call
     from the list to avoid running it twice; 
     also, this function might be called in a tight
     loop (see search.c), so we should give the
     other threads some time to run.  */

  return YES;
}

void gtkDoneSaveCalls() {
  int i;
  PTHREAD_REL_SELF(&mainThread);
  MUTEX_LOCK(&sclock);
  for (i=0;i<pscCount;i++) 
    psc[i]->func(psc[i]);
  i = pscCount;
  MUTEX_UNLOCK(&sclock);  
  /* wait until all PSC-jobs have left
     the gtkSaveCall method before destroying
     the mutex! */
  while (i != 0) {
    gnunet_util_sleep(50 * cronMILLIS);    
    MUTEX_LOCK(&sclock);
    i = pscCount;
    MUTEX_UNLOCK(&sclock);
  }
  MUTEX_DESTROY(&sclock);
}


/**
 * Called from a "SaveCall"-function to indicate that it is done
 */
void gtkSaveCallDone(Semaphore *sem) {
  if (sem)
    SEMAPHORE_UP(sem);
}

/**
 * Destroy a widget. Called from threads other than the main thread
 */
gint doDestroyWidget(SaveCall *call) {
  gtk_widget_destroy((GtkWidget *) call->args);

  gtkSaveCallDone(call->sem);

  return FALSE;
}

/**
 * Callback for handling "delete_event": close the window 
 */
gint deleteEvent(GtkWidget * widget,
		 GdkEvent * event,
		 gpointer data) {
#if DEBUG_HELPER
  LOG(LOG_DEBUG, 
      "In '%s'.\n",
      __FUNCTION__);
#endif
  return FALSE;
}

/**
 * A callback to destroy any widget given as second argument
 */
void destroyWidget(GtkWidget * dummy, 
		   GtkWidget * widget) {
#if DEBUG_HELPER
  LOG(LOG_DEBUG, 
      "In '%s' of %p.\n", 
      __FUNCTION__,
      widget);
#endif
  gtk_widget_destroy(widget);
}

/**
 * Callback function for guiMessage()
 */
gint doGuiMessage(SaveCall *call) {
  GtkWidget * window;
  GtkWidget * label;
  GtkWidget * box;
  GtkWidget * button;

  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_container_set_border_width(GTK_CONTAINER(window), 10);
  gtk_window_set_title(GTK_WINDOW(window), 
		       _("Notification"));
  gtk_signal_connect(GTK_OBJECT(window), 
		     "delete_event",
		     GTK_SIGNAL_FUNC(deleteEvent), 
		     NULL);

  box = gtk_vbox_new(FALSE, 0);
  gtk_container_add(GTK_CONTAINER(window), 
		    box);

  label = gtk_label_new((gchar *) call->args);
  free((gchar *) call->args); /* allocated in g_strdup_vprintf */
  gtk_box_pack_start(GTK_BOX(box),
		     label,
		     FALSE,
		     FALSE,
		     0);
  
  button = gtk_button_new_with_label(_("Ok"));
  gtk_signal_connect(GTK_OBJECT (button),
		      "clicked",
		      GTK_SIGNAL_FUNC(destroyWidget),
		     window);
  gtk_box_pack_start(GTK_BOX(box),button,FALSE,FALSE,0);
  
  gtk_window_set_position(GTK_WINDOW(window),
			  GTK_WIN_POS_MOUSE);
  gtk_widget_show_all(window);
  gtk_widget_grab_focus(button);
  
  gtkSaveCallDone(call->sem);

  return FALSE;
}

/** 
 * Displays an informative message to the user in a fresh window 
 */
void guiMessage(const char * format, ...) {
  va_list args;
  gchar *note;

  va_start(args, format);
  note = g_strdup_vprintf(format, args);
  va_end(args);
  
  gtkSaveCall((GtkFunction) doGuiMessage, note);
}

/**
 * Callback for infoMessage()
 */
gint doInfoMessage(SaveCall *call) {
  GtkTextIter iter;
  GtkTextBuffer * buffer;

  if(!infoWindow) {
    GtkWidget * box1;
    GtkWidget * button;
    GtkWidget * scrolled_window;

    infoWindow = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_signal_connect(GTK_OBJECT(infoWindow),
                       "delete_event",
                       GTK_SIGNAL_FUNC(deleteEvent),
                       NULL);

    gtk_window_set_title(GTK_WINDOW(infoWindow),
                         _("Messages"));
    gtk_widget_set_usize(GTK_WIDGET(infoWindow),
                         780,
                         300);

    box1 = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER (infoWindow),
                      box1);
    gtk_widget_show(box1);
    
    /* create a scrollable window */
    scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
    				   GTK_POLICY_AUTOMATIC,
				   GTK_POLICY_ALWAYS);
    gtk_box_pack_start(GTK_BOX(box1),
    		       scrolled_window,
		       TRUE,
		       TRUE,
		       0);
    gtk_widget_show(scrolled_window);

    /* create a text widget */
    infoText = gtk_text_view_new();
    
    gtk_text_view_set_editable(GTK_TEXT_VIEW (infoText),
                          FALSE);
    gtk_container_add(GTK_CONTAINER(scrolled_window),
    		      infoText);
    gtk_widget_show(infoText);
    gtk_widget_realize(infoText);
  
    /* finish with a close button */
    button = gtk_button_new_with_label(_("Close"));
    gtk_box_pack_start(GTK_BOX (box1),
                       button,
                       FALSE,
                       FALSE,
                       0);
    gtk_signal_connect_object(GTK_OBJECT(button),
                              "clicked",
                              GTK_SIGNAL_FUNC(hideWindow),
                              GTK_OBJECT(infoWindow));
    gtk_signal_connect_object(GTK_OBJECT(infoWindow), 
			      "delete_event",
                              GTK_SIGNAL_FUNC(hideWindow),
                              GTK_OBJECT(infoWindow));
    gtk_signal_connect_object(GTK_OBJECT(infoWindow), 
			      "destroy",
                              GTK_SIGNAL_FUNC(hideWindow),
                              GTK_OBJECT(infoWindow));
    gtk_widget_show(button);
  }
  if(((InfoMessage *) call->args)->doPopup==YES)
    gtk_widget_show(infoWindow);

  /* append the text */
  buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW (infoText));
  gtk_text_buffer_get_iter_at_offset(buffer, &iter, -1);
  gtk_text_buffer_insert(buffer,
			 &iter,
			 ((InfoMessage *) call->args)->note, 
			 -1);

  gtkSaveCallDone(call->sem);

  return FALSE;
}

/** 
 * Appends a message to the info window
 *
 * @param doPopup do we open the window, YES or NO
 *
 */
void infoMessage(int doPopup, const char * format, ...) {
  va_list args;
  InfoMessage info;

  va_start(args, format);
  info.note = g_strdup_vprintf(format, args);
  va_end(args);
  info.doPopup = doPopup;
  gtkSaveCall((GtkFunction) doInfoMessage, &info);
  g_free(info.note);
}

/** 
 * Appends a log entry to the info window
 *
 * @param txt the log entry
 *
 */
void addLogEntry(const char *txt) {
  infoMessage(NO, txt);
}

GtkNotebook * notebook = NULL;

gint doAddToNotebook(SaveCall *call) {
  GtkWidget * label = gtk_label_new(((AddNotebook *) call->args)->labelName);
  gtk_notebook_append_page(notebook, 
			   ((AddNotebook *) call->args)->frame, 
			   label);
  gtk_widget_show(((AddNotebook *) call->args)->frame);  
  
  gtkSaveCallDone(call->sem);
  
  return FALSE;
}

void addToNotebook(const char * labelName,
		   GtkWidget * frame) {
  AddNotebook note;
  
  note.labelName = labelName;
  note.frame = frame;
  /* add a new notebook for the search results */
  gtkSaveCall((GtkFunction) doAddToNotebook, &note);
}

void hideWindow(GtkWidget * widget,
		gpointer data) {
  if(widget)
    gtk_widget_hide(widget);
}

/**
 * A dirty way to pump some stats from gnunetd
 */
void showStats(GtkWidget * widget,
	       gpointer data) {
  FILE *fp;
  char * ptr;
  char buffer[512];
  char fn[512];
  char * cfgFile;
  GtkWidget * window;
  GtkWidget * scrolled_window;
  GtkWidget * clist;
  GtkWidget * vbox;
  GtkWidget * button;
  gchar * results[2];
  static gchar * descriptions[] = {
    gettext_noop("Statistic"),
    gettext_noop("Value"),
  };
  static int widths[] = {
    600, 70
  };
  int i;

  /* create window etc */
  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(window),
  		       _("gnunetd statistics"));
  gtk_widget_set_usize(GTK_WIDGET(window),
  		       780,
		       300);
  vbox = gtk_vbox_new(FALSE, 1);
  gtk_container_add(GTK_CONTAINER(window), vbox);

  scrolled_window = gtk_scrolled_window_new(NULL,NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
  				 GTK_POLICY_AUTOMATIC,
				 GTK_POLICY_ALWAYS);
  gtk_box_pack_start(GTK_BOX(vbox),
  		     scrolled_window,
		     TRUE,
		     TRUE,
		     0);

  clist = gtk_clist_new_with_titles(2, descriptions);
  for(i=0;i<2;i++)
    gtk_clist_set_column_width(GTK_CLIST(clist),
    			       i,
			       widths[i]);
  gtk_clist_set_column_justification(GTK_CLIST(clist),
  				     1,
				     GTK_JUSTIFY_RIGHT);
  gtk_container_add(GTK_CONTAINER(scrolled_window),
  		    clist);

  button = gtk_button_new_with_label(_("Close"));
  gtk_signal_connect(GTK_OBJECT(button),
  		     "clicked",
		     GTK_SIGNAL_FUNC(destroyWidget),
		     window);
  gtk_box_pack_start(GTK_BOX(vbox),
  		     button,
  		     FALSE,
		     FALSE,
		     0);

  gtk_clist_freeze(GTK_CLIST(clist));

  /* Poll for statistics */
  /* FIXME: done with a kludge until someone bothers to
   * use gnunet-stats code */

  SNPRINTF(fn,
	   512,
	   "/tmp/gnunet-gtk_stats.XXXXXX");
  mkstemp(fn);

#ifdef MINGW
  {
    char *winfn = MALLOC(_MAX_PATH + 1);
    conv_to_win_path(fn, winfn);
    strcpy(fn, winfn);
    FREE(winfn);
  }
#endif

  cfgFile = getConfigurationString("FILES",
  				   "gnunet.conf");
  if(cfgFile == NULL) {
    BREAK();
    cfgFile = STRDUP(DEFAULT_CLIENT_CONFIG_FILE);
  }

#ifdef MINGW
  CHDIR("/bin");
#endif

  SNPRINTF(buffer, 
	   512,
	   "gnunet-stats -c \"%s\" >%s",
	   cfgFile,
	   fn);
  system(buffer);
  FREE(cfgFile);
  fp=FOPEN(fn, "r");
  if(!fp) {
    gtk_widget_destroy(window);
    guiMessage(_("Error reading '%s' output from file '%s'.\n"),
	       "gnunet-stats",
    	       fn);
    LOG_FILE_STRERROR(LOG_ERROR, "open", fn);
    return;
  }
  while(!feof(fp)) {
    fgets(buffer, 512, fp);
    if(buffer[0]==0 || buffer[0]=='\n' || feof(fp))
      continue;
    ptr = buffer;
    while(*ptr!=':') ptr++;
    *ptr=0;
    ptr++;
    while(*ptr==' ') ptr++;
    results[0]=buffer;
    results[1]=ptr;
    
    /* remove CR/LF */
    while(*ptr != '\n') ptr++;
    *ptr = 0;
    if(*(ptr-1) == '\r') *(ptr-1) = 0;
    
    gtk_clist_append(GTK_CLIST(clist),
    		     results);
  }
  fclose(fp);
  UNLINK(fn);
  
  gtk_clist_thaw(GTK_CLIST(clist));
  
  gtk_widget_show_all(window);
}

/** 
 * Checks if gnunetd is running
 * 
 * NOTE: Uses CS_PROTO_CLIENT_COUNT query to determine if 
 * gnunetd is running
 */
static int checkDaemonRunning(void) {
  GNUNET_TCP_SOCKET * sock;
  CS_HEADER csHdr;
  int ret;

  sock = getClientSocket();
  if(sock == NULL) {
    BREAK();
    return SYSERR;  
  }    

  csHdr.size
    = htons(sizeof(CS_HEADER));
  csHdr.type
    = htons(CS_PROTO_CLIENT_COUNT);
  if (SYSERR == writeToSocket(sock,
                              &csHdr)) {
    LOG(LOG_DEBUG, 
	_("gnunetd is NOT running.\n"));
    releaseClientSocket(sock);
    return SYSERR;
  } 
  if (SYSERR == readTCPResult(sock, 
  			      &ret)) {
    BREAK();
    releaseClientSocket(sock);
    return SYSERR;
  }
  releaseClientSocket(sock);
  
  return OK;
}

#if LINUX || OSX || SOLARIS || SOMEBSD
static int launchWithExec() {
  pid_t pid;

  pid = fork();
  if (pid == 0) {
    char * args[4];
    char * path;
    char * cp;

    path = NULL;
    cp = getConfigurationString("MAIN", 
				"ARGV[0]");
    if (cp != NULL) {
      int i = strlen(cp);
      while ( (i >= 0) && 
	      (cp[i] != DIR_SEPARATOR) )
	i--;
      if ( i != -1 ) {
	cp[i+1] = '\0';
	path = MALLOC(i+1+strlen("gnunetd"));
	strcpy(path, cp);
	strcat(path, "gnunetd");      
	args[0] = path;
	FREE(cp);
      } else {
	args[0] = "gnunetd";
      }
    }
    cp = getConfigurationString("GNUNET-GTK",
				"GNUNETD-CONFIG");
    if (cp != NULL) {
      args[1] = "-c";
      args[2] = cp;
    } else {
      args[1] = NULL;
    }
    args[3] = NULL;
    errno = 0;
    nice(10); /* return value is not well-defined */
    if (errno != 0) 
      LOG_STRERROR(LOG_WARNING, "nice");    
    if (path != NULL)
      execv(path,
	    args);
    else
      execvp("gnunetd",
	     args);
    LOG_STRERROR(LOG_FAILURE, "exec");
    LOG(LOG_FAILURE,
	_("Attempted path to '%s' was '%s'.\n"),
	"gnunetd",
	(path == NULL) ? "gnunetd" : path);
    FREENONNULL(path); /* yeah, right, like we're likely to get
			  here... */
    FREENONNULL(args[1]);
    _exit(-1);
  } else {
    pid_t ret;
    int status;

    ret = waitpid(pid, &status, 0);
    if (ret == -1) {
      LOG_STRERROR(LOG_ERROR, "waitpid");
      return SYSERR;
    }
    if ( (WIFEXITED(status) &&
	  (0 != WEXITSTATUS(status)) ) ) {
      guiMessage(_("Starting gnunetd failed, error code: %d"),
		 WEXITSTATUS(status));
      return SYSERR;
    }
#ifdef WCOREDUMP
    if (WCOREDUMP(status)) {
      guiMessage(_("Starting gnunetd failed (core dumped)."));
      return SYSERR;
    }
#endif
    if (WIFSIGNALED(status) ||
	WTERMSIG(status) ) {
      guiMessage(_("Starting gnunetd failed (aborted by signal)."));
      return SYSERR;
    }
    return OK;
  }
}
#endif

static int doLaunch() {
  
#if LINUX || OSX || SOLARIS || SOMEBSD
  return launchWithExec();
#elif MINGW
  char szCall[_MAX_PATH + 1], szWd[_MAX_PATH + 1], szCWd[_MAX_PATH + 1];
  char *args[1];

  conv_to_win_path("/bin/gnunetd.exe", szCall);
  conv_to_win_path("/bin", szWd);
  _getcwd(szCWd, _MAX_PATH);

  chdir(szWd);
  args[0] = NULL;
  spawnvp(_P_NOWAIT, szCall, (const char *const *) args);
  chdir(szCWd);
  
  return OK;
#else
  /* any system out there that does not support THIS!? */
  system("gnunetd"); /* we may not have nice,
			so let's be minimalistic here. */
  return OK;
#endif  
}

/** 
 * Launch gnunetd, don't check if its running
 */
static void launchDaemonNoCheck(GtkWidget * widget,
				gpointer data) {
  /* sanity checks, not critical for ports */
  char * host = getConfigurationString("NETWORK",
				       "HOST");
  if (host != NULL) {
    if (0 != strcmp(host,
		    "localhost")) {
      char * hostname;
      hostname = MALLOC(1024);
      if (0 != gethostname(hostname, 1024)) {
	LOG_STRERROR(LOG_ERROR, "gethostname");
      } else {
	/* we could go crazy here and try to open a socket locally
	   and then attempt to connect to it using the NS lookup result
	   for "host" -- and do it for IPv4 and IPv6 and possibly still
	   be wrong due some crazy firewall configuration.  Or we can
	   just do the simpelst thing (strcmp) and expect the user to
	   fix it if he cares to have the warning go away... */
	if (0 != strcmp(host,
			hostname)) {
	  guiMessage("gnunetd is configured to run on host '%s' and\n"
		     "gnunet-gtk is running on host '%s', which seems to be a different machine.\n"
		     "gnunet-gtk can only start gnunetd on host '%s'.\n"
		     "This may not be what you want (it may not work).\n"
		     "I will proceed anyway, good luck.",
		     host,
		     hostname,
		     hostname);
	}	  
      }
      FREE(hostname);
    }
    FREE(host);
  }
  /* end of sanity checks */
  doLaunch();
  pollForLaunch = TRUE;
  gtk_widget_destroy(GTK_WIDGET(data));
}

/** 
 * Launch gnunetd w/ checks
 */
void launchDaemon(GtkWidget * widget,
 	          gpointer data) {
  if (OK == checkDaemonRunning() ) {
    guiMessage(_("gnunetd is already running"));
    return;
  } else {					
    doLaunch();
    pollForLaunch = TRUE;
  }
}

/** 
 * Kill gnunetd
 */
void killDaemon(GtkWidget * widget,
 	        gpointer data) {
  if (OK == checkDaemonRunning() ) {
    GNUNET_TCP_SOCKET * sock;
    CS_HEADER csHdr;
    int ret;

    sock = getClientSocket();
    if (sock == NULL) {
      /* well, probably already dead */
      return;
    }
    csHdr.size 
      = htons(sizeof(CS_HEADER));
    csHdr.type
      = htons(CS_PROTO_SHUTDOWN_REQUEST);
    if (SYSERR == writeToSocket(sock,
    				&csHdr)) {
      guiMessage(_("Error sending shutdown request to gnunetd."));
      releaseClientSocket(sock);
      return;
    }
    if (SYSERR == readTCPResult(sock,
    				&ret)) {
      guiMessage(_("Error reading shutdown confirmation from gnunetd."));
      releaseClientSocket(sock);
      return;
    }
    if (ret == OK)
      guiMessage(_("gnunetd agreed to shut down."));
    else
      guiMessage(_("gnunetd refused to shut down (error code '%d')."), 
                 ret);
    releaseClientSocket(sock);
  } else {
    guiMessage(_("gnunetd is not running."));
  }
}

/**
 * Ask if the user wishes to start gnunetd
 */
static void initDaemonStartDialog(void) {
   GtkWidget *dialog;
   GtkWidget *label;
   GtkWidget *okay_button;
   GtkWidget *no_button;

   dialog = gtk_dialog_new();
   label = gtk_label_new(_("gnunetd (daemon) doesn't seem to be running.\nWould you like to start it?\n"));
   gtk_container_add (GTK_CONTAINER(GTK_DIALOG(dialog)->vbox),
                      label);

   okay_button = gtk_button_new_with_label(_("Yes!"));
   no_button = gtk_button_new_with_label(_("No."));
   
   gtk_signal_connect(GTK_OBJECT(okay_button), 
                      "clicked",
                      GTK_SIGNAL_FUNC(launchDaemonNoCheck), 
		      dialog);
   gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->action_area),
                      okay_button);
   gtk_signal_connect(GTK_OBJECT(no_button), 
		      "clicked",
                      GTK_SIGNAL_FUNC(destroyWidget), 
                      dialog);
   gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->action_area),
                      no_button);

   gtk_widget_show_all(dialog);
}

/**
 * Checks if gnunetd is running and if not, prompts user 
 * to run gnunetd. Always returns OK.
 */
int checkForDaemon(void) {  
  if (SYSERR == checkDaemonRunning()) {
    char * host;

    host = getConfigurationString("NETWORK",
      	  		  	  "HOST");
    if (host != NULL && strcmp(host,
			       "localhost")==0 )
      initDaemonStartDialog();
    else
      guiMessage(_("gnunetd does not seem to be running.\n"
		   "Unfortunately, gnunet-gtk cannot identify config entry"
		   "\n\nNETWORK/HOST '%s'\n\n"
		   "as a local machine, so gnunetd cannot be\n"
		   "launched by gnunet-gtk."),
		 (host == NULL ? "" : host) );
  }

  return OK;
}

static gint doUpdateMenus(SaveCall * call) {
  static GtkWidget * killEntry = NULL;
  static GtkWidget * launchEntry = NULL;
  static GtkWidget * statsEntry = NULL;
  static int once = 1;
  static int isLocal;
  char * host;
  int ret;

  ret = * (int*) call->args;
  if (once) {
    once = 0;
    killEntry = gtk_item_factory_get_widget(itemFactory,
					    "/Advanced/"
					    "Kill gnunetd");
    launchEntry = gtk_item_factory_get_widget(itemFactory,
					      "/Advanced/"
					      "Launch gnunetd");
    statsEntry = gtk_item_factory_get_widget(itemFactory,
					     "/File/"
					     "Show gnunetd stats");    
    host = getConfigurationString("NETWORK",
				  "HOST");
    if ( (host == NULL) ||
	 (strcmp(host, "localhost")==0) )
      isLocal = TRUE;
    else
      isLocal = FALSE;
    FREENONNULL(host);
  }
  if (ret == SYSERR) {
    gtk_widget_set_sensitive(statsEntry, FALSE);
    gtk_widget_set_sensitive(killEntry, FALSE);
    gtk_widget_set_sensitive(launchEntry, (TRUE & isLocal) );
  } else {
    gtk_widget_set_sensitive(statsEntry, TRUE);
    gtk_widget_set_sensitive(killEntry, TRUE);
    gtk_widget_set_sensitive(launchEntry, FALSE);
    
    if (pollForLaunch == TRUE) {
      pollForLaunch = FALSE;
      guiMessage(_("gnunetd is now running."));
    }
  }    
  gtkSaveCallDone(call->sem);
  return FALSE;
}

void cronCheckDaemon(void * dummy) {
  static int last = 42;
  int ret;
  
  ret = checkDaemonRunning();
  if (ret != last) {
    last = ret;    
    gtkSaveCall((GtkFunction) doUpdateMenus, &ret);
  }      
}


/**
 * A function for numeric comparisons of strings
 */
gint numericComp(GtkCList *clist,
                 gconstpointer ptr1,
                 gconstpointer ptr2) {
  double value1;
  double value2;
  GtkCListRow * row1 = (GtkCListRow *) ptr1;
  GtkCListRow * row2 = (GtkCListRow *) ptr2;

  value1 = atof(GTK_CELL_TEXT(row1->cell[clist->sort_column])->text);
  value2 = atof(GTK_CELL_TEXT(row2->cell[clist->sort_column])->text);

  if(value1>value2)
    return(-1);
  else if(value1==value2)
    return(0);
  else
    return(1);
}

/**
 * A function for case-insensitive text comparisons
 */
gint alphaComp(GtkCList *clist,
               gconstpointer ptr1,
               gconstpointer ptr2) {
  char * text1;
  char * text2;
  GtkCListRow * row1 = (GtkCListRow *) ptr1;
  GtkCListRow * row2 = (GtkCListRow *) ptr2;

  text1 = GTK_CELL_TEXT(row1->cell[clist->sort_column])->text;
  text2 = GTK_CELL_TEXT(row2->cell[clist->sort_column])->text;

  return (strcasecmp(text1,text2));
}

/**
 * A function for percentage comparisons 
 */
gint percentComp(GtkCList *clist,
                 gconstpointer ptr1,
                 gconstpointer ptr2) {
  char * tmp1;
  char * tmp2;
  double value1;
  double value2;
  GtkCListRow * row1 = (GtkCListRow *) ptr1;
  GtkCListRow * row2 = (GtkCListRow *) ptr2;

  tmp1 = GTK_CELL_TEXT(row1->cell[clist->sort_column])->text;
  tmp2 = GTK_CELL_TEXT(row2->cell[clist->sort_column])->text;

  /* Hack for DONE strings :) */
  if(strstr(tmp1,"%") == 0) {
    if(strstr(tmp2,"%") == 0)
      return 0;	/* Both "DONE" */
    else
      return -1; /* A done, B not */
  }
  if(strstr(tmp2,"%")==0) 
    return 1; /* B done, A not */

  /* Both have %, must remove */
  tmp1 = STRDUP(GTK_CELL_TEXT(row1->cell[clist->sort_column])->text);
  tmp2 = STRDUP(GTK_CELL_TEXT(row2->cell[clist->sort_column])->text);
 
  tmp1[strlen(tmp1)-1]=0;
  tmp2[strlen(tmp2)-1]=0;
  
  value1 = atof(tmp1);
  value2 = atof(tmp2);

  FREE(tmp1);
  FREE(tmp2);

  if(value1>value2)
    return(-1);
  else if(value1==value2)
    return(0);
  else
    return(1);
}

/**
 * A general right-button popup menu callback
 */
gboolean popupCallback(GtkWidget *widget,
                       GdkEvent *event,
                       GtkWidget *menu )
{
   GdkEventButton *bevent = (GdkEventButton *)event;

#if HELPER_DEBUG 
   fprintf(stderr, "popupc\n");
#endif

   /* Only take button presses */
   if (event->type != GDK_BUTTON_PRESS)
     return FALSE;

   if (bevent->button != 3)
     return FALSE;

   /* Show the menu */
   gtk_widget_show(menu);
   gtk_menu_popup (GTK_MENU(menu), NULL, NULL,
                   NULL, NULL, bevent->button, bevent->time);

   return TRUE;
}

/* end of helper.c */
