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
 * @file applications/afs/gtkui/helper.h
 * @author Igor Wronsky 
 */

#ifndef GTKUI_HELPER_H
#define GTKUI_HELPER_H


#include "platform.h"

/* for GTK 2 */
#define GTK_ENABLE_BROKEN

#include <gtk/gtk.h>
#include <gtk/gtktext.h>

typedef struct {
  Semaphore *sem;
  void *args;
  GtkFunction func;
} SaveCall;

typedef struct {
  int doPopup;
  gchar *note;
} InfoMessage;      

typedef struct {
  const char *labelName;
  GtkWidget *frame;
} AddNotebook;


/* callback: window close: close the window */
gint deleteEvent(GtkWidget * widget,
		 GdkEvent * event,
		 gpointer data);

/**
 * A callback to destroy any widget given as second argument
 *
 */
void destroyWidget(GtkWidget * dummy, GtkWidget * widget);

/**
 * Displays an informative message to the user
 */
void guiMessage(const char * format, ...);

/**
 * Appends a message to the info window 
 */
void infoMessage(int doPopup, const char * format, ...);

/** 
 * Appends a log entry to the info window
 *
 * @param txt the log entry
 *
 */
void addLogEntry(const char *txt);

void addToNotebook(const char * labelName,
		   GtkWidget * frame);

void hideWindow(GtkWidget * widget,
		gpointer data);

void showStats(GtkWidget * widget,
	       gpointer data);

int checkForDaemon(void);

void cronCheckDaemon(void * dummy);
void launchDaemon(GtkWidget * widget,
  		  gpointer data);
void killDaemon(GtkWidget * widget,
	        gpointer data);

/**
 * A function for numeric comparisons of strings
 */
gint numericComp(GtkCList *clist,
                 gconstpointer ptr1,
                 gconstpointer ptr2);

/**
 * A function for case-insensitive text comparisons
 */
gint alphaComp(GtkCList *clist,
               gconstpointer ptr1,
               gconstpointer ptr2);

/**
 * A function for comparisons of percentages
 */
gint percentComp(GtkCList *clist,
                 gconstpointer ptr1,
                 gconstpointer ptr2);

/**
 * A general right-button popup menu callback
 */
gboolean popupCallback(GtkWidget *widget,
                       GdkEvent *event,
		                   GtkWidget *menu );
		       
/**
 * Call a callback function from the mainloop/main thread ("SaveCall").
 * Since GTK doesn't work with multi-threaded applications under Windows,
 * all GTK operations have to be done in the main thread
 */
void gtkSaveCall(GtkFunction func, void *args);

/**
 * Initialize "SaveCalls"
 */
void gtkInitSaveCalls();

void gtkDoneSaveCalls();

int gtkRunSomeSaveCalls();
 
/**
 * Called from a "SaveCall"-function to indicate that it is done
 */
void gtkSaveCallDone(Semaphore *sem);

/**
 * Destroy a widget. Called from threads other than the main thread
 */
gint doDestroyWidget(SaveCall *call);

extern GtkNotebook * notebook;
extern GtkWidget * infoWindow;

#endif
