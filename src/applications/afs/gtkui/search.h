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
 * @file applications/afs/gtkui/search.h
 * @author Christian Grothoff
 **/

#ifndef GTKUI_SEARCH_H
#define GTKUI_SEARCH_H

/**
 * Data for a search process
 **/
typedef struct {
  int type;
  GtkWidget * search_result_list;  
  int doTerminate;
  GNUNET_TCP_SOCKET * SEARCH_socket_;
  PTHREAD_T thread; /* search thread */
  int skipMenuRefresh; /* don't refresh gtk menus (its slow)? (YES/NO) */
  Semaphore * sem; /* shutdown signaling */
} ListModel;

typedef struct {
  GtkWidget *search_result_list;
  RootNode *rootCopy;
  gchar * results[7];
} Result;

typedef struct {
  ListModel *model;
  GtkWidget *ret;
} InitResultList;

#define LM_TYPE_SEARCH 1
#define LM_TYPE_DIRECTORY 2
#define LM_TYPE_NSSEARCH 3

/**
 * Get the window with the search results.
 **/
GtkWidget * getSearchWindow(gchar * searchString);

GtkWidget * initializeSearchResultList(ListModel * model);

/**
 * Should the receive thread abort? (has the window been closed?)
 * This is a callback for the receiveResults method (since
 * not every "error" on the socket corresponds to a closed
 * window!).
 *
 * @return YES if we should abort
 **/
int testTermination(ListModel * model);

/**
 * Display results.  This is a callback from receiveResults that is
 * called on every new result.
 *
 * @param rootNode Data about a file
 * @param model Data related to the search
 **/
void displayResultGTK(RootNode * rootNode,
		      ListModel * model);
 
/**
 * Some search list row has been unselected
 **/
void unselect_row_callbackGTK(GtkWidget *widget,
			      gint row,
			      gint column,
			      GdkEventButton *event,
			      gpointer data);

/**
 * User has selected some search list row
 **/
void select_row_callbackGTK(GtkWidget *widget,
			    gint row,
			    gint column,
			    GdkEventButton *event,
			    gpointer data);

#endif
