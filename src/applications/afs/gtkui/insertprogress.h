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
 * @file applications/afs/gtkui/insertprogress.h
 * @author Christian Grothoff
 **/

#ifndef GTKUI_INSERT_PROGRESS_H
#define GTKUI_INSERT_PROGRESS_H

#include "platform.h"
#include <gtk/gtk.h>

/**
 * @brief state associated with an insertion
 **/
typedef struct {
  char * fileName;
  char * fileNameRoot;
  char * description;
  char * mimetype;
  char ** keywords;
  int num_keywords;
  char opDescription[32];		/* used in progressBar */
  int indexContent;
  int copyFile;
  GtkWidget * progressBar;
  GtkWidget * progressBarWindow;
  int deleteAfterInsert;
} InsertModel;

/**
 * @brief state associated with an insertion
 **/
typedef struct {
  char * fileName;
  char * fileNameRoot;
  char * description;
  char * mimetype;
  char ** keywords;
  int num_keywords;
  char opDescription[32];		/* used in progressBar */
  int indexContent;
  int copyFile;
  GtkWidget * progressBar;
  GtkWidget * progressBarWindow;
  int deleteAfterInsert;
  char ** gkeywords;
  int num_gkeywords;
  GtkObject * adjustment;
  GtkObject * adjustment2;
  GtkWidget * progressBar2;
  unsigned long long pos;
} InsertDirectoryModel;

/**
 * Main function of the insert thread.  Does the
 * actual insertion.
 *
 * @param ilm Collected data related to the insertion
 */
void insertFileGtkThread(InsertModel * ilm);


/**
 * A function to be run by the insert thread. Does the
 * actual insertion for directories.
 *
 * @param ilm Collected data related to the insertion
 */
void insertDirectoryGtkThread(InsertDirectoryModel * ilm);

 
void createInsertProgressBar(InsertModel * ilm);

void createInsertDirectoryProgressBar(InsertDirectoryModel * ilm);

#endif
