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
 * @file src/applications/afs/gtkui/directorydisplay.c
 * @brief code that displays the contents of a directory
 * @author Christian Grothoff
 */


#include "gnunet_afs_esed2.h"
#include "helper.h"
#include "directory.h"
#include "directorydisplay.h"
#include "search.h"

void displayDirectory(const char * filename,
		      RootNode * rn) {
  GtkWidget * box;
  ListModel * model;  
  GNUnetDirectory * dir;
  int i;

  dir = readGNUnetDirectory(filename);
  if (dir == NULL) {
    LOG(LOG_WARNING,
        _("Downloaded directory '%s' has invalid format.\n"),
        filename);
    guiMessage(_("Downloaded directory '%s' has invalid format.\n"),
               filename);
    return;
  }
  model = (ListModel*) MALLOC(sizeof(ListModel));
  model->type = LM_TYPE_DIRECTORY;
  box = initializeSearchResultList(model);
  
  /* do a nested freeze on the clist, for efficiency */
  gtk_clist_freeze(GTK_CLIST(model->search_result_list));
    
  for (i=0;i<ntohl(dir->number_of_files);i++) {
    /* sneaky side-effect: add to state DB!
     (note that if you download a directory
     with gnunet-download, this does not happen
     since we don't know the mime-type in
     gnunet-download.) */
    makeRootNodeAvailable(&((GNUnetDirectory_GENERIC*)dir)->contents[i], 
			  DIR_CONTEXT_DIRECTORY);
    model->skipMenuRefresh = (i==ntohl(dir->number_of_files)-1 ? NO : YES );
    displayResultGTK(&((GNUnetDirectory_GENERIC*)dir)->contents[i],
		     model);
  }
  FREE(dir);
 
  gtk_clist_thaw(GTK_CLIST(model->search_result_list));
 
  if (rn != NULL ) {
    rn->header.description[MAX_DESC_LEN-1] = '\0';
    addToNotebook(rn->header.description,
  	  	  box);
  } else {
    const char * fileNameRoot = filename;
    int i;

    for (i=strlen(filename)-1;i>=0;i--) {
      if (filename[i] == DIR_SEPARATOR) {
        fileNameRoot = &filename[i+1];
        break;
      }
    }
    addToNotebook(fileNameRoot,
		  box);
  }
}

/* end of directorydisplay.c */
