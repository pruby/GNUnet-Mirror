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
 * @file applications/afs/gtkui/pseudonyms.h
 * @brief Pseudonym creation and deletion dialogs
 * @author Christian Grothoff
 **/
#ifndef GTKUI_PSEUDONYMS_H
#define GTKUI_PSEUDONYMS_H

/**
 * Open a window to allow the user to create a pseudonym
 *
 * @param unused GTK handle that is not used
 * @param unused2 not used
 **/
void openCreatePseudonymDialog(GtkWidget * unused,
			       unsigned int unused2);

/**
 * Open a window to allow the user to delete a pseudonym
 *
 * @param unused GTK handle that is not used
 * @param unused2 not used
 **/
void openDeletePseudonymDialog(GtkWidget * unused,
			       unsigned int unused2);

#endif
