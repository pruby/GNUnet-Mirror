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
 * @file applications/afs/gtkui/namespace.h
 * @brief namespace insert and search entry points
 * @author Christian Grothoff
 **/

#ifndef GTKUI_NAMESPACE_H
#define GTKUI_NAMESPACE_H



/**
 * Open a window to allow the user to build a namespace.
 *
 * @param context selector for a subset of the known RootNodes
 **/
void openAssembleNamespaceDialog(GtkWidget * unused,
				 unsigned int unused2);

/**
 * Open a window to allow the user to search a namespace
 *
 * @param unused GTK handle that is not used
 * @param unused2 argument that is always 0
 **/
void searchNamespace(GtkWidget * unused,
		     unsigned int unused2);

#endif
