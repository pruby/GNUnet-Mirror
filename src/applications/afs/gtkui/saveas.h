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
 * @file applications/afs/gtkui/saveas.h
 * @author Christian Grothoff
 **/

#ifndef GTKUI_SAVEAS_H
#define GTKUI_SAVEAS_H

#include "platform.h"

/**
 * Open the window that prompts the user for the 
 * filename.
 * This method must open the window,
 * copy the arguments and return. After the method
 * returns, the arguments passed to it will be
 * freed, so pointer should not be retained.
 * The method executes during a signal handler,
 * so a GTK lock is not required to to GUI 
 * operations.
 **/
void openSaveAs(RootNode * root);

#endif
