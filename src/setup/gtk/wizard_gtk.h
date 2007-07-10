/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2005 Christian Grothoff (and other contributing authors)

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
 * @file setup/gtk/wizard_gtk.h
 * @brief GNUnet Setup
 * @author Nils Durner
 */

#ifndef WIZARD_GTK_H
#define WIZARD_GTK_H

#include "gnunet_setup_lib.h"
#include "wizard_util.h"

int gtk_wizard_mainsetup_gtk (int argc,
                              char *const *argv,
                              struct PluginHandle *self,
                              struct GE_Context *ectx,
                              struct GC_Configuration *cfg,
                              struct GNS_Context *gns,
                              const char *filename, int is_daemon);

#endif
