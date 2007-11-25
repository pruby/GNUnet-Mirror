/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)

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
#ifndef GLADE_SUPPORT_H
#define GLADE_SUPPORT_H

#include "gnunet_util.h"
#include <gtk/gtk.h>
#include <gtk/gtktext.h>
#include <glade/glade.h>

#define mainXML GNUNET_GTK_get_main_glade_XML()

GladeXML *GNUNET_GTK_get_main_glade_XML (void);

void destroyMainXML (void);

void setLibrary (struct GNUNET_PluginHandle *lib);

GtkWidget *get_xml (const char *dialog_name);

GladeXML *load_xml (const char *dialog_name);

/**
 * Helper function to just show a simple dialog
 * that requires no initialization.
 */
void showDialog (const char *name);

GtkWidget *lookup_widget (const char *name);

#endif
