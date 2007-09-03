/*
     This file is part of GNUnet
     (C) 2005, 2007 Christian Grothoff (and other contributing authors)

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
 * @file src/plugins/about/about.c
 * @author Christian Grothoff
 * @author Igor Wronsky
 *
 * This file contains the about dialog.
 */

#include "platform.h"
#include "glade_support.h"

/**
 * This displays an about window
 */
void
on_aboutButton_activatesetup_gtk (GtkWidget * dummy, gpointer data)
{
  GtkWidget *ad;
  GladeXML *axml;

  axml = load_xml ("aboutdialog");
  ad = glade_xml_get_widget (axml, "aboutdialog");
  gtk_dialog_run (GTK_DIALOG (ad));
  gtk_widget_destroy (ad);
  g_object_unref (axml);
}

/**
 * Close a window (gtk_widget_destroy).
 */
void
gtk_widget_destroy_setup_gtk (GtkWidget * dummy)
{
  gtk_widget_destroy (dummy);
}

/* end of about.c */
