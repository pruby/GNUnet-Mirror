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
 * @file src/applications/afs/gtkui/about.c
 * @author Christian Grothoff
 * @author Igor Wronsky
 *
 * This file contains the about dialog.
 */

#include "platform.h"
#include "gnunet_afs_esed2.h"
#include "gdk-pixbuf/gdk-pixbuf.h"
#include "gtk26about.h"

#include "helper.h"
#include "about.h"

/**
 * This displays an about window
 *
 * Todo: the GTK demo can do links.
 */
void about(GtkWidget *dummy,
	   gpointer data) {
  const gchar * authors[] = {
    "Juergen Appel <jappel@linux01.gwdg.de>",
    "Krista Bennett <kbennett@cerias.purdue.edu>",
    "James Blackwell <jblack@linuxguru.net>",
    "Ludovic Courtes <ludo@chbouib.org>",
    "Nils Durner <N.Durner@t-online.de>",
    "Renaldo Ferreira <rf@cs.purdue.edu>",
    "Christian Grothoff <christian@grothoff.org>",
    "Eric Haumant",
    "Tzvetan Horozov <horozov@motorola.com>",
    "Gerd Knorr <kraxel@bytesex.org>",
    "Werner Koch <libgcrypt@g10code.com>",
    "Uli Luckas <luckas@musoft.de>",
    "Blake Matheny <bmatheny@purdue.edu>",
    "Glenn McGrath <bug1@iinet.net.au>",
    "Hendrik Pagenhardt <Hendrik.Pagenhardt@gmx.net>",
    "Ioana Patrascu <ioanapatrascu@yahoo.com>",
    "Marko Raeihae",
    "Paul Ruth <ruth@cs.purdue.edu>",
    "Risto Saarelma",
    "Antti Salonen",
    "Tiberius Stef <tstef@cs.purdue.edu>",
    "Tuomas Toivonen",
    "Tomi Tukiainen",
    "Kevin Vandersloot <kfv101@psu.edu>",
    "Simo Viitanen",
    "Larry Waldo", 
    "Igor Wronsky <iwronsky@users.sourceforge.net>",
    "<january@hushmail.com>",
    NULL,
  };
  const gchar * artists[] = {
    "Christian Muellner <chris@flop.de>",
    "Alex Jones <alexrjones@ntlworld.com>",
    NULL,
  };
  const char * trans = _("translator-credits");
  const char * license = "GNUnet is free software; you can redistribute it and/or modify\n"
			 "it under the terms of the GNU General Public License as published\n"
			 "by the Free Software Foundation; either version 2, or (at your\n"
			 "option) any later version.\n\n"
			 "GNUnet is distributed in the hope that it will be useful, but\n"
			 "WITHOUT ANY WARRANTY; without even the implied warranty of\n"
			 "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n"
                         "See the GNU General Public License for more details.\n\n"
			 "You should have received a copy of the GNU General Public License\n"
			 "along with GNUnet; see the file COPYING.  If not, write to the\n"
			 "Free Software Foundation, Inc., 59 Temple Place - Suite 330,\n"
                         "Boston, MA 02111-1307, USA.\n";

  GdkPixbuf * logo;
  GError * error;

  error = NULL;
  logo = gdk_pixbuf_new_from_file(DATADIR"/gnunet_logo.png",
				  &error);
  if (logo != NULL) {
    gtk_show_about_dialog(NULL, 
			  "logo", logo,
			  "name", "gnunet-gtk",
			  "version", VERSION,
			  "copyright" , "(C) 2001-2004 Christian Grothoff (and other contributing authors)",
			  "website", "http://www.gnu.org/software/gnunet/",
			  "license", license,		  
			  "authors", authors,
			  "artists", artists,
			  (0 == strcmp(trans,"translator-credits")) ? NULL : "translator_credits", trans,
			  NULL);
    g_object_unref(G_OBJECT(logo));
  } else {
    gtk_show_about_dialog(NULL, 
			  "name", "gnunet-gtk",
			  "version", VERSION,
			  "copyright" , "(C) 2001-2004 Christian Grothoff (and other contributing authors)",
			  "website", "http://www.gnu.org/software/gnunet/",
			  "license", license,		  
			  "authors", authors,
			  "artists", artists,
			  (0 == strcmp(trans,"translator-credits")) ? NULL : "translator_credits", trans,
			  NULL);
  }
}

/* end of about.c */
