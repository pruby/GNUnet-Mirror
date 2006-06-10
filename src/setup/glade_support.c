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

#include "platform.h"
#include "gnunet_util.h"
#include "glade_support.h"

/**
 * Handle to the dynamic library (which contains this code)
 */
static void * library;

/**
 * Current glade handle.
 */
static GladeXML * mainXML_;

GladeXML * getMainXML() {
  return mainXML_;
}

void destroyMainXML() {
  GNUNET_ASSERT(mainXML_ != NULL);
  g_object_unref(mainXML_);
  mainXML_ = NULL;
}

char * get_glade_filename() {
  char * gladeFile;

#ifdef MINGW
  gladeFile = MALLOC(_MAX_PATH + 1);
  plibc_conv_to_win_path(DATADIR"/wizard.glade",
			 gladeFile);
#else
  gladeFile = STRDUP(DATADIR"/wizard.glade");
#endif
  return gladeFile;
}


static void connector(const gchar *handler_name,
		      GObject *object,
		      const gchar *signal_name,
		      const gchar *signal_data,
		      GObject *connect_object,
		      gboolean after,
		      gpointer user_data) {
  GladeXML * xml = user_data;
  void * method;

  GNUNET_ASSERT(xml != NULL);
  method = trybindDynamicMethod(library,
				"",
				handler_name);
  if (method == NULL) {
    LOG(LOG_DEBUG,
	_("Failed to find handler for `%s'\n"),
	handler_name);
    return;
  }
  glade_xml_signal_connect(xml,
			   handler_name,
			   (GCallback) method);
}

GladeXML * load_xml(const char * dialog_name) {
  char * gladeFile;
  GladeXML * ret;

  gladeFile = get_glade_filename();
  ret = glade_xml_new(gladeFile,
		      dialog_name,
		      PACKAGE_NAME);
  if (ret == NULL)
    errexit(_("Failed to open `%s'.\n"),
	    gladeFile);  
  FREE(gladeFile);
  glade_xml_signal_autoconnect_full(ret, &connector, ret);
  return ret;
}

GtkWidget * lookup_widget(const char * name) {
  return glade_xml_get_widget(mainXML_, name);
}

GtkWidget * get_xml(const char * dialog_name) {
  mainXML_ = load_xml(dialog_name);
  return glade_xml_get_widget(mainXML_,
			      dialog_name);
}

/**
 * Helper function to just show a simple dialog
 * that requires no initialization.
 */
void showDialog(const char * name) {
  GtkWidget * msgSave;
  char * gladeFile;
  GladeXML * myXML;
  
  gladeFile = get_glade_filename();
  myXML = glade_xml_new(gladeFile,
			name,
			PACKAGE_NAME);
  if (mainXML_ == NULL)
    errexit(_("Failed to open `%s'.\n"),
	    gladeFile);  
  FREE(gladeFile);
  glade_xml_signal_autoconnect_full(myXML, &connector, myXML);
  msgSave = glade_xml_get_widget(myXML,
				 name);
  gtk_widget_show(msgSave);
  g_object_unref(myXML);
}

void setLibrary(void * lib) {
  library = lib;
}

