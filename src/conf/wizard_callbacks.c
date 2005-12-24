/*
     This file is part of GNUnet.
     (C) 2005 Christian Grothoff (and other contributing authors)

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
 * @file conf/gbasic-callbacks.c
 * @brief Callbacks for the GTK configuration assistant
 * @author Nils Durner
 */

#include "platform.h"
#include "confdata.h"

#define LKC_DIRECT_LINK
#include "lkc.h"


#include <gtk/gtk.h>

#include "wizard_callbacks.h"
#include "wizard_interface.h"
#include "wizard_support.h"
#include "wizard_util.h"
#include "wizard_gtk.h"

#include "lkc.h"

extern GtkWidget *curwnd;
extern int doOpenEnhConfigurator;
extern int doAutoStart;
extern char *user_name, *group_name;
static int doUpdate = YES;

GtkWidget *msgSave;
GtkWidget *msgSaveFailed;
GtkWidget *msgUpdateFailed;

/* 1 = terminate app on "assi_destroy" */
int quit;

void
on_step1_next_clicked (GtkButton * button, gpointer user_data)
{
	quit = 0;
	gtk_widget_destroy(curwnd);
	quit = 1;
	
	curwnd = create_assi_step2();
	load_step2();
	gtk_widget_show(curwnd);
}


void
on_abort_clicked (GtkButton * button, gpointer user_data)
{
	msgSave = create_msgSave();
	gtk_widget_show(msgSave);
}


void
on_step2_back_clicked (GtkButton * button, gpointer user_data)
{
	quit = 0;
	gtk_widget_destroy(curwnd);
	quit = 1;
	curwnd = create_assi_step1();
	gtk_widget_show(curwnd);
}


void
on_step2_next_clicked (GtkButton * button, gpointer user_data)
{
	quit = 0;
	gtk_widget_destroy(curwnd);
	quit = 1;
	
	curwnd = create_assi_step3();
	load_step3();
	gtk_widget_show(curwnd);
}


void
on_step3_back_clicked (GtkButton * button, gpointer user_data)
{
	quit = 0;
	gtk_widget_destroy(curwnd);
	quit = 1;

	curwnd = create_assi_step2();
	load_step2();
	gtk_widget_show(curwnd);
}


void
on_step3_next_clicked (GtkButton * button, gpointer user_data)
{
	quit = 0;
	gtk_widget_destroy(curwnd);
	quit = 1;
	
	curwnd = create_assi_step4();
	load_step4();
	gtk_widget_show(curwnd);
}


void
on_step5_back_clicked (GtkButton * button, gpointer user_data)
{
	quit = 0;
	gtk_widget_destroy(curwnd);
	quit = 1;
	
	curwnd = create_assi_step4();
	load_step4();
	gtk_widget_show(curwnd);
}

void showErr(char *prefix, char *error) {
	GtkWidget *vbox17, *hbox67, *label98;
	char *err;
	
	msgSaveFailed = create_msgSaveFailed();
	
	vbox17 = lookup_widget(msgSaveFailed, "vbox17");
	hbox67 = lookup_widget(vbox17, "hbox67");
	label98 = lookup_widget(vbox17, "label98");
	
	err = malloc(strlen(prefix) + strlen(error) + 2);
	sprintf(err, "%s %s", prefix, error);
	
	gtk_label_set_text(GTK_LABEL(label98), err);
	
	free(err);
	
	gtk_widget_show(msgSaveFailed);
}

int
save_conf ()
{
  char * filename;
	
  filename = getConfigurationString("GNUNET-SETUP",
				    "FILENAME");
  if (conf_write(filename)) {
    char * err;
    const char * prefix;

    prefix = _("Unable to save configuration file `%s':");

    err = malloc(strlen(filename) + strlen(prefix) + 1);
    sprintf(err, prefix, filename);
    showErr(err, STRERROR(errno));
    free(err);

    free(filename);
    return 0;
  }
  free(filename);	
  return 1;
}

void
on_finish_clicked (GtkButton * button, gpointer user_data)
{  
	if (doAutoStart && user_name)
		if (!wiz_createGroupUser(group_name, user_name)) {
#ifndef MINGW
			showErr(_("Unable to create user account:"), STRERROR(errno));
#endif
			return;
		}

	if (!wiz_autostartService(doAutoStart, user_name, group_name)) {
#ifndef MINGW
		showErr(_("Unable to change startup process:"), STRERROR(errno));
#endif
	}	

	if (!save_conf())
		return;
    
  if (doUpdate) {
    if (system("gnunet-update") != 0) {
      msgUpdateFailed = create_msgUpdateFailed();
      gtk_widget_show(msgUpdateFailed);
    }
    else
      gtk_widget_destroy(curwnd);
  }
  else
    gtk_widget_destroy(curwnd);
}

void
on_saveYes_clicked (GtkButton * button, gpointer user_data)
{
	int i = save_conf();
	
	gtk_widget_destroy(msgSave);
	if (i)
	{
		quit = 1;
		gtk_widget_destroy(curwnd);
	}
}

void
on_saveNo_clicked (GtkButton * button, gpointer user_data)
{
	quit = 1;
	gtk_widget_destroy(msgSave);
	gtk_widget_destroy(curwnd);
}

void
on_assi_destroy (GtkObject * object, gpointer user_data)
{
	/* Don't terminate if the user just clicked "Next" */
	if (quit)
		gtk_main_quit();
}

void
on_saveFailedOK_clicked (GtkButton * button, gpointer user_data)
{
	gtk_widget_destroy(msgSaveFailed);
}

void
on_updateFailedOK_clicked (GtkButton * button, gpointer user_data)
{
  gtk_widget_destroy(msgUpdateFailed);
}

void
on_entIP_changed (GtkEditable * editable, gpointer user_data)
{
	struct symbol *sym = sym_lookup("IP", "NETWORK", 0);
	sym_set_string_value(sym, gtk_editable_get_chars(editable, 0, -1));
}


void
on_cmbNIC_changed (GtkComboBox * combobox, gpointer user_data)
{
	GtkTreeIter iter;
	GValue val;
	char *entry;
#ifdef MINGW
	char nic[21], *idx;
	char *dst;
#else
	char *nic;
#endif
	struct symbol *sym;
	GtkTreeModel *model;
	
	gtk_combo_box_get_active_iter(combobox, &iter);
	model = gtk_combo_box_get_model(combobox);
	memset(&val, 0, sizeof(val));
	gtk_tree_model_get_value(model, &iter, 0, &val);
	entry = (char *) g_value_get_string(&val);

#ifdef MINGW
	idx = strrchr(entry, '-');
	if (! idx)
		return;
	idx += 2;
	dst = nic;
	while(*idx)
		*dst++ = *idx++;
	dst[-1] = 0;
#else
	nic = entry;
#endif
	sym = sym_lookup("INTERFACE", "NETWORK", 0);
	sym_set_string_value(sym, nic);
	sym = sym_lookup("INTERFACES", "LOAD", 0);
	sym_set_string_value(sym, nic);
}

void
on_chkFW_toggled (GtkToggleButton * togglebutton, gpointer user_data)
{
	struct symbol *sym = sym_lookup("LIMITED", "NAT", 0);
	sym_set_tristate_value(sym,
		gtk_toggle_button_get_active(togglebutton) ? yes : no);
}

void
on_entUp_changed (GtkEditable * editable, gpointer user_data)
{
	struct symbol *sym = sym_lookup("MAXNETUPBPSTOTAL", "LOAD", 0);
	sym_set_string_value(sym, gtk_editable_get_chars(editable, 0, -1));
}


void
on_entDown_changed (GtkEditable * editable, gpointer user_data)
{
	struct symbol *sym = sym_lookup("MAXNETDOWNBPSTOTAL", "LOAD", 0);
	sym_set_string_value(sym, gtk_editable_get_chars(editable, 0, -1));
}


void
on_radGNUnet_toggled (GtkToggleButton * togglebutton, gpointer user_data)
{
	struct symbol *sym = sym_lookup("BASICLIMITING", "LOAD", 0);
	sym_set_tristate_value(sym,	gtk_toggle_button_get_active(togglebutton) ? yes : no);
}


void
on_radShare_toggled (GtkToggleButton * togglebutton, gpointer user_data)
{
	struct symbol *sym = sym_lookup("BASICLIMITING", "LOAD", 0);
	sym_set_tristate_value(sym,	gtk_toggle_button_get_active(togglebutton) ? no : yes);
}


void
on_entCPU_changed (GtkEditable * editable, gpointer user_data)
{
	struct symbol *sym = sym_lookup("MAXCPULOAD", "LOAD", 0);
	sym_set_string_value(sym, gtk_editable_get_chars(editable, 0, -1));
}

void
on_chkMigr_toggled (GtkToggleButton * togglebutton, gpointer user_data)
{
	struct symbol *sym = sym_lookup("ACTIVEMIGRATION", "FS", 0);
	sym_set_tristate_value(sym,
		gtk_toggle_button_get_active(togglebutton) ? yes : no);
}

void
on_entQuota_changed (GtkEditable * editable, gpointer user_data)
{
	struct symbol *sym = sym_lookup("QUOTA", "FS", 0);
	sym_set_string_value(sym, gtk_editable_get_chars(editable, 0, -1));
}


void
on_chkStart_toggled (GtkToggleButton * togglebutton, gpointer user_data)
{
  struct symbol *sym = sym_lookup("AUTOSTART", "GNUNETD", 0);

	doAutoStart = gtk_toggle_button_get_active(togglebutton);
  sym_set_tristate_value(sym, doAutoStart ? yes : no);
}


void
on_chkEnh_toggled (GtkToggleButton * togglebutton, gpointer user_data)
{
	doOpenEnhConfigurator = gtk_toggle_button_get_active(togglebutton);
}

void
on_chkUpdate_toggled (GtkToggleButton * togglebutton, gpointer user_data)
{
  doUpdate = gtk_toggle_button_get_active(togglebutton);
}

void
on_step4_back_clicked (GtkButton * button, gpointer user_data)
{
	quit = 0;
	gtk_widget_destroy(curwnd);
	quit = 1;
	
	curwnd = create_assi_step3();
	load_step3();
	gtk_widget_show(curwnd);
}

void
on_step4_next_clicked (GtkButton * button, gpointer user_data)
{
	quit = 0;
	gtk_widget_destroy(curwnd);
	quit = 1;
	
	curwnd = create_assi_step5();
	load_step5();
	gtk_widget_show(curwnd);
}

void
on_entUser_changed (GtkEditable * editable, gpointer user_data)
{
  struct symbol *sym;

	if (user_name)
		free(user_name);
	
	user_name = strdup(gtk_editable_get_chars(editable, 0, -1));

  sym = sym_lookup("USER", "GNUNETD", 0);
  sym_set_string_value(sym, user_name);
}


void
on_entGroup_changed (GtkEditable * editable, gpointer user_data)
{
  struct symbol *sym;

	if (group_name)
		free(group_name);
	
	group_name = strdup(gtk_editable_get_chars(editable, 0, -1));

  sym = sym_lookup("GROUP", "GNUNETD", 0);
  sym_set_string_value(sym, group_name);
}
