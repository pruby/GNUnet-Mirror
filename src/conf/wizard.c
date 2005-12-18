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
 * @file conf/wizard.c
 * @brief A easy-to-use configuration assistant
 * @author Nils Durner
 */

#include "gnunet_util.h"
#include "platform.h"

#ifndef MINGW
#include <grp.h>
#endif


#define LKC_DIRECT_LINK
#include "lkc.h"

#include <gtk/gtk.h>

#include "wizard_interface.h"
#include "wizard_support.h"
#include "wizard_callbacks.h"
#include "wizard_util.h"

#include "wizard.h"
#include "gconf.h"
#include "confdata.h"

GtkWidget *curwnd;
GtkWidget *cmbNIC;

int doOpenEnhConfigurator = 0;
int doAutoStart = 0;
char * user_name = NULL;
char * group_name = NULL;
static int nic_item_count = 0;

void insert_nic(const char *name,
                int defaultNIC,
                void * cls)
{
 gtk_combo_box_append_text(GTK_COMBO_BOX(cmbNIC), name);

	defaultNIC = wiz_is_nic_default(name, defaultNIC);

  /* Make default selection */
  if (defaultNIC)
  {
  	GtkTreeModel *model;
  	GtkTreeIter cur, last;
  	model = gtk_combo_box_get_model(GTK_COMBO_BOX(cmbNIC));
  	gtk_tree_model_get_iter_first(model, &cur);
  	last = cur;
  	while(gtk_tree_model_iter_next(model, &cur))
  	{
  		last = cur;
  	}
  	
  	gtk_combo_box_set_active_iter(GTK_COMBO_BOX(cmbNIC), &last);
  	on_cmbNIC_changed(GTK_COMBO_BOX(cmbNIC), NULL);
  }

	nic_item_count++;
}

void load_step2()
{
	struct symbol *sym;
	
	GtkWidget *vbox3, *frame1, *vbox4, *vbox5, *vbox6, *table1, *entIP,
		*chkFW;
	
	vbox3 = lookup_widget(curwnd, "vbox3");
	frame1 = lookup_widget(vbox3, "frame1");
	vbox4 = lookup_widget(frame1, "vbox4");
	vbox5 = lookup_widget(vbox4, "vbox5");
	vbox6 = lookup_widget(vbox5, "vbox6");
	table1 = lookup_widget(vbox6, "table1");
	
	cmbNIC = lookup_widget(table1, "cmbNIC");
	entIP = lookup_widget(table1, "entIP");
	chkFW = lookup_widget(table1, "chkFW");

	sym = sym_find("INTERFACE", "NETWORK");
	if (sym)
	{
		nic_item_count = 0;
		enumNetworkIfs(insert_nic, NULL);

		if (!nic_item_count)
		{
			/* ifconfig unavailable */
	  	GtkTreeIter iter;
	  	GtkTreeModel *model;
	  	char *nic;
	  	
			sym_calc_value_ext(sym, 1);
			nic = (char *) sym_get_string_value(sym);

			if (!nic || strlen(nic) == 0)
				nic = "eth0";
			gtk_combo_box_append_text(GTK_COMBO_BOX(cmbNIC), nic);
			
	  	model = gtk_combo_box_get_model(GTK_COMBO_BOX(cmbNIC));  		
  		gtk_tree_model_get_iter_first(model, &iter);
	  	gtk_combo_box_set_active_iter(GTK_COMBO_BOX(cmbNIC), &iter);
	  	on_cmbNIC_changed(GTK_COMBO_BOX(cmbNIC), NULL);			
		}

		gtk_widget_set_usize(cmbNIC, 10, -1);
	}

	sym = sym_find("IP", "NETWORK");
	if (sym)
	{
		sym_calc_value_ext(sym, 1);
		gtk_entry_set_text(GTK_ENTRY(entIP), sym_get_string_value(sym));
	}

	sym = sym_find("LIMITED", "NAT");
	if (sym)
	{
		sym_calc_value_ext(sym, 1);
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chkFW),
			sym_get_tristate_value(sym) != no);
	}
}

void load_step3()
{
	struct symbol *sym;
	GtkWidget *vbox7, *frame3, *vbox8, *vbox9, *vbox10, *frame4, *hbox24, *table2,
		*frame5, *vbox11, *frame6, *hbox25, *entUp, *entDown, *radGNUnet, *radShare,
		*entCPU;
		
	vbox7 = lookup_widget(curwnd, "vbox7");
	frame3 = lookup_widget(vbox7, "frame3");
	vbox8 = lookup_widget(frame3, "vbox8");
	vbox9 = lookup_widget(vbox8, "vbox9");
	vbox10 = lookup_widget(vbox9, "vbox10");
	
	frame4 = lookup_widget(vbox10, "frame4");
	hbox24 = lookup_widget(frame4, "hbox24");
	table2 = lookup_widget(hbox24, "table2");
	
	frame5 = lookup_widget(vbox10, "frame5");
	vbox11 = lookup_widget(frame5, "vbox11");
	
	frame6 = lookup_widget(vbox10, "frame6");
	hbox25 = lookup_widget(frame6, "hbox25");
	
	entUp = lookup_widget(table2, "entUp");
	entDown = lookup_widget(table2, "entDown");
	
	radGNUnet = lookup_widget(vbox11, "radGNUnet");
	radShare = lookup_widget(vbox11, "radShare");

	entCPU = lookup_widget(hbox25, "entCPU");
	
	
	sym = sym_find("MAXNETUPBPSTOTAL", "LOAD");
	if (sym)
	{
		sym_calc_value_ext(sym, 1);
		gtk_entry_set_text(GTK_ENTRY(entUp), sym_get_string_value(sym));
	}

	sym = sym_find("MAXNETDOWNBPSTOTAL", "LOAD");
	if (sym)
	{
		sym_calc_value_ext(sym, 1);
		gtk_entry_set_text(GTK_ENTRY(entDown), sym_get_string_value(sym));
	}
	
	sym = sym_find("BASICLIMITING", "LOAD");
	if (sym)
	{
		sym_calc_value_ext(sym, 1);
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(
			sym_get_tristate_value(sym) != no ? radGNUnet : radShare ), TRUE);
	}

	sym = sym_find("MAXCPULOAD", "LOAD");
	if (sym)
	{
		sym_calc_value_ext(sym, 1);
		gtk_entry_set_text(GTK_ENTRY(entCPU), sym_get_string_value(sym));
	}
}

void load_step4()
{
  struct symbol *sym;
  GtkWidget *vbox18, *frame8, *vbox19, *table3, *entUser, *entGroup;
  const char * uname = NULL;
  const char * gname = NULL;

  vbox18 = lookup_widget(curwnd, "vbox18");
  frame8 = lookup_widget(vbox18, "frame8");
  vbox19 = lookup_widget(frame8, "vbox19");
  table3 = lookup_widget(vbox19, "table3");
  entUser = lookup_widget(table3, "entUser");
  entGroup = lookup_widget(table3, "entGroup");

  if (NULL != user_name)
  {
    sym = sym_find("USER", "GNUNETD");
    if (sym)
    {
      sym_calc_value_ext(sym, 1);
      uname = sym_get_string_value(sym);
    }
  }

  if (NULL != group_name)
  {
    sym = sym_find("GROUP", "GNUNETD");
    if (sym)
    {
      sym_calc_value_ext(sym, 1);
      gname = sym_get_string_value(sym);
    }
  }

#ifndef MINGW
  if (NULL == uname || strlen(uname) == 0)
  {
    if((geteuid() == 0) || (NULL != getpwnam("gnunet")))
      user_name = STRDUP("gnunet");
    else {
      uname = getenv("USER");
      if (uname != NULL)
	user_name = STRDUP(uname);
      else
	user_name = NULL;
    }
  } else {
    user_name = STRDUP(uname);
  }
  if(NULL == gname || strlen(gname) == 0)
  {
    struct group * grp;
    if((geteuid() == 0) || (NULL != getgrnam("gnunet")))
      group_name = STRDUP("gnunet");
    else {
      grp = getgrgid(getegid());
      if ( (grp != NULL) &&
	   (grp->gr_name != NULL) )
	group_name = STRDUP(grp->gr_name);
      else
	group_name = NULL;
    }
  } else {
    group_name = STRDUP(gname);
  }

#else
  if (NULL == uname || strlen(uname) == 0)
    user_name = STRDUP("");
  else
    user_name = STRDUP(uname);
  if (NULL == gname || strlen(gname) == 0)
    group_name = STRDUP("");
  else
    group_name = STRDUP(gname);
#endif

  if(user_name)
    gtk_entry_set_text(GTK_ENTRY(entUser), user_name);
  if(group_name)
    gtk_entry_set_text(GTK_ENTRY(entGroup), group_name);
  if(isOSUserAddCapable())
    gtk_widget_set_sensitive(entUser, TRUE);
  else
    gtk_widget_set_sensitive(entUser, FALSE);
  if(isOSGroupAddCapable())
    gtk_widget_set_sensitive(entGroup, TRUE);
  else
    gtk_widget_set_sensitive(entGroup, FALSE);
}


void load_step5()
{
	struct symbol *sym;
	GtkWidget *vbox12, *frame7, *vbox13, *vbox14, *vbox15, *hbox53, *chkMigr,
		*entQuota, *chkEnh, *chkStart;
		
	vbox12 = lookup_widget(curwnd, "vbox12");
	frame7 = lookup_widget(vbox12, "frame7");
	vbox13 = lookup_widget(frame7, "vbox13");
	vbox14 = lookup_widget(vbox13, "vbox14");
	vbox15 = lookup_widget(vbox14, "vbox15");

	hbox53 = lookup_widget(vbox14, "hbox53");
	entQuota = lookup_widget(hbox53, "entQuota");

	chkMigr = lookup_widget(vbox14, "chkMigr");
	chkStart = lookup_widget(vbox14, "chkStart");
	chkEnh = lookup_widget(vbox14, "chkEnh");
	
	sym = sym_find("QUOTA", "FS");
	if (sym)
	{
		sym_calc_value_ext(sym, 1);
		gtk_entry_set_text(GTK_ENTRY(entQuota), sym_get_string_value(sym));
	}

	sym = sym_find("ACTIVEMIGRATION", "FS");
	if (sym)
	{
		sym_calc_value_ext(sym, 1);
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chkMigr),
			sym_get_tristate_value(sym) != no);
	}

	if (isOSAutostartCapable())
		gtk_widget_set_sensitive(chkStart, TRUE);

  sym = sym_find("AUTOSTART", "GNUNETD");
  if (sym)
  {
    sym_calc_value_ext(sym, 1);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chkStart),
      sym_get_tristate_value(sym) != no);
  }

	if (doOpenEnhConfigurator)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chkEnh), 1);		
}

int wizard_main (int argc, char **argv)
{
  struct symbol *sym;
  char * filename;
	
  gtk_init(&argc, &argv);
  
#ifdef ENABLE_NLS
  /* GTK uses UTF-8 encoding */
  bind_textdomain_codeset(PACKAGE, "UTF-8");
#endif

#ifdef WINDOWS
  FreeConsole();
#endif

  gtk_set_locale ();

  filename = getConfigurationString("GNUNET-SETUP",
				   "FILENAME");
  conf_read(filename);
  FREE(filename);

  sym = sym_find("EXPERIMENTAL", "Meta");
  sym_set_tristate_value(sym, yes);
  sym = sym_find("ADVANCED", "Meta");
  sym_set_tristate_value(sym, yes);
  sym = sym_find("RARE", "Meta");
  sym_set_tristate_value(sym, yes);

  curwnd = create_assi_step1 ();
  gtk_widget_show (curwnd);

  gtk_main ();

  if (doOpenEnhConfigurator)
    gconf_main(argc, argv);

  return 0;
}
