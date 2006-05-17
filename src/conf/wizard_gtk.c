/*
     This file is part of GNUnet.
     (C) 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file conf/wizard_gtk.c
 * @brief A easy-to-use configuration assistant
 * @author Nils Durner
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "platform.h"
#include "glade_support.h"

#ifndef MINGW
#include <grp.h>
#endif

#define LKC_DIRECT_LINK
#include "lkc.h"

#include "wizard_util.h"
#include "wizard_gtk.h"
#include "gconf.h"
#include "confdata.h"

/**
 * Current open window. 
 */
static GtkWidget * curwnd;

static int doOpenEnhConfigurator = 0;

static int doAutoStart = 0;

static int doUpdate = YES;

static char * user_name = NULL;

static char * group_name = NULL;


/* 1 = terminate app on "assi_destroy" */
static int quit;

/**
 * Destroy the current window (without exiting).
 * Also unrefs the current glade XML context.
 */
static void destroyCurrentWindow() {
  GNUNET_ASSERT(mainXML != NULL);
  GNUNET_ASSERT(curwnd != NULL);
  quit = 0;
  gtk_widget_destroy(curwnd);
  curwnd = NULL;
  destroyMainXML();
  quit = 1;
}

void on_assi_destroy (GtkObject * object, 
		      gpointer user_data) {
  /* Don't terminate if the user just clicked "Next" */
  if (quit)
    gtk_main_quit();
}


struct insert_nic_cls {
  GtkWidget * cmbNIC;
  int nic_item_count;
};

void on_cmbNIC_changed (GtkComboBox * combobox, 
			gpointer user_data) {
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

static void insert_nic(const char *name,
		       int defaultNIC,
		       void * cls) {
  struct insert_nic_cls * inc = cls;
  GtkWidget * cmbNIC = inc->cmbNIC;

  gtk_combo_box_append_text(GTK_COMBO_BOX(cmbNIC), name);
  defaultNIC = wiz_is_nic_default(name, defaultNIC);
  if (defaultNIC) 
    gtk_combo_box_set_active(GTK_COMBO_BOX(cmbNIC), inc->nic_item_count);
}

void load_step2(GtkButton * button,
		gpointer prev_window) {
  struct symbol *sym;
  GtkWidget * entIP;
  GtkWidget * chkFW;
  GtkTreeIter iter;
  GtkListStore *model;
  char *nic;
  struct insert_nic_cls cls;
  const char * val;

  destroyCurrentWindow();
  curwnd = get_xml("assi_step2");	
  cls.cmbNIC = lookup_widget("cmbNIC");
  GNUNET_ASSERT(cls.cmbNIC != NULL);
  cls.nic_item_count = 0;
  model = gtk_list_store_new(1, G_TYPE_STRING);
  gtk_combo_box_set_model(GTK_COMBO_BOX(cls.cmbNIC),
			  GTK_TREE_MODEL(model));
  gtk_combo_box_entry_set_text_column(GTK_COMBO_BOX_ENTRY(cls.cmbNIC),
				      0);

  sym = sym_find("INTERFACE", "NETWORK");
  if (sym != NULL) {
    
    enumNetworkIfs(&insert_nic, &cls);
    
    if (cls.nic_item_count != 0) {
      /* ifconfig unavailable */
      
      sym_calc_value_ext(sym, 1);
      nic = (char *) sym_get_string_value(sym);
      
      if (!nic || strlen(nic) == 0)
	nic = "eth0";
      gtk_combo_box_append_text(GTK_COMBO_BOX(cls.cmbNIC), nic);
      gtk_tree_model_get_iter_first(GTK_TREE_MODEL(model), 
				    &iter);
      gtk_combo_box_set_active_iter(GTK_COMBO_BOX(cls.cmbNIC), &iter);
      on_cmbNIC_changed(GTK_COMBO_BOX(cls.cmbNIC), NULL);			
    }
    
    gtk_widget_set_usize(cls.cmbNIC, 10, -1);
  }
  
  entIP = lookup_widget("entIP");
  sym = sym_find("IP", "NETWORK");
  if (sym != NULL) {
    sym_calc_value_ext(sym, 1);
    val = sym_get_string_value(sym);
    if (val == NULL)
      val = "";
    gtk_entry_set_text(GTK_ENTRY(entIP), val);
  }
  
  chkFW = lookup_widget("chkFW");
  sym = sym_find("LIMITED", "NAT");
  if (sym != NULL) {
    sym_calc_value_ext(sym, 1);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chkFW),
				 sym_get_tristate_value(sym) != no);
  }
  gtk_widget_show(curwnd);
}

void load_step3(GtkButton * button,
		gpointer prev_window) {
  struct symbol *sym;
  GtkWidget * entUp;
  GtkWidget * entDown;
  GtkWidget * radGNUnet;
  GtkWidget * radShare;
  GtkWidget * entCPU;
  const char * val;
  
  destroyCurrentWindow();
  curwnd = get_xml("assi_step3");
  entUp = lookup_widget("entUp");
  entDown = lookup_widget("entDown");  
  radGNUnet = lookup_widget("radGNUnet");
  radShare = lookup_widget("radShare");  
  entCPU = lookup_widget("entCPU");
	
  sym = sym_find("MAXNETUPBPSTOTAL", "LOAD");
  if (sym) {
    sym_calc_value_ext(sym, 1);
    val = sym_get_string_value(sym);
    if (val == NULL)
      val = "";
    gtk_entry_set_text(GTK_ENTRY(entUp), val);
  }
  sym = sym_find("MAXNETDOWNBPSTOTAL", "LOAD");
  if (sym) {
    sym_calc_value_ext(sym, 1);
    val = sym_get_string_value(sym);
    if (val == NULL)
      val = "";
    gtk_entry_set_text(GTK_ENTRY(entDown), val);
  }
  sym = sym_find("BASICLIMITING", "LOAD");
  if (sym) {
    sym_calc_value_ext(sym, 1);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(sym_get_tristate_value(sym) != no 
						   ? radGNUnet 
						   : radShare ), 
				 TRUE);
  }
  sym = sym_find("MAXCPULOAD", "LOAD");
  if (sym) {
    sym_calc_value_ext(sym, 1);
    val = sym_get_string_value(sym);
    if (val == NULL)
      val = "";
    gtk_entry_set_text(GTK_ENTRY(entCPU), val);
  }
  gtk_widget_show(curwnd);
}

void load_step4(GtkButton * button,
		gpointer prev_window) {
  struct symbol *sym;
  GtkWidget * entUser;
  GtkWidget * entGroup;
  const char * uname = NULL;
  const char * gname = NULL;

  destroyCurrentWindow();
  curwnd = get_xml("assi_step4");
  entUser = lookup_widget("entUser");
  entGroup = lookup_widget("entGroup");

  if (NULL != user_name) {
    sym = sym_find("USER", "GNUNETD");
    if (sym) {
      sym_calc_value_ext(sym, 1);
      uname = sym_get_string_value(sym);
    }
  }

  if (NULL != group_name) {
    sym = sym_find("GROUP", "GNUNETD");
    if (sym) {
      sym_calc_value_ext(sym, 1);
      gname = sym_get_string_value(sym);
    }
  }

#ifndef MINGW
  if (NULL == uname || strlen(uname) == 0) {
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

  if (user_name != NULL)
    gtk_entry_set_text(GTK_ENTRY(entUser), user_name);
  if (group_name != NULL)
    gtk_entry_set_text(GTK_ENTRY(entGroup), group_name);
  if(isOSUserAddCapable())
    gtk_widget_set_sensitive(entUser, TRUE);
  else
    gtk_widget_set_sensitive(entUser, FALSE);
  if(isOSGroupAddCapable())
    gtk_widget_set_sensitive(entGroup, TRUE);
  else
    gtk_widget_set_sensitive(entGroup, FALSE);
  gtk_widget_show(curwnd);
}


void load_step5(GtkButton * button,
		gpointer prev_window) {
  struct symbol *sym;
  GtkWidget * chkMigr;
  GtkWidget * entQuota;
  GtkWidget * chkEnh;
  GtkWidget * chkStart;
  const char * val;
  
  destroyCurrentWindow();
  curwnd = get_xml("assi_step5");
  entQuota =  lookup_widget("entQuota"); 
  chkMigr =  lookup_widget("chkMigr");
  chkStart =  lookup_widget("chkStart");
  chkEnh =  lookup_widget("chkEnh");
  
  sym = sym_find("QUOTA", "FS");
  if (sym) {
    sym_calc_value_ext(sym, 1);
    val = sym_get_string_value(sym);
    if (val == NULL)
      val = "";
    gtk_entry_set_text(GTK_ENTRY(entQuota), val);
  }
  
  sym = sym_find("ACTIVEMIGRATION", "FS");
  if (sym) {
    sym_calc_value_ext(sym, 1);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chkMigr),
				 sym_get_tristate_value(sym) != no);
  }
  
  if (isOSAutostartCapable())
    gtk_widget_set_sensitive(chkStart, TRUE);
  
  sym = sym_find("AUTOSTART", "GNUNETD");
  if (sym) {
    sym_calc_value_ext(sym, 1);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chkStart),
      sym_get_tristate_value(sym) != no);
  }

  if (doOpenEnhConfigurator)
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chkEnh), 1);		
  gtk_widget_show(curwnd);
}

void do_destroy_widget(GtkButton * button,
		       gpointer user_data) {
  GtkWidget * msgSaveFailed = user_data;
  gtk_widget_destroy(msgSaveFailed);
}

static void showErr(const char * prefix, 
		    const char * error) {
  GtkWidget * label98;
  GtkWidget * msgSaveFailed;
  char * err;  
  GladeXML * myXML;
  
  myXML = load_xml("msgSaveFailed");
  msgSaveFailed = glade_xml_get_widget(myXML,
				       "msgSaveFailed");
  label98 = glade_xml_get_widget(myXML, "label98");  
  err = MALLOC(strlen(prefix) + strlen(error) + 2);
  sprintf(err, 
	  "%s %s", 
	  prefix, 
	  error);  
  gtk_label_set_text(GTK_LABEL(label98), err);  
  FREE(err);  
  gtk_widget_show(msgSaveFailed);
  g_object_unref(myXML);
}


static int save_conf() {
  char * err;
  const char * prefix;
  char * filename;
	
  filename = getConfigurationString("GNUNET-SETUP",
				    "FILENAME");
  if (conf_write(filename)) {
    prefix = _("Unable to save configuration file `%s':");

    err = MALLOC(strlen(filename) + strlen(prefix) + 1);
    sprintf(err, prefix, filename);
    showErr(err, STRERROR(errno));
    FREE(err);

    FREE(filename);
    return SYSERR;
  }
  FREE(filename);	
  return OK;
}

void on_saveYes_clicked (GtkButton * button, 
			 gpointer user_data) {
  int i;
  GtkWidget * msgSave = user_data;

  i = save_conf();  
  gtk_widget_destroy(msgSave);
  if (OK == i) {
    quit = 1;
    gtk_widget_destroy(curwnd);
  }
}

void on_saveNo_clicked (GtkButton * button, 
			gpointer user_data) {
  GtkWidget * msgSave = user_data;

  quit = 1;
  gtk_widget_destroy(msgSave);
  gtk_widget_destroy(curwnd);
}

void on_abort_clicked(GtkButton * button, 
		      gpointer user_data) {
  showDialog("msgSave");
}

void on_finish_clicked (GtkButton * button, 
			gpointer user_data) {  
  if (doAutoStart && (user_name != NULL))
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
  
  if (OK != save_conf())
    return;
  
  if (doUpdate &&
      (system("gnunet-update") != 0) )
    showDialog("msgUpdateFailed");  
  else
    gtk_widget_destroy(curwnd);
}

void on_updateFailedOK_clicked (GtkButton * button, 
				gpointer user_data) {
  GtkWidget * dialog = user_data;
  gtk_widget_destroy(dialog);
}

void on_entIP_changed (GtkEditable * editable, 
		       gpointer user_data) {
  struct symbol *sym;
  gchar * ret;
  
  sym = sym_lookup("IP", "NETWORK", 0);
  ret = gtk_editable_get_chars(editable, 0, -1);
  sym_set_string_value(sym, ret);
  g_free(ret);
}


void on_chkFW_toggled (GtkToggleButton * togglebutton, 
		       gpointer user_data) {
  struct symbol *sym = sym_lookup("LIMITED", "NAT", 0);
  sym_set_tristate_value(sym,
			 gtk_toggle_button_get_active(togglebutton) ? yes : no);
}

void on_entUp_changed (GtkEditable * editable, 
		       gpointer user_data) {
  gchar * ret;
  struct symbol *sym;
  
  sym = sym_lookup("MAXNETUPBPSTOTAL", "LOAD", 0);
  ret = gtk_editable_get_chars(editable, 0, -1);
  sym_set_string_value(sym, ret);
  g_free(ret);
}


void on_entDown_changed (GtkEditable * editable, 
			 gpointer user_data) {
  struct symbol *sym;
  gchar * ret;

  sym = sym_lookup("MAXNETDOWNBPSTOTAL", "LOAD", 0);
  ret = gtk_editable_get_chars(editable, 0, -1);
  sym_set_string_value(sym, ret);
  g_free(ret);
}


void on_radGNUnet_toggled(GtkToggleButton * togglebutton, 
			  gpointer user_data) {
  struct symbol *sym = sym_lookup("BASICLIMITING", "LOAD", 0);
  sym_set_tristate_value(sym,	
			 gtk_toggle_button_get_active(togglebutton) ? yes : no);
}


void on_radShare_toggled (GtkToggleButton * togglebutton, 
			  gpointer user_data) {
  struct symbol *sym = sym_lookup("BASICLIMITING", "LOAD", 0);
  sym_set_tristate_value(sym,	
			 gtk_toggle_button_get_active(togglebutton) ? no : yes);
}


void on_entCPU_changed (GtkEditable * editable, 
			gpointer user_data) {
  struct symbol *sym;
  gchar * ret;

  sym = sym_lookup("MAXCPULOAD", "LOAD", 0);
  ret = gtk_editable_get_chars(editable, 0, -1);
  sym_set_string_value(sym, ret);
  g_free(ret);
}

void on_chkMigr_toggled (GtkToggleButton * togglebutton, 
			 gpointer user_data) {
  struct symbol *sym = sym_lookup("ACTIVEMIGRATION", "FS", 0);
  sym_set_tristate_value(sym,
			 gtk_toggle_button_get_active(togglebutton) ? yes : no);
}

void on_entQuota_changed (GtkEditable * editable, 
			  gpointer user_data) {
  struct symbol *sym;
  gchar * ret;

  sym = sym_lookup("QUOTA", "FS", 0);
  ret = gtk_editable_get_chars(editable, 0, -1);
  sym_set_string_value(sym, ret);
  g_free(ret);
}


void on_chkStart_toggled (GtkToggleButton * togglebutton, 
			  gpointer user_data) {
  struct symbol *sym = sym_lookup("AUTOSTART", "GNUNETD", 0);
  doAutoStart = gtk_toggle_button_get_active(togglebutton);
  sym_set_tristate_value(sym, doAutoStart ? yes : no);
}


void on_chkEnh_toggled (GtkToggleButton * togglebutton, 
			gpointer user_data) {
  doOpenEnhConfigurator = gtk_toggle_button_get_active(togglebutton);
}

void on_chkUpdate_toggled(GtkToggleButton * togglebutton, 
			  gpointer user_data) {
  doUpdate = gtk_toggle_button_get_active(togglebutton);
}

void on_entUser_changed (GtkEditable * editable,
			 gpointer user_data) {
  struct symbol *sym;
  gchar * ret;

  sym = sym_lookup("USER", "GNUNETD", 0);
  ret = gtk_editable_get_chars(editable, 0, -1);
  GNUNET_ASSERT(ret != NULL);
  sym_set_string_value(sym, ret);
  FREENONNULL(user_name);
  if (strlen(ret) != 0)
    user_name = STRDUP(ret);
  else
    user_name = NULL;
  g_free(ret);
  
}

void on_entGroup_changed (GtkEditable * editable,
			  gpointer user_data) {
  struct symbol *sym;
  gchar * ret;

  FREENONNULL(group_name);
  ret = gtk_editable_get_chars(editable, 0, -1);
  GNUNET_ASSERT(ret != NULL);
  sym_set_string_value(sym, ret);
  if (strlen(ret) != 0)
    group_name = STRDUP(ret);
  else
    group_name = NULL;
  sym = sym_lookup("GROUP", "GNUNETD", 0);
  g_free(ret);
}


int gtk_wizard_main(int argc, 
		    char **argv,
		    void * lib) {
  struct symbol * sym;
  char * filename;
	
  setLibrary(lib);
  g_thread_init(NULL);
  gtk_init(&argc, &argv); 
#ifdef ENABLE_NLS
  bind_textdomain_codeset(PACKAGE, "UTF-8"); /* for gtk */
#endif
#ifdef WINDOWS
  FreeConsole();
#endif

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
  curwnd = get_xml("assi_step1");
  gtk_widget_show(curwnd);
  gdk_threads_enter();
  gtk_main();
  gdk_threads_leave();
  destroyMainXML();
  setLibrary(NULL);
  if (doOpenEnhConfigurator)
    gconf_main(argc, argv, lib);
  FREENONNULL(user_name);
  FREENONNULL(group_name);
  return 0;
}
