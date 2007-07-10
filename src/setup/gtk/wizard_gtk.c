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
 * @file setup/gtk/wizard_gtk.c
 * @brief A easy-to-use configuration assistant
 * @author Nils Durner
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "platform.h"
#include "glade_support.h"

#include "wizard_gtk.h"
#include "gconf.h"

#include "gnunet_util_config.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_error.h"

/**
 * Current open window.
 */
static GtkWidget *curwnd;

static int doOpenEnhConfigurator = 0;

static int doAutoStart = 0;

static int doUpdate = YES;

static char *user_name = NULL;

static char *group_name = NULL;

static struct GC_Configuration *editCfg = NULL;

static struct GE_Context *err_ctx = NULL;

static const char *cfg_fn = NULL;

/* 1 = terminate app on "assi_destroy" */
static int quit;

static int daemon_config;

/**
 * Destroy the current window (without exiting).
 * Also unrefs the current glade XML context.
 */
static void
destroyCurrentWindow ()
{
  GE_ASSERT (err_ctx, mainXML != NULL);
  GE_ASSERT (err_ctx, curwnd != NULL);
  quit = 0;
  gtk_widget_destroy (curwnd);
  curwnd = NULL;
  destroyMainXML ();
  quit = 1;
}

void
on_assi_destroysetup_gtk (GtkObject * object, gpointer user_data)
{
  /* Don't terminate if the user just clicked "Next" */
  if (quit)
    gtk_main_quit ();
}


struct insert_nic_cls
{
  GtkWidget *cmbNIC;
  int nic_item_count;
};

void
on_cmbNIC_changedsetup_gtk (GtkComboBox * combobox, gpointer user_data)
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
  GtkTreeModel *model;

  gtk_combo_box_get_active_iter (combobox, &iter);
  model = gtk_combo_box_get_model (combobox);
  memset (&val, 0, sizeof (val));
  gtk_tree_model_get_value (model, &iter, 0, &val);
  entry = (char *) g_value_get_string (&val);

#ifdef MINGW
  idx = strrchr (entry, '-');
  if (!idx)
    return;
  idx += 2;
  dst = nic;
  while (*idx)
    *dst++ = *idx++;
  dst[-1] = 0;
#else
  nic = entry;
#endif
  GC_set_configuration_value_string (editCfg,
                                     err_ctx, "NETWORK", "INTERFACE", nic);
  GC_set_configuration_value_string (editCfg,
                                     err_ctx, "LOAD", "INTERFACES", nic);
}

static int
insert_nic (const char *name, int defaultNIC, void *cls)
{
  gchar *utf8_name;
  gsize unused;
  struct insert_nic_cls *inc = cls;
  GtkWidget *cmbNIC = inc->cmbNIC;

  utf8_name = g_locale_to_utf8 (name, -1, NULL, &unused, NULL);
  if (!utf8_name)
    utf8_name = STRDUP (_("(unknown connection)"));

  gtk_combo_box_append_text (GTK_COMBO_BOX (cmbNIC), utf8_name);
  free (utf8_name);
  defaultNIC = wiz_is_nic_default (editCfg, name, defaultNIC);
  if (defaultNIC)
    gtk_combo_box_set_active (GTK_COMBO_BOX (cmbNIC), inc->nic_item_count);

  return OK;
}

void
load_step2setup_gtk (GtkButton * button, gpointer prev_window)
{
  GtkWidget *entIP;
  GtkWidget *chkFW;
  GtkTreeIter iter;
  GtkListStore *model;
  struct insert_nic_cls cls;
  char *val;

  destroyCurrentWindow ();
  curwnd = get_xml ("assi_step2");
  cls.cmbNIC = lookup_widget ("cmbNIC");
  GE_ASSERT (err_ctx, cls.cmbNIC != NULL);
  cls.nic_item_count = 0;
  model = gtk_list_store_new (1, G_TYPE_STRING);
  gtk_combo_box_set_model (GTK_COMBO_BOX (cls.cmbNIC),
                           GTK_TREE_MODEL (model));
  gtk_combo_box_entry_set_text_column (GTK_COMBO_BOX_ENTRY (cls.cmbNIC), 0);

  os_list_network_interfaces (err_ctx, &insert_nic, &cls);

  if (cls.nic_item_count != 0)
    {
      GC_get_configuration_value_string (editCfg,
                                         "NETWORK",
                                         "INTERFACE", "eth0", &val);
      gtk_combo_box_append_text (GTK_COMBO_BOX (cls.cmbNIC), val);
      gtk_tree_model_get_iter_first (GTK_TREE_MODEL (model), &iter);
      gtk_combo_box_set_active_iter (GTK_COMBO_BOX (cls.cmbNIC), &iter);
      on_cmbNIC_changedsetup_gtk (GTK_COMBO_BOX (cls.cmbNIC), NULL);
      FREE (val);
    }

  gtk_widget_set_usize (cls.cmbNIC, 10, -1);

  entIP = lookup_widget ("entIP");
  GC_get_configuration_value_string (editCfg, "NETWORK", "IP", "", &val);
  gtk_entry_set_text (GTK_ENTRY (entIP), val);
  FREE (val);

  chkFW = lookup_widget ("chkFW");
  gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (chkFW),
                                GC_get_configuration_value_yesno (editCfg,
                                                                  "NAT",
                                                                  "LIMITED",
                                                                  NO) == YES);

  gtk_widget_show (curwnd);
}

void
load_step3setup_gtk (GtkButton * button, gpointer prev_window)
{
  GtkWidget *entUp;
  GtkWidget *entDown;
  GtkWidget *radGNUnet;
  GtkWidget *radShare;
  GtkWidget *entCPU;
  char *val;

  destroyCurrentWindow ();
  curwnd = get_xml ("assi_step3");
  entUp = lookup_widget ("entUp");
  entDown = lookup_widget ("entDown");
  radGNUnet = lookup_widget ("radGNUnet");
  radShare = lookup_widget ("radShare");
  entCPU = lookup_widget ("entCPU");
  GC_get_configuration_value_string (editCfg,
                                     "LOAD",
                                     "MAXNETUPBPSTOTAL", "50000", &val);
  gtk_entry_set_text (GTK_ENTRY (entUp), val);
  FREE (val);
  GC_get_configuration_value_string (editCfg,
                                     "LOAD",
                                     "MAXNETDOWNBPSTOTAL", "50000", &val);
  gtk_entry_set_text (GTK_ENTRY (entDown), val);
  FREE (val);
  gtk_toggle_button_set_active
    (GTK_TOGGLE_BUTTON
     ((GC_get_configuration_value_yesno (editCfg,
                                         "LOAD",
                                         "BASICLIMITING",
                                         NO) == YES)
      ? radGNUnet : radShare), TRUE);
  GC_get_configuration_value_string (editCfg,
                                     "LOAD", "MAXCPULOAD", "50", &val);
  gtk_entry_set_text (GTK_ENTRY (entCPU), val);
  FREE (val);

  gtk_widget_show (curwnd);
}

void
load_step4setup_gtk (GtkButton * button, gpointer prev_window)
{
  GtkWidget *entUser;
  GtkWidget *entGroup;
  char *uname = NULL;
  char *gname = NULL;
  int cap;

  destroyCurrentWindow ();
  curwnd = get_xml ("assi_step4");
  entUser = lookup_widget ("entUser");
  entGroup = lookup_widget ("entGroup");

  if (NULL != user_name)
    {
      GC_get_configuration_value_string (editCfg,
                                         "GNUNETD", "USER", "gnunet", &uname);
    }

  if (NULL != group_name)
    {
      GC_get_configuration_value_string (editCfg,
                                         "GNUNETD",
                                         "GROUP", "gnunet", &gname);
    }

#ifndef MINGW
  if (NULL == uname || strlen (uname) == 0)
    {
      if ((geteuid () == 0) || (NULL != getpwnam ("gnunet")))
        user_name = STRDUP ("gnunet");
      else
        {
          uname = getenv ("USER");
          if (uname != NULL)
            user_name = STRDUP (uname);
          else
            user_name = NULL;
        }
    }
  else
    {
      user_name = STRDUP (uname);
    }
  if (NULL == gname || strlen (gname) == 0)
    {
      struct group *grp;
      if ((geteuid () == 0) || (NULL != getgrnam ("gnunet")))
        group_name = STRDUP ("gnunet");
      else
        {
          grp = getgrgid (getegid ());
          if ((grp != NULL) && (grp->gr_name != NULL))
            group_name = STRDUP (grp->gr_name);
          else
            group_name = NULL;
        }
    }
  else
    {
      group_name = STRDUP (gname);
    }

#else
  if (NULL == uname || strlen (uname) == 0)
    user_name = STRDUP ("");
  else
    user_name = STRDUP (uname);
  if (NULL == gname || strlen (gname) == 0)
    group_name = STRDUP ("");
  else
    group_name = STRDUP (gname);
#endif

  if (user_name != NULL)
    gtk_entry_set_text (GTK_ENTRY (entUser), user_name);
  if (group_name != NULL)
    gtk_entry_set_text (GTK_ENTRY (entGroup), group_name);
  cap = os_modify_autostart (err_ctx, 1, 1, NULL, NULL, NULL);
  gtk_widget_set_sensitive (entUser, cap);
#ifdef WINDOWS
  cap = FALSE;
#endif
  gtk_widget_set_sensitive (entGroup, cap);

  gtk_widget_show (curwnd);
}


void
load_step5setup_gtk (GtkButton * button, gpointer prev_window)
{
  GtkWidget *chkMigr;
  GtkWidget *entQuota;
  GtkWidget *chkEnh;
  GtkWidget *chkStart;
  char *val;

  destroyCurrentWindow ();
  curwnd = get_xml ("assi_step5");
  entQuota = lookup_widget ("entQuota");
  chkMigr = lookup_widget ("chkMigr");
  chkStart = lookup_widget ("chkStart");
  chkEnh = lookup_widget ("chkEnh");

  GC_get_configuration_value_string (editCfg, "FS", "QUOTA", "1024", &val);
  gtk_entry_set_text (GTK_ENTRY (entQuota), val);
  FREE (val);

  gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (chkMigr),
                                GC_get_configuration_value_yesno (editCfg,
                                                                  "FS",
                                                                  "ACTIVEMIGRATION",
                                                                  YES) ==
                                YES);

  if (os_modify_autostart (err_ctx, 1, 1, NULL, NULL, NULL))
    gtk_widget_set_sensitive (chkStart, TRUE);


  gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (chkStart),
                                GC_get_configuration_value_yesno (editCfg,
                                                                  "GNUNETD",
                                                                  "AUTOSTART",
                                                                  NO) == YES);

  if (doOpenEnhConfigurator)
    gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (chkEnh), 1);
  gtk_widget_show (curwnd);
}

void
do_destroy_widgetsetup_gtk (GtkButton * button, gpointer user_data)
{
  GtkWidget *msgSaveFailed = user_data;
  gtk_widget_destroy (msgSaveFailed);
}

static void
showErr (const char *prefix, const char *error)
{
  GtkWidget *dialog;
  char *err;

  err = MALLOC (strlen (prefix) + strlen (error) + 2);
  sprintf (err, "%s %s", prefix, error);

  dialog = gtk_message_dialog_new (NULL,
                                   GTK_DIALOG_MODAL,
                                   GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, err);
  FREE (err);
  gtk_dialog_run (GTK_DIALOG (dialog));
  gtk_widget_destroy (dialog);
}


static int
save_conf ()
{
  char *err;
  const char *prefix;

  if (GC_write_configuration (editCfg, cfg_fn))
    {
      prefix = _("Unable to save configuration file `%s':");

      err = MALLOC (strlen (cfg_fn) + strlen (prefix) + 1);
      sprintf (err, prefix, cfg_fn);
      showErr (err, STRERROR (errno));
      FREE (err);
      return SYSERR;
    }
  return OK;
}

void
on_abort_clickedsetup_gtk (GtkButton * button, gpointer user_data)
{
  GtkWidget *dialog;
  int ok, ret;

  ok = OK;

  dialog = gtk_message_dialog_new (NULL,
                                   GTK_DIALOG_MODAL,
                                   GTK_MESSAGE_QUESTION,
                                   GTK_BUTTONS_YES_NO,
                                   _
                                   ("Do you want to save the new configuration?"));
  ret = gtk_dialog_run (GTK_DIALOG (dialog));
  gtk_widget_destroy (dialog);
  switch (ret)
    {
    case GTK_RESPONSE_YES:
      ok = save_conf ();
      break;
    case GTK_RESPONSE_NO:
      ok = OK;
      break;
    case GTK_RESPONSE_CANCEL:
    default:
      ok = NO;
    }

  if (ok)
    {
      quit = 1;
      gtk_widget_destroy (curwnd);
    }
}

void
on_finish_clickedsetup_gtk (GtkButton * button, gpointer user_data)
{
  char *gup;
  char *bin;
  if (doAutoStart && (user_name != NULL))
    if (!wiz_createGroupUser (group_name, user_name))
      {
#ifndef MINGW
        showErr (_("Unable to create user account:"), STRERROR (errno));
#endif
        return;
      }

  if (wiz_autostartService (doAutoStart, user_name, group_name) != OK)
    {
#ifndef MINGW
      showErr (_("Unable to change startup process:"), STRERROR (errno));
#endif
    }

  if (OK != save_conf ())
    return;
  if (doUpdate)
    {
      bin = os_get_installation_path (IPK_BINDIR);
      gup = MALLOC (strlen (bin) + 30 + strlen (cfg_fn));
      strcpy (gup, bin);
      FREE (bin);
      strcat (gup, "/gnunet-update -c ");
      strcat (gup, cfg_fn);
      if (system (gup) != 0)
        showErr (_("Running gnunet-update failed.\n"
                   "This maybe due to insufficient permissions, please check your configuration.\n"
                   "Finally, run gnunet-update manually."), "");
      FREE (gup);
    }
  gtk_widget_destroy (curwnd);
}

void
on_updateFailedOK_clickedsetup_gtk (GtkButton * button, gpointer user_data)
{
  GtkWidget *dialog = user_data;
  gtk_widget_destroy (dialog);
}

void
on_entIP_changedsetup_gtk (GtkEditable * editable, gpointer user_data)
{
  gchar *ret;

  ret = gtk_editable_get_chars (editable, 0, -1);
  GC_set_configuration_value_string (editCfg, err_ctx, "NETWORK", "IP", ret);
  g_free (ret);
}


void
on_chkFW_toggledsetup_gtk (GtkToggleButton * togglebutton, gpointer user_data)
{
  GC_set_configuration_value_choice (editCfg, err_ctx, "LIMITED", "NAT",
                                     gtk_toggle_button_get_active
                                     (togglebutton) ? "YES" : "NO");
}

void
on_entUp_changedsetup_gtk (GtkEditable * editable, gpointer user_data)
{
  gchar *ret;

  ret = gtk_editable_get_chars (editable, 0, -1);
  GC_set_configuration_value_string (editCfg,
                                     err_ctx,
                                     "LOAD", "MAXNETUPBPSTOTAL", ret);
  g_free (ret);
}


void
on_entDown_changedsetup_gtk (GtkEditable * editable, gpointer user_data)
{
  gchar *ret;

  ret = gtk_editable_get_chars (editable, 0, -1);
  GC_set_configuration_value_string (editCfg,
                                     err_ctx,
                                     "LOAD", "MAXNETDOWNBPSTOTAL", ret);
  g_free (ret);
}


void
on_radGNUnet_toggledsetup_gtk (GtkToggleButton * togglebutton,
                               gpointer user_data)
{
  GC_set_configuration_value_choice (editCfg,
                                     err_ctx,
                                     "LOAD",
                                     "BASICLIMITING",
                                     gtk_toggle_button_get_active
                                     (togglebutton) ? "YES" : "NO");
}


void
on_radShare_toggledsetup_gtk (GtkToggleButton * togglebutton,
                              gpointer user_data)
{
  GC_set_configuration_value_choice (editCfg,
                                     err_ctx,
                                     "LOAD",
                                     "BASICLIMITING",
                                     gtk_toggle_button_get_active
                                     (togglebutton) ? "NO" : "YES");
}


void
on_entCPU_changedsetup_gtk (GtkEditable * editable, gpointer user_data)
{
  gchar *ret;
  int num;

  ret = gtk_editable_get_chars (editable, 0, -1);
  num = atoi (ret);
  GC_set_configuration_value_number (editCfg, err_ctx, "LOAD", "MAXCPULOAD",
                                     num);
  g_free (ret);
}

void
on_chkMigr_toggledsetup_gtk (GtkToggleButton * togglebutton,
                             gpointer user_data)
{
  GC_set_configuration_value_choice (editCfg,
                                     err_ctx,
                                     "FS",
                                     "ACTIVEMIGRATION",
                                     gtk_toggle_button_get_active
                                     (togglebutton) ? "YES" : "NO");
}

void
on_entQuota_changedsetup_gtk (GtkEditable * editable, gpointer user_data)
{
  gchar *ret;

  ret = gtk_editable_get_chars (editable, 0, -1);
  GC_set_configuration_value_string (editCfg, err_ctx, "FS", "QUOTA", ret);
  g_free (ret);
}


void
on_chkStart_toggledsetup_gtk (GtkToggleButton * togglebutton,
                              gpointer user_data)
{
  doAutoStart = gtk_toggle_button_get_active (togglebutton);
  GC_set_configuration_value_choice (editCfg,
                                     err_ctx,
                                     "AUTOSTART",
                                     "GNUNETD", doAutoStart ? "YES" : "NO");
}


void
on_chkEnh_toggledsetup_gtk (GtkToggleButton * togglebutton,
                            gpointer user_data)
{
  doOpenEnhConfigurator = gtk_toggle_button_get_active (togglebutton);
}

void
on_chkUpdate_toggledsetup_gtk (GtkToggleButton * togglebutton,
                               gpointer user_data)
{
  doUpdate = gtk_toggle_button_get_active (togglebutton);
}

void
on_entUser_changedsetup_gtk (GtkEditable * editable, gpointer user_data)
{
  gchar *ret;

  ret = gtk_editable_get_chars (editable, 0, -1);
  GE_ASSERT (err_ctx, ret != NULL);
  GC_set_configuration_value_string (editCfg, err_ctx, "GNUNETD", "USER",
                                     ret);
  FREENONNULL (user_name);
  if (strlen (ret) != 0)
    user_name = STRDUP (ret);
  else
    user_name = NULL;
  g_free (ret);

}

void
on_entGroup_changedsetup_gtk (GtkEditable * editable, gpointer user_data)
{
  gchar *ret;

  FREENONNULL (group_name);
  ret = gtk_editable_get_chars (editable, 0, -1);
  GE_ASSERT (err_ctx, ret != NULL);
  GC_set_configuration_value_string (editCfg,
                                     err_ctx, "GNUNETD", "GROUP", ret);
  if (strlen (ret) != 0)
    group_name = STRDUP (ret);
  else
    group_name = NULL;
  g_free (ret);
}

int
gtk_wizard_mainsetup_gtk (int argc,
                          char *const *argv,
                          struct PluginHandle *self,
                          struct GE_Context *ectx,
                          struct GC_Configuration *cfg,
                          struct GNS_Context *gns,
                          const char *filename, int is_daemon)
{
  GE_ASSERT (ectx, is_daemon);
  g_thread_init (NULL);
  gtk_init (&argc, (char ***) &argv);
#ifdef ENABLE_NLS
  bind_textdomain_codeset (PACKAGE, "UTF-8");   /* for gtk */
#endif
#ifdef WINDOWS
  FreeConsole ();
#endif

  editCfg = cfg;
  err_ctx = ectx;
  cfg_fn = filename;
  daemon_config = is_daemon;
  setLibrary (self);
  curwnd = get_xml ("assi_step1");
  gtk_widget_show (curwnd);
  gdk_threads_enter ();
  gtk_main ();
  gdk_threads_leave ();
  destroyMainXML ();
  if (doOpenEnhConfigurator)
    gconf_main_post_init (self, ectx, cfg, gns, filename, is_daemon);
  FREENONNULL (user_name);
  FREENONNULL (group_name);
  setLibrary (NULL);

  return 0;
}
