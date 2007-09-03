/*
     This file is part of GNUnet.
     (C) 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @brief GNUnet Setup
 * @file setup/gtk/ngconf.c
 * @author Nils Durner
 * @author Christian Grothoff
 */

#include "gnunet_setup_lib.h"
#include "glade_support.h"
#include "gconf.h"
#include "platform.h"

static GtkListStore *no_model;

static struct GC_Configuration *cfg;

static struct GE_Context *ectx;

static const char *cfg_filename;

struct P2W
{
  struct P2W *next;
  struct GNS_Tree *pos;
  GtkWidget *w;
};

/**
 * Maping of GNS_tree positions to widgets
 * (used for visibility updates).
 */
static struct P2W *pws;

#if GTK_MAJOR_VERSION >= 2 && GTK_MINOR_VERSION >= 12
#else
static GtkTooltips *tips;
#endif

static void
tooltip (GtkWidget * w, const char *text)
{
#if GTK_MAJOR_VERSION >= 2 && GTK_MINOR_VERSION >= 12
  gtk_widget_set_tooltip_text (w, text);
#else
  gtk_tooltips_set_tip (tips, w, text, NULL);
#endif
}

static void
update_visibility ()
{
  struct P2W *pos;

  pos = pws;
  while (pos != NULL)
    {
      if (pos->pos->visible)
        gtk_widget_show (pos->w);
      else
        gtk_widget_hide (pos->w);
      pos = pos->next;
    }
}

static void
link_visibility (struct GNS_Tree *pos, GtkWidget * w)
{
  struct P2W *pw;
  pw = MALLOC (sizeof (struct P2W));
  pw->pos = pos;
  pw->w = w;
  pw->next = pws;
  pws = pw;
}

static void
boolean_toggled (GtkToggleButton * togglebutton, gpointer user_data)
{
  struct GNS_Tree *pos = user_data;
  GC_set_configuration_value_string (cfg,
                                     ectx,
                                     pos->section,
                                     pos->option,
                                     gtk_toggle_button_get_active
                                     (togglebutton) ? "YES" : "NO");
  update_visibility ();
}

static void
radio_update (GtkRadioButton * button, gpointer user_data)
{
  struct GNS_Tree *pos = user_data;
  const char *opt;

  opt = g_object_get_data (G_OBJECT (button), "SC-value");
  GC_set_configuration_value_string (cfg,
                                     ectx, pos->section, pos->option, opt);
  update_visibility ();
}

static void
multi_update (GtkToggleButton * button, gpointer user_data)
{
  struct GNS_Tree *pos = user_data;
  char *val;
  char *opt;
  char *ret;
  char *v;
  char *s;

  val = NULL;
  GC_get_configuration_value_string (cfg,
                                     pos->section, pos->option, NULL, &val);
  GE_ASSERT (ectx, val != NULL);
  opt = g_object_get_data (G_OBJECT (button), "MC-value");
  if (gtk_toggle_button_get_active (button))
    {
      ret = MALLOC (strlen (val) + strlen (opt) + 2);
      strcpy (ret, val);
      strcat (ret, " ");
      strcat (ret, opt);
    }
  else
    {
      v = val;
      while ((NULL != (s = strstr (v, opt))) &&
             (((s[strlen (opt)] != '\0') &&
               (s[strlen (opt)] != ' ')) || ((s != val) && (s[-1] != ' '))))
        v = s + 1;
      GE_ASSERT (NULL, s != NULL);
      ret = MALLOC (strlen (val));
      s[0] = '\0';
      if (s != val)
        s[-1] = '\0';           /* kill space */
      strcpy (ret, val);
      strcat (ret, &s[strlen (opt)]);
    }
  GC_set_configuration_value_string (cfg,
                                     ectx, pos->section, pos->option, ret);
  FREE (ret);
  FREE (val);
  update_visibility ();
}

static void
string_update (GtkEntry * entry, gpointer user_data)
{
  struct GNS_Tree *pos = user_data;
  GC_set_configuration_value_string (cfg,
                                     ectx,
                                     pos->section,
                                     pos->option, gtk_entry_get_text (entry));
  update_visibility ();
}

static int
addLeafToTree (GtkWidget * parent, struct GNS_Tree *pos)
{
  GtkWidget *ebox;
  GtkWidget *box;
  GtkWidget *w;
  GtkWidget *choice;
  GtkWidget *label;
  int i;
  char defStr[128];
  const char *lri;

  box = gtk_hbox_new (FALSE, 0);
  link_visibility (pos, box);
  switch (pos->type & GNS_TypeMask)
    {
    case GNS_Boolean:
      w = gtk_check_button_new_with_label (pos->description);
      gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w),
                                    pos->value.Boolean.val);
      tooltip (w, pos->help);
      g_signal_connect (w, "toggled", G_CALLBACK (&boolean_toggled), pos);
      gtk_box_pack_start (GTK_BOX (box), w, FALSE, FALSE, 10);
      break;
    case GNS_String:
      ebox = gtk_vbox_new (FALSE, 10);
      w = gtk_entry_new ();
      label = gtk_label_new (pos->description);
      gtk_label_set_mnemonic_widget (GTK_LABEL (label), w);
      gtk_box_pack_start (GTK_BOX (ebox), label, FALSE, FALSE, 10);
      gtk_entry_set_text (GTK_ENTRY (w), pos->value.String.val);
      g_signal_connect (w, "changed", G_CALLBACK (&string_update), pos);
      tooltip (w, pos->help);
      gtk_box_pack_start (GTK_BOX (ebox), w, TRUE, TRUE, 10);
      gtk_box_pack_start (GTK_BOX (box), ebox, TRUE, TRUE, 10);
      break;
    case GNS_MC:
      i = 0;
      label = gtk_label_new (pos->description);
      gtk_box_pack_start (GTK_BOX (box), label, FALSE, FALSE, 10);
      while (NULL != (lri = pos->value.String.legalRange[i]))
        {

          w = gtk_check_button_new_with_label (lri);
          tooltip (w, pos->help);
          g_object_set_data (G_OBJECT (w), "MC-value", (void *) lri);
          if ((NULL != strstr (pos->value.String.val,
                               lri)) &&
              ((' ' == strstr (pos->value.String.val,
                               lri)[strlen (lri)])
               || ('\0' ==
                   strstr (pos->value.String.val,
                           lri)[strlen (lri)]))
              &&
              ((pos->value.String.val ==
                strstr (pos->value.String.val,
                        lri))
               || (' ' == strstr (pos->value.String.val, lri)[-1])))
            gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w), TRUE);
          g_signal_connect (w, "toggled", G_CALLBACK (&multi_update), pos);
          gtk_box_pack_start (GTK_BOX (box), w, FALSE, FALSE, 5);
          i++;
        }
      break;
    case GNS_SC:
      w = NULL;
      i = 0;
      choice = NULL;
      label = gtk_label_new (pos->description);
      gtk_box_pack_start (GTK_BOX (box), label, FALSE, FALSE, 10);
      while (NULL != (lri = pos->value.String.legalRange[i]))
        {
          if (w != NULL)
            w =
              gtk_radio_button_new_with_label_from_widget
              (GTK_RADIO_BUTTON (w), lri);
          else
            w = gtk_radio_button_new_with_label (NULL, lri);
          tooltip (w, pos->help);
          g_object_set_data (G_OBJECT (w), "SC-value", (void *) lri);
          gtk_box_pack_start (GTK_BOX (box), w, FALSE, FALSE, 0);
          if (0 == strcmp (lri, pos->value.String.val))
            choice = w;
          g_signal_connect (w, "toggled", G_CALLBACK (&radio_update), pos);
          i++;
        }
      gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (choice), TRUE);

      break;
    case GNS_Double:
      SNPRINTF (defStr, 128, "%llf", pos->value.Double.val);
      w = gtk_entry_new ();
      tooltip (w, pos->help);
      label = gtk_label_new (pos->description);
      gtk_label_set_mnemonic_widget (GTK_LABEL (label), w);
      gtk_box_pack_start (GTK_BOX (box), label, FALSE, FALSE, 10);
      g_signal_connect (w, "changed", G_CALLBACK (&string_update), pos);
      gtk_entry_set_text (GTK_ENTRY (w), defStr);
      gtk_box_pack_start (GTK_BOX (box), w, FALSE, FALSE, 0);
      break;
    case GNS_UInt64:
      w = gtk_spin_button_new_with_range (pos->value.UInt64.min,
                                          pos->value.UInt64.max, 1);
      tooltip (w, pos->help);
      label = gtk_label_new (pos->description);
      gtk_label_set_mnemonic_widget (GTK_LABEL (label), w);
      gtk_box_pack_start (GTK_BOX (box), label, FALSE, FALSE, 10);
      gtk_spin_button_set_value (GTK_SPIN_BUTTON (w), pos->value.UInt64.val);
      gtk_spin_button_set_numeric (GTK_SPIN_BUTTON (w), TRUE);
      gtk_spin_button_set_digits (GTK_SPIN_BUTTON (w), 0);
      g_signal_connect (w, "changed", G_CALLBACK (&string_update), pos);
      gtk_box_pack_start (GTK_BOX (box), w, FALSE, FALSE, 0);
      break;
    default:
      GE_ASSERT (NULL, 0);
      return 0;
    }
  gtk_box_pack_start (GTK_BOX (parent), box, FALSE, FALSE, 10);
  return 1;
}

static int
addNodeToTree (GtkNotebook * parent, struct GNS_Tree *pos)
{
  int i;
  struct GNS_Tree *child;
  GtkNotebook *notebook;
  GtkWidget *vbox;
  GtkWidget *label;
  GtkWidget *scroll;
  int have;

  have = 0;
  i = 0;
  vbox = gtk_vbox_new (FALSE, 0);
  notebook = NULL;
  while (NULL != (child = pos->children[i]))
    {
      switch (child->type & GNS_KindMask)
        {
        case GNS_Node:
          if (notebook == NULL)
            {
              notebook = GTK_NOTEBOOK (gtk_notebook_new ());
              gtk_box_pack_start (GTK_BOX (vbox), GTK_WIDGET (notebook), TRUE,
                                  TRUE, 0);
            }
          have = have | addNodeToTree (notebook, child);
          break;
        case GNS_Leaf:
          have = have | addLeafToTree (vbox, child);
          break;
        case GNS_Root:
        default:
          GE_ASSERT (NULL, 0);
          break;
        }
      i++;
    }
  if (have != 0)
    {
      label = gtk_label_new (pos->description);
      gtk_widget_show_all (vbox);
      gtk_widget_show_all (label);
      scroll = gtk_scrolled_window_new (NULL, NULL);
      gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
                                      GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
      link_visibility (pos, scroll);
      link_visibility (pos, label);
      gtk_scrolled_window_add_with_viewport (GTK_SCROLLED_WINDOW (scroll),
                                             vbox);
      gtk_notebook_append_page (parent, scroll, label);
    }
  else
    {
      g_object_unref (vbox);
    }
  return have;
}

static void
initView (struct GNS_Context *gns)
{
  GtkNotebook *notebook;
  notebook = GTK_NOTEBOOK (lookup_widget ("configNotebook"));
  addNodeToTree (notebook, GNS_get_tree (gns));
  gtk_widget_show_all (GTK_WIDGET (notebook));
  update_visibility ();
}


/**
 * User requested save manually.  Save configuration.
 */
void
on_saveButton_activatesetup_gtk ()
{
  GtkWidget *dialog;
  if (0 == GC_write_configuration (cfg, cfg_filename))
    {
      dialog = gtk_message_dialog_new (NULL,
                                       GTK_DIALOG_MODAL,
                                       GTK_MESSAGE_INFO,
                                       GTK_BUTTONS_OK,
                                       _("Configuration saved."));
      gtk_dialog_run (GTK_DIALOG (dialog));
      gtk_widget_destroy (dialog);
    }
  else
    {
      dialog = gtk_message_dialog_new (NULL,
                                       GTK_DIALOG_MODAL,
                                       GTK_MESSAGE_ERROR,
                                       GTK_BUTTONS_OK,
                                       _("Failed to save configuration."));
      gtk_dialog_run (GTK_DIALOG (dialog));
      gtk_widget_destroy (dialog);
    }
}


/**
 * User clicked to close window.  Check if configuration
 * needs saving and possibly save configuration or do not
 * exit.
 *
 * @return TRUE to NOT exit (i.e. user hits cancel on save YES/NO/CANCEL).
 */
gboolean
on_main_window_delete_eventsetup_gtk ()
{
  GtkWidget *dialog;
  gint ret;
  if (GC_test_dirty (cfg))
    {
      dialog = gtk_message_dialog_new (NULL,
                                       GTK_DIALOG_MODAL,
                                       GTK_MESSAGE_QUESTION,
                                       GTK_BUTTONS_YES_NO,
                                       _("Configuration changed. Save?"));
      ret = gtk_dialog_run (GTK_DIALOG (dialog));
      gtk_widget_destroy (dialog);
      switch (ret)
        {
        case GTK_RESPONSE_YES:
          if (0 != GC_write_configuration (cfg, cfg_filename))
            {
              dialog = gtk_message_dialog_new (NULL,
                                               GTK_DIALOG_MODAL,
                                               GTK_MESSAGE_ERROR,
                                               GTK_BUTTONS_OK,
                                               _
                                               ("Error saving configuration."));
              gtk_dialog_run (GTK_DIALOG (dialog));
              gtk_widget_destroy (dialog);
            }
          return FALSE;
        case GTK_RESPONSE_NO:
          return FALSE;
        case GTK_RESPONSE_CANCEL:
        default:
          return TRUE;
        }
    }
  return FALSE;
}

/**
 * We're really exiting.  Final cleanup code (in GTK).
 */
void
gtk_main_quitsetup_gtk ()
{
  gtk_main_quit ();
}



int
gconf_main_post_init (struct
                      PluginHandle
                      *self,
                      struct
                      GE_Context *e,
                      struct
                      GC_Configuration
                      *c,
                      struct
                      GNS_Context *gns, const char *filename, int is_daemon)
{
  GtkWidget *mainWindow;
  cfg = c;
  ectx = e;
  cfg_filename = filename;
  no_model = gtk_list_store_new (1, G_TYPE_STRING);
  setLibrary (self);
#if GTK_MAJOR_VERSION >= 2 && GTK_MINOR_VERSION >= 12
#else
  tips = gtk_tooltips_new ();
#endif
  mainWindow = get_xml ("setupWindow");
  initView (gns);
  gtk_window_maximize (GTK_WINDOW (mainWindow));
  gtk_widget_show (mainWindow);
  gdk_threads_enter ();
#ifdef WINDOWS
  SetCursor (LoadCursor (NULL, IDC_ARROW));
#endif
  gtk_main ();
  gdk_threads_leave ();
  destroyMainXML ();
  setLibrary (NULL);
  g_object_unref (G_OBJECT (no_model));
  no_model = NULL;
  return 0;
}


/* Main */
int
gconf_mainsetup_gtk (int argc,
                     const char
                     **argv,
                     struct
                     PluginHandle
                     *self,
                     struct GE_Context
                     *ectx,
                     struct
                     GC_Configuration
                     *cfg,
                     struct
                     GNS_Context *gns, const char *filename, int is_daemon)
{
  g_thread_init (NULL);
  gtk_init (&argc, (char ***) &argv);
#if ENABLE_NLS
  bind_textdomain_codeset (PACKAGE, "UTF-8");   /* for gtk */
#endif
#ifdef WINDOWS
  FreeConsole ();
#endif
  return gconf_main_post_init (self, ectx, cfg, gns, filename, is_daemon);
}
