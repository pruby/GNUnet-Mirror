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
 *
 * TODO:
 * * add proper widgets for each option
 * * implement event handlers to process widget option changes!
 * * update glade file to create Notebook instead of tree view
 */

#include "gnunet_setup_lib.h"
#include "glade_support.h"
#include "gconf.h"
#include "platform.h"

static GtkListStore *no_model;

static struct GC_Configuration *cfg;

static struct GE_Context *ectx;

static const char *cfg_filename;

static void
boolean_toggled (GtkToggleButton * togglebutton, gpointer user_data)
{
  struct GNS_Tree *pos = user_data;
  GC_set_configuration_value_number (cfg,
                                     ectx,
                                     pos->section,
                                     pos->option,
                                     gtk_toggle_button_get_mode
                                     (togglebutton));
}

static void
radio_update (GtkRadioButton * button, gpointer user_data)
{
  struct GNS_Tree *pos = user_data;
  GSList *list = gtk_radio_button_get_group (button);
  int i;

  i = 0;
  while (pos->value.String.legalRange[i] != NULL)
    {
      if (list->data == button)
        {
          GC_set_configuration_value_string (cfg,
                                             ectx,
                                             pos->section,
                                             pos->option,
                                             pos->value.String.legalRange[i]);
        }
      list = list->next;
      i++;
    }
}

static void
multi_update (GtkRadioButton * button, gpointer user_data)
{
  struct GNS_Tree *pos = user_data;
  GSList *list = gtk_radio_button_get_group (button);
  int i;
  char *val;
  int size;

  size = 1;
  i = 0;
  while (pos->value.String.legalRange[i] != NULL)
    size += strlen (pos->value.String.legalRange[i++]) + 1;
  val = MALLOC (size);
  val[0] = '\0';
  i = 0;
  while (pos->value.String.legalRange[i] != NULL)
    {
      if (gtk_toggle_button_get_mode (GTK_TOGGLE_BUTTON (list->data)))
        strcat (val, pos->value.String.legalRange[i]);
      list = list->next;
      i++;
    }
  GC_set_configuration_value_string (cfg,
                                     ectx, pos->section, pos->option, val);
  FREE (val);
}

static void
string_update (GtkEntry * entry, gpointer user_data)
{
  struct GNS_Tree *pos = user_data;
  GC_set_configuration_value_string (cfg,
                                     ectx,
                                     pos->section,
                                     pos->option, gtk_entry_get_text (entry));
}

static int
addLeafToTree (GtkWidget * parent, struct GNS_Tree *pos)
{
  GtkWidget *box;
  GtkWidget *label;
  GtkWidget *w;
  GSList *list;
  int i;
  char defStr[128];

  if (!pos->visible)
    return 0;
  box = gtk_hbox_new (FALSE, 0);
  switch (pos->type & GNS_TypeMask)
    {
    case GNS_Boolean:
      w = gtk_check_button_new_with_label (pos->description);
      gtk_toggle_button_set_mode (GTK_TOGGLE_BUTTON (w),
                                  pos->value.Boolean.val);
      g_signal_connect (w, "toggled", &boolean_toggled, pos);
      gtk_box_pack_start (GTK_BOX (box), w, TRUE, TRUE, FALSE);
      break;
    case GNS_String:
      w = gtk_entry_new ();
      gtk_entry_set_text (GTK_ENTRY (w), pos->value.String.val);
      g_signal_connect (w, "toggled", &boolean_toggled, pos);
      gtk_box_pack_start (GTK_BOX (box), w, TRUE, TRUE, FALSE);
      label = gtk_label_new (pos->help);
      gtk_box_pack_start (GTK_BOX (box), label, TRUE, TRUE, FALSE);
      break;
    case GNS_MC:
      i = 0;
      while (pos->value.String.legalRange[i] != NULL)
        {
          w =
            gtk_check_button_new_with_label (pos->value.String.legalRange[i]);
          g_signal_connect (w, "toggled", &multi_toggled, pos);
          if ((NULL != strstr (pos->value.String.legalRange[i],
                               pos->value.String.val)) &&
              ((' ' == strstr (pos->value.String.legalRange[i],
                               pos->value.String.val)[strlen (pos->value.
                                                              String.
                                                              legalRange[i])])
               || ('\0' ==
                   strstr (pos->value.String.legalRange[i],
                           pos->value.String.val)[strlen (pos->value.String.
                                                          legalRange[i])]))
              &&
              ((pos->value.String.legalRange[i] ==
                strstr (pos->value.String.legalRange[i],
                        pos->value.String.val))
               || (' ' ==
                   strstr (pos->value.String.legalRange[i],
                           pos->value.String.val)[-1])))
            gtk_toggle_button_set_mode (GTK_TOGGLE_BUTTON (w, TRUE));
          gtk_box_pack_start (GTK_BOX (box), w, TRUE, TRUE, FALSE);
          i++;
        }
      break;
    case GNS_SC:
      w = NULL;
      i = 0;
      while (pos->value.String.legalRange[i] != NULL)
        {
          w =
            gtk_radio_button_new_with_label_from_widget
            (w, pos->value.String.legalRange[i]);
          g_signal_connect (w, "toggled", &multi_toggled, pos);
          gtk_box_pack_start (GTK_BOX (box), w, TRUE, TRUE, FALSE);
          if (0 ==
              strcmp (pos->value.String.legalRange[i], pos->value.String.val))
            gtk_toggle_button_set_mode (GTK_TOGGLE_BUTTON (w, TRUE));
          i++;
        }

      break;
    case GNS_Double:
      SNPRINTF (defStr, 128, "%llf", pos->value.Double.val);
      w = gtk_entry_new ();
      g_signal_connect (w, "changed", &string_toggled, pos);
      gtk_entry_set_text (GTK_ENTRY (w), defStr);
      gtk_box_pack_start (GTK_BOX (box), w, TRUE, TRUE, FALSE);
      break;
    case GNS_UInt64:
      SNPRINTF (defStr, 128, "%llu", pos->value.UInt64.val);
      w = gtk_entry_new ();
      gtk_entry_set_text (GTK_ENTRY (w), defStr);
      g_signal_connect (w, "changed", &string_toggled, pos);
      gtk_box_pack_start (GTK_BOX (box), w, TRUE, TRUE, FALSE);
      break;
    default:
      GE_ASSERT (NULL, 0);
      return 0;
    }
  label = gtk_label_new (pos->help);
  gtk_box_pack_start (GTK_BOX (box), label, TRUE, TRUE, FALSE);
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
  int have;
  if (!pos->visible)
    return 0;
  have = 0;
  notebook = GTK_NOTEBOOK (gtk_notebook_new ());
  vbox = gtk_vbox_new (FALSE, 0);
  label = gtk_label_new (pos->description);
  gtk_box_pack_start (GTK_BOX (vbox) notebook, TRUE, TRUE, FALSE);
  i = 0;
  while (NULL != (child = pos->children[i]))
    {
      switch (child->type & GNS_KindMask)
        {
        case GNS_Node:
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
      gtk_notebook_append_page (parent, vbox, label);
    }
  else
    {
      g_unref (vbox);
      g_unref (label);
    }
  return have;
}

static void
initView (struct GNS_Context *gns)
{
  GtkWidget *notebook;
  notebook = lookup_widget ("configNotebook");
  addNodeToTree (notebook, gns);
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
gboolean on_main_window_delete_eventsetup_gtk ()
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
