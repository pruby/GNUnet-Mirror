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
 * @brief GNUnet Setup
 * @file setup/gtk/gconf.c
 * @author Nils Durner
 * @author Christian Grothoff
 *
 * TODO:
 * - process save configuration event
 * - process editing signals
 * - avoid completely killing existing tree after each edit
 */

#include "gnunet_setup_lib.h"
#include "glade_support.h"
#include "platform.h"

/**
 * @brief definition of the entries in the main model for
 *  the setup tree
 */
enum {
  SETUP_SECTION,
  SETUP_OPTION,
  SETUP_TREENODE,
  SETUP_ZERO,
  SETUP_FALSE,
  SETUP_TRUE,
  SETUP_DWIDTH,
  SETUP_HWIDTH,
  SETUP_WRAP,
  SETUP_EDIT_BGCOLOR,
  SETUP_DEFAULT_VALUE,
  SETUP_BOOL_VALUE,
  SETUP_TEXT_VALUE,
  SETUP_COMBO_MODEL,
  SETUP_TOGGLE_VIS,
  SETUP_TEXT_VIS,
  SETUP_COMBO_VIS,
  SETUP_DESCRIPTION,
  SETUP_HELPTEXT,
  SETUP_NUM,
};

static GtkListStore * no_model;

static struct GC_Configuration * cfg;

static struct GE_Context * ectx;

static void addToTree(GtkTreeStore * model,
		      GtkTreeIter * parent,
		      struct GNS_Tree * pos) {
  GtkTreeIter it;
  GtkTreeIter it2;
  int i;
  GtkListStore * cmodel;
  char defStr[128];
  char valStr[128];

  gtk_tree_store_append(model,
			&it,
			parent);
  gtk_tree_store_set(model,
		     &it,
		     SETUP_SECTION, pos->section,
		     SETUP_OPTION, pos->option,
		     SETUP_TREENODE, pos,
		     SETUP_ZERO, 0,
		     SETUP_FALSE, FALSE,
		     SETUP_TRUE, TRUE,
		     SETUP_DWIDTH, 120,
		     SETUP_HWIDTH, 400,
		     SETUP_WRAP, PANGO_WRAP_WORD_CHAR,
		     SETUP_EDIT_BGCOLOR, "yellow",
		     SETUP_DEFAULT_VALUE, "",
		     SETUP_BOOL_VALUE, FALSE,
		     SETUP_TEXT_VALUE, "",
		     SETUP_COMBO_MODEL, no_model,
		     SETUP_TOGGLE_VIS, FALSE,
		     SETUP_TEXT_VIS, FALSE,
		     SETUP_COMBO_VIS, FALSE,
		     SETUP_DESCRIPTION, pos->description,
		     SETUP_HELPTEXT, pos->help,
		     -1);
  switch (pos->type & GNS_KindMask) {
  case GNS_Node: 
    i = 0;
    while (pos->children[i] != NULL) {
      addToTree(model,
		&it,
		pos->children[i]);
      i++;
    }
    break;
  case GNS_Leaf:
    switch (pos->type & GNS_TypeMask) {
    case GNS_Boolean:
      gtk_tree_store_set(model,
			 &it,
			 SETUP_DEFAULT_VALUE, pos->value.Boolean.def ? "YES" : "NO",
			 SETUP_BOOL_VALUE, pos->value.Boolean.val ? TRUE : FALSE,
			 SETUP_TOGGLE_VIS, TRUE,
			 -1);
      break;
    case GNS_String:
      cmodel = gtk_list_store_new(1,
				  G_TYPE_STRING);
      gtk_tree_store_set(model,
			 &it,
			 SETUP_DEFAULT_VALUE, pos->value.String.def,
			 SETUP_TEXT_VALUE, pos->value.String.val,
			 SETUP_COMBO_MODEL, cmodel,
			 -1);
      if (pos->value.String.legalRange[0] == NULL) {
	gtk_list_store_insert_with_values(cmodel,
					  &it2,
					  -1,
					  0, pos->value.String.val,
					  -1);
	gtk_tree_store_set(model,
			   &it,
			   SETUP_TEXT_VIS, TRUE,
			   SETUP_COMBO_VIS, TRUE,
			   -1);
      } else {
	i = 0;
	while (pos->value.String.legalRange[i] != NULL) {
	  gtk_list_store_insert_with_values(cmodel,
					    &it2,
					    -1,
					    0, pos->value.String.legalRange[i],
					    -1);
	  i++;
	}
	gtk_tree_store_set(model,
			   &it,
			   SETUP_COMBO_VIS, TRUE,
			   -1);
      }
      break;
    case GNS_Double:
      cmodel = gtk_list_store_new(1,
				  G_TYPE_STRING);
      SNPRINTF(defStr, 128, "%f", pos->value.Double.def);
      SNPRINTF(valStr, 128, "%f", pos->value.Double.val);
      gtk_list_store_insert_with_values(cmodel,
					&it2,
					-1,
					0, valStr, 
					-1);
      if (0 != strcmp(valStr, defStr)) {
	gtk_list_store_insert_with_values(cmodel,
					&it2,
					  -1,
					  0, valStr, 
					  -1);
      }
      gtk_tree_store_set(model,
			 &it,
			 SETUP_DEFAULT_VALUE, defStr,
			 SETUP_TEXT_VALUE, valStr,
			 SETUP_COMBO_VIS, TRUE,
			 SETUP_TEXT_VIS, TRUE,
			 SETUP_COMBO_MODEL, cmodel,
			 -1);
      break;
    case GNS_UInt64:
      cmodel = gtk_list_store_new(1,
				  G_TYPE_STRING);
      SNPRINTF(defStr, 128, "%llu", pos->value.UInt64.def);
      SNPRINTF(valStr, 128, "%llu", pos->value.UInt64.val);
      gtk_list_store_insert_with_values(cmodel,
					&it2,
					-1,
					0, valStr, 
					-1);
      if (0 != strcmp(valStr, defStr)) {
	gtk_list_store_insert_with_values(cmodel,
					&it2,
					  -1,
					  0, valStr, 
					  -1);
      }
      gtk_tree_store_set(model,
			 &it,
			 SETUP_DEFAULT_VALUE, defStr,
			 SETUP_COMBO_VIS, TRUE,
			 SETUP_TEXT_VALUE, valStr,
			 SETUP_TEXT_VIS, TRUE,
			 SETUP_COMBO_MODEL, cmodel,
			 -1);
      break;
    default:
      GE_ASSERT(NULL, 0);
      gtk_tree_store_remove(model,
			    &it);
      return;
    }
    break;    
  case GNS_Root:
  default:
    GE_ASSERT(NULL, 0);
    gtk_tree_store_remove(model,
			  &it);
    return;
  }	  
}

static void updateTreeModel(struct GNS_Context * gns) {
  GtkWidget * treeView;
  GtkTreeStore * model;
  struct GNS_Tree * tree;
  int i;

  model = gtk_tree_store_new(SETUP_NUM,
			     G_TYPE_STRING, /* section */
			     G_TYPE_STRING, /* option */
			     G_TYPE_POINTER,  /* node */
			     G_TYPE_INT, /* always 0 */
			     G_TYPE_BOOLEAN, /* always FALSE */
			     G_TYPE_BOOLEAN, /* always TRUE */
			     G_TYPE_INT, /* dwidth */
			     G_TYPE_INT, /* hwidth */
			     G_TYPE_INT, /* wrap */
			     G_TYPE_STRING, /* edit bg color */
			     G_TYPE_STRING, /* default value */
			     G_TYPE_BOOLEAN, /* true/false value */
			     G_TYPE_STRING, /* current text value */
			     GTK_TYPE_LIST_STORE, /* combo model */
			     G_TYPE_BOOLEAN, /* toggle visible? */
			     G_TYPE_BOOLEAN, /* text   visible? */
			     G_TYPE_BOOLEAN, /* combo  visible? */
			     G_TYPE_STRING,  /* description */
			     G_TYPE_STRING);  /* help text */
  
  tree = GNS_get_tree(gns);
  i = 0;
  while (tree->children[i] != NULL) {
    addToTree(model,
	      NULL,
	      tree->children[i]);
    i++;
  }
  
  treeView = lookup_widget("configTreeView");
  gtk_tree_view_set_model(GTK_TREE_VIEW(treeView),
			  GTK_TREE_MODEL(model));
}

static void toggleBooleanHandler(GtkCellRendererToggle * rdner,
				 gchar * path,
				 gpointer user_data) {
  struct GNS_Context * gns = user_data;

  printf("FIXME: find out which entry was toggled, change configuration and regenerate tree!\n");
  updateTreeModel(gns);
}

static void editedTextHandler(GtkCellRendererToggle * rdner,
			      gchar * arg1,
			      gchar * arg2,
			      gpointer user_data) {
  struct GNS_Context * gns = user_data;

  printf("FIXME: find out which entry was edited, change configuration and regenerate tree!\n");
  updateTreeModel(gns);
}




static void initTreeView(struct GNS_Context * gns) {
  GtkWidget * treeView;
  GtkTreeViewColumn * column;
  GtkCellRenderer * renderer;
  int col;

  treeView = lookup_widget("configTreeView");


  renderer = gtk_cell_renderer_text_new();
  col = gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(treeView),
						    -1,
						    _("Description"),
						    renderer,
						    "text", SETUP_DESCRIPTION,
						    "wrap-width", SETUP_DWIDTH,
						    "wrap-mode", SETUP_WRAP,
						    NULL);
  column = gtk_tree_view_get_column(GTK_TREE_VIEW(treeView),
				    col - 1);
  gtk_tree_view_column_set_resizable(column, TRUE);


  renderer = gtk_cell_renderer_toggle_new();
  g_signal_connect(renderer,
		   "toggled",
		   G_CALLBACK(&toggleBooleanHandler),
		   gns);
  col = gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(treeView),
						    -1,
						    _("Y/N"),
						    renderer,
						    "active", SETUP_BOOL_VALUE,
						    "visible", SETUP_TOGGLE_VIS,
						    "cell-background", SETUP_EDIT_BGCOLOR,
						    NULL);
  column = gtk_tree_view_get_column(GTK_TREE_VIEW(treeView),
				    col - 1);
  gtk_tree_view_column_set_resizable(column, TRUE);


  renderer = gtk_cell_renderer_combo_new();
  g_signal_connect(renderer,
		   "edited",
		   G_CALLBACK(&editedTextHandler),
		   gns);
  col = gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(treeView),
						    -1,
						    _("Value"),
						    renderer,
						    "text", SETUP_TEXT_VALUE,
						    "visible", SETUP_COMBO_VIS,
						    "model", SETUP_COMBO_MODEL,
						    "text-column", SETUP_ZERO,
						    "has-entry", SETUP_TEXT_VIS,
						    "background", SETUP_EDIT_BGCOLOR,
						    "background-set", SETUP_TRUE,
						    "editable", SETUP_TRUE,
						    NULL);
  column = gtk_tree_view_get_column(GTK_TREE_VIEW(treeView),
				    col - 1);
  gtk_tree_view_column_set_resizable(column, TRUE);


  renderer = gtk_cell_renderer_text_new();
  col = gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(treeView),
						    -1,
						    _("Default"),
						    renderer,
						    "text", SETUP_DEFAULT_VALUE,
						    NULL);
  column = gtk_tree_view_get_column(GTK_TREE_VIEW(treeView),
				    col - 1);
  gtk_tree_view_column_set_resizable(column, TRUE);


  renderer = gtk_cell_renderer_text_new();
  col = gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(treeView),
						    -1,
						    _("Help"),
						    renderer,
						    "text", SETUP_HELPTEXT,
						    "wrap-width", SETUP_HWIDTH,
						    "wrap-mode", SETUP_WRAP,
						    NULL);
  column = gtk_tree_view_get_column(GTK_TREE_VIEW(treeView),
				    col - 1);
  gtk_tree_view_column_set_resizable(column, TRUE);


  renderer = gtk_cell_renderer_text_new();
  col = gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(treeView),
						    -1,
						    _("Section"),
						    renderer,
						    "text", SETUP_SECTION,
						    NULL);
  column = gtk_tree_view_get_column(GTK_TREE_VIEW(treeView),
				    col - 1);
  gtk_tree_view_column_set_resizable(column, TRUE);


  renderer = gtk_cell_renderer_text_new();
  col = gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(treeView),
						    -1,
						    _("Option"),
						    renderer,
						    "text", SETUP_OPTION,
						    NULL);
  column = gtk_tree_view_get_column(GTK_TREE_VIEW(treeView),
				    col - 1);
  gtk_tree_view_column_set_resizable(column, TRUE);
}


int gconf_main_post_init(struct PluginHandle * self,
			 struct GE_Context * e,
			 struct GC_Configuration * c,
			 struct GNS_Context * gns,
			 const char * filename,
			 int is_daemon) {
  GtkWidget * mainWindow;

  cfg = c;
  ectx = e;
  no_model = gtk_list_store_new(1,
				G_TYPE_STRING);
  setLibrary(self);
  mainWindow = get_xml("setupWindow");
  updateTreeModel(gns);
  initTreeView(gns);
  gtk_window_maximize(GTK_WINDOW(mainWindow));
  gtk_widget_show(mainWindow);
  gdk_threads_enter();
#ifdef WINDOWS
  SetCursor(LoadCursor(NULL, IDC_ARROW));
#endif
  gtk_main();
  gdk_threads_leave();
  destroyMainXML(); 
  setLibrary(NULL);
  g_object_unref(G_OBJECT(no_model));
  no_model = NULL;
  return 0;
}


/* Main */
int gconf_mainsetup_gtk(int argc, 
			const char ** argv, 
			struct PluginHandle * self,
			struct GE_Context * ectx,
			struct GC_Configuration * cfg,
			struct GNS_Context * gns,
			const char * filename,
			int is_daemon) {
  g_thread_init(NULL);
  gtk_init(&argc, (char***) &argv);
#if ENABLE_NLS
  bind_textdomain_codeset(PACKAGE, "UTF-8"); /* for gtk */
#endif
#ifdef WINDOWS
  FreeConsole();
#endif

  /* add_pixmap_directory (PACKAGE_DATA_DIR "/" PACKAGE "/pixmaps"); */
  /* add_pixmap_directory (PACKAGE_SOURCE_DIR "/pixmaps"); */
  return gconf_main_post_init(self,
			      ectx,
			      cfg,
			      gns, 
			      filename,
			      is_daemon);
}
