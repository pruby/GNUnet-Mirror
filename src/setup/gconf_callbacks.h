#include <gtk/gtk.h>


void on_window1_destroy (GtkObject * object, gpointer user_data);

void
on_window1_size_request (GtkWidget * widget,
			 GtkRequisition * requisition, gpointer user_data);

gboolean
on_window1_delete_event (GtkWidget * widget,
			 GdkEvent * event, gpointer user_data);

void on_load1_activate (GtkMenuItem * menuitem, gpointer user_data);

void on_save1_activate (GtkMenuItem * menuitem, gpointer user_data);

void on_save_as1_activate (GtkMenuItem * menuitem, gpointer user_data);

void on_quit1_activate (GtkMenuItem * menuitem, gpointer user_data);

void on_show_name1_activate (GtkMenuItem * menuitem, gpointer user_data);

void on_show_range1_activate (GtkMenuItem * menuitem, gpointer user_data);

void on_show_data1_activate (GtkMenuItem * menuitem, gpointer user_data);

void
on_show_all_options1_activate (GtkMenuItem * menuitem, gpointer user_data);

void
on_show_debug_info1_activate (GtkMenuItem * menuitem, gpointer user_data);

void on_introduction1_activate (GtkMenuItem * menuitem, gpointer user_data);

void on_about1_activate (GtkMenuItem * menuitem, gpointer user_data);

void on_license1_activate (GtkMenuItem * menuitem, gpointer user_data);

void on_back_pressed (GtkButton * button, gpointer user_data);

void on_load_pressed (GtkButton * button, gpointer user_data);

void on_save_pressed (GtkButton * button, gpointer user_data);

void on_single_clicked (GtkButton * button, gpointer user_data);

void on_split_clicked (GtkButton * button, gpointer user_data);

void on_full_clicked (GtkButton * button, gpointer user_data);

void on_collapse_pressed (GtkButton * button, gpointer user_data);

void on_expand_pressed (GtkButton * button, gpointer user_data);

void on_treeview2_cursor_changed (GtkTreeView * treeview, gpointer user_data);

gboolean
on_treeview1_button_press_event (GtkWidget * widget,
				 GdkEventButton * event, gpointer user_data);

gboolean
on_treeview2_key_press_event (GtkWidget * widget,
			      GdkEventKey * event, gpointer user_data);

gboolean
on_treeview2_button_press_event (GtkWidget * widget,
				 GdkEventButton * event, gpointer user_data);
