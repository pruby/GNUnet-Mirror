#include "platform.h"
#include "gnunet_util.h"

#include <gtk/gtk.h>


void on_step1_next_clicked (GtkButton * button, gpointer user_data);

void on_abort_clicked (GtkButton * button, gpointer user_data);

void on_step2_back_clicked (GtkButton * button, gpointer user_data);

void on_step2_next_clicked (GtkButton * button, gpointer user_data);

void on_step3_back_clicked (GtkButton * button, gpointer user_data);

void on_step3_next_clicked (GtkButton * button, gpointer user_data);

void on_step5_back_clicked (GtkButton * button, gpointer user_data);

void on_finish_clicked (GtkButton * button, gpointer user_data);

void on_saveYes_clicked (GtkButton * button, gpointer user_data);

void on_saveNo_clicked (GtkButton * button, gpointer user_data);

void on_assi_destroy (GtkObject * object, gpointer user_data);

void on_saveFailedOK_clicked (GtkButton * button, gpointer user_data);

void on_updateFailedOK_clicked (GtkButton * button, gpointer user_data);

void on_entIP_changed (GtkEditable * editable, gpointer user_data);

void on_cmbNIC_changed (GtkComboBox * combobox, gpointer user_data);

void on_chkFW_toggled (GtkToggleButton * togglebutton, gpointer user_data);

void on_entUp_changed (GtkEditable * editable, gpointer user_data);

void on_entDown_changed (GtkEditable * editable, gpointer user_data);

void
on_radGNUnet_toggled (GtkToggleButton * togglebutton, gpointer user_data);

void on_radShare_toggled (GtkToggleButton * togglebutton, gpointer user_data);

void on_entCPU_changed (GtkEditable * editable, gpointer user_data);

void on_chkMigr_toggled (GtkToggleButton * togglebutton, gpointer user_data);

void on_entQuota_changed (GtkEditable * editable, gpointer user_data);

void on_chkStart_toggled (GtkToggleButton * togglebutton, gpointer user_data);

void on_chkEnh_toggled (GtkToggleButton * togglebutton, gpointer user_data);

void on_chkUpdate_toggled (GtkToggleButton * togglebutton, gpointer user_data);

void on_step4_back_clicked (GtkButton * button, gpointer user_data);

void on_step4_next_clicked (GtkButton * button, gpointer user_data);

void on_entUser_changed (GtkEditable * editable, gpointer user_data);

void on_entGroup_changed (GtkEditable * editable, gpointer user_data);
