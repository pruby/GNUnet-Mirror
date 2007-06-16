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
 * @file setup/ncurses/wizard_curs.c
 * @brief A easy-to-use configuration assistant for curses
 * @author Nils Durner
 * @author Christian Grothoff
 *
 * TODO:
 * - use ectx to capture error messages and show them to
 *   the user properly (some currently printf'ed to console!)
 * - additional autodetections (IP, etc)
 * - share helper functions with mconf.c (refactoring)
 */

#include <dialog.h>

#undef _
#undef OK
#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_setup_lib.h"

#include "wizard_curs.h"
#include "mconf.h"

#ifndef MINGW
#include <termios.h>
#include <grp.h>
#endif

static struct GE_Context * ectx;

static struct GC_Configuration * cfg;

static int last;

static const char * cfg_fn;

static void showCursErr(const char * prefix,
			const char * error) {
  char * err;
	
  err = MALLOC(strlen(prefix) + strlen(error) + 2);
  sprintf(err,
	  "%s %s",
	  prefix,
	  error);
  dialog_msgbox(_("Error"),
		err,
		70,
		15,
		1);
  FREE(err);	
}

static void show_help(const char * helptext) {
  dialog_vars.help_button = 0;
  dialog_msgbox(_("Help"),
		helptext,
		20,
		70,
		TRUE);
}

static void show_error(const char * msg) {
  dialog_vars.help_button = 0;
  dialog_msgbox(_("Error!"),
		msg,
		20,
		70,
		TRUE);
}

static int query_yesno(const char * title,
		       const char * question,
		       const char * help,
		       const char * section,
		       const char * option) {
  int ret;

  if (help == NULL)
    dialog_vars.help_button = 0;
  else
    dialog_vars.help_button = 1;
  dialog_vars.cancel_label = _("No");
  dialog_vars.ok_label = _("Yes");
  while (true) {
    ret = dialog_yesno(title,	
		       question,
		       20,
		       70);
    switch(ret) {
    case DLG_EXIT_OK:
    case DLG_EXIT_CANCEL:
      if (0 != GC_set_configuration_value_string(cfg,
						 ectx,
						 section,
						 option,
						 ret == DLG_EXIT_OK
						 ? "YES"
						 : "NO")) {
	show_error(_("Internal error! (Choice invalid?)"));
	break;
      }
      return 1; /* advance */
    case DLG_EXIT_ESC:
      return 0; /* abort */
    case DLG_EXIT_HELP:
      show_help(help);
      break;
    case DLG_EXIT_EXTRA:
      return -1; /* back */
    default:
      GE_BREAK(ectx, 0);
      break;
    }
  }
}

static int query_string(const char * title,
			const char * question,
			const char * help,
			const char * section,
			const char * option,
			const char * def) {
  int ret;
  int msel;
  DIALOG_FORMITEM fitem;

  if (help == NULL)
    dialog_vars.help_button = 0;
  else
    dialog_vars.help_button = 1;
  dialog_vars.cancel_label = _("Abort");
  dialog_vars.ok_label = _("Ok");
  fitem.type = 0;
  fitem.name = STRDUP(question);
  fitem.name_len = strlen(question);
  fitem.name_y = 3;
  fitem.name_x = 5;
  fitem.name_free = 0;
  fitem.text_y = 5;
  fitem.text_x = 5;
  fitem.text_flen = 55;
  fitem.text_ilen = 63;
  fitem.text_free = 0;
  fitem.help_free = 0;
  fitem.text = MALLOC(65536);
  strcpy(fitem.text,
	 def);
  fitem.text_len = strlen(fitem.text);
  fitem.help = STRDUP(help);
  msel = 0;

  ret = 2;
  while (ret == 2) {
    ret = dlg_form(title,
		   "",
		   20,
		   70,
		   15,
		   1,
		   &fitem,
		   &msel);
    switch(ret) {
    case DLG_EXIT_OK:
      if (0 != GC_set_configuration_value_string(cfg,
						 ectx,
						 section,
						 option,
						 fitem.text)) {
	show_error(_("Internal error! (Choice invalid?)"));
	ret = 2;
      } else {
	ret = 1; /* advance */
      }
      break;
    case DLG_EXIT_CANCEL:
    case DLG_EXIT_ESC:
      ret = 0; /* abort */
      break;
    case DLG_EXIT_HELP:
      show_help(help);
      ret = 2;
      break;
    case DLG_EXIT_EXTRA:
      ret = -1; /* back */
      break;
    default:
      GE_BREAK(ectx, 0);
      ret = 0;
      break;
    }
  }
  FREE(fitem.name);
  FREE(fitem.text);
  FREE(fitem.help);
  return ret;
}

static int welcome() {
  dialog_vars.help_button = 0;
  dialog_msgbox(_("GNUnet configuration"),
		_("Welcome to GNUnet!\n\nThis assistant will ask you a few basic questions "
		  "in order to configure GNUnet.\n\nPlease visit our homepage at\n\t"
		  "http://gnunet.org/\nand join our community at\n\t"
		  "http://gnunet.org/drupal/\n\nHave a lot of fun,\n\nthe GNUnet team"),
		20,
		70,
		TRUE);
  return 1;
}

#define MAX_NIC 64

static int insert_nic_curs(const char * name,
			   int defaultNIC,
			   void * cls) {
  DIALOG_LISTITEM * nic_items = cls;
  DIALOG_LISTITEM * item;
  unsigned int pos;

  pos = 0;
  while ( (pos < MAX_NIC) &&
	  (nic_items[pos].text != NULL) )
    pos++;
  if (pos == MAX_NIC)
    return SYSERR;
  item = &nic_items[pos];
  item->name = "";
  item->text = STRDUP(name);
  item->help = "";
  item->state = defaultNIC;
  return OK;
}

static int network_interface() {
  DIALOG_LISTITEM nic_items[MAX_NIC];
  unsigned int total;
  int ret;
  int msel;
  DIALOG_FORMITEM fitem;

  fitem.type = 0;
  fitem.name = "";
  fitem.name_len = strlen(fitem.name);
  fitem.name_y = 3;
  fitem.name_x = 5;
  fitem.name_free = 0;
  fitem.text_y = 5;
  fitem.text_x = 5;
  fitem.text_flen = 55;
  fitem.text_ilen = 63;
  fitem.text_free = 0;
  fitem.help_free = 0;
  memset(nic_items,
	 0,
	 sizeof(DIALOG_LISTITEM) * MAX_NIC);
  os_list_network_interfaces(NULL,
			     &insert_nic_curs,
			     nic_items);
  total = 0;
  while ( (total < MAX_NIC) &&
	  (nic_items[total].text != NULL) ) {
    if (nic_items[total].state)
      msel = total;
    total++;
  }
  if (total > 0) {
    while (true) {
      ret = dlg_menu(_("GNUnet configuration"),
		     _("Choose the network interface that connects your computer to "
		       "the internet from the list below."),
		     20,
		     70,
		     10,
		     total,
		     nic_items,
		     &msel,
		     NULL);
      switch (ret) {
      case DLG_EXIT_OK:
	if (0 != GC_set_configuration_value_choice(cfg,
						   ectx,
						   "NETWORK",
						   "INTERFACE",
						   nic_items[msel].name)) {
	  show_error(_("Internal error! (Choice invalid?)"));
	  break;
	}
	return 1;
      case DLG_EXIT_HELP:
	show_help(_("The \"Network interface\" is the device "
		    "that connects your computer to the internet. This is usually a modem, "
		    "an ISDN card or a network card in case you are using DSL."));
	break;
      case DLG_EXIT_ESC:
      case DLG_EXIT_ERROR:
      case DLG_EXIT_CANCEL:
	return 0;
      }
    }
  }
  return query_string(_("Network configuration: interface"),
		      _("What is the name of the network interface that connects your computer to the Internet?"),
		      _("The \"Network interface\" is the device "
			"that connects your computer to the internet. This is usually a modem, "
			"an ISDN card or a network card in case you are using DSL."),
		      "NETWORK",
		      "INTERFACE",
		      "eth0");
}

static int nat_limited() {
  /* TODO: try autodetect! */
  return query_yesno(_("Network configuration: NAT"),
		     _("Is this machine behind "
		       "NAT?\n\nIf you are connected to the internet through another computer "
		       "doing SNAT, a router or a \"hardware firewall\" and other computers "
		       "on the internet cannot connect to this computer, say \"yes\" here. "
		       "Answer \"no\" on direct connections through modems, ISDN cards and "
		       "DNAT (also known as \"port forwarding\")."),
		     NULL,
		     "NAT",
		     "LIMITED");
}

static int ip_address() {
  /* TODO: try autodetect! */
  return query_string(_("Network configuration: IP"),
		      _("What is this computer's public IP address or hostname?"),
		      _("If your provider always assigns the same "
			"IP-Address to you (a \"static\" IP-Address), enter it into the "
			"\"IP-Address\" field. If your IP-Address changes every now and then "
			"(\"dynamic\" IP-Address) but there's a hostname that always points "
			"to your actual IP-Address (\"Dynamic DNS\"), you can also enter it "
			"here.\n"
			"If left empty, GNUnet will try to automatically detect the IP.\n"
			"You can specify a hostname, GNUnet will then use DNS to resolve it.\n"
			"If in doubt, leave this empty."),
		      "NETWORK",
		      "IP",
		      "");
}

static int network_load_up() {
  return query_string(_("Bandwidth configuration: upload"),
		      _("How much upstream bandwidth (in bytes/s) may be used?"),
		      _("You can limit GNUnet's resource usage "
			"here.\n\nThe \"upstream\" is the data channel through which data "
			"is *sent* to the internet. The limit is the maximum amount"
			"which GNUnet is allowed to use. If you have a flatrate, you can set it to "
			"the maximum speed of your internet connection. You should not use a value "
			"that is higher than what your actual connection allows."),
		      "LOAD",
		      "MAXNETUPBPSTOTAL",
		      "50000");
}

static int network_load_down() {
  return query_string(_("Bandwidth configuration: download"),
		      _("How much downstream bandwidth (in bytes/s) may be used?"),
		      _("You can limit GNUnet's resource usage "
			"here.\n\nThe \"downstream\" is the data channel through which data "
			"is *received* from the internet. The limit is the maximum amount"
			"which GNUnet is allowed to use. If you have a flatrate, you can set it to "
			"the maximum speed of your internet connection. You should not use a value "
			"that is higher than what your actual connection allows."),
		      "LOAD",
		      "MAXNETDOWNBPSTOTAL",
		      "50000");
}

static int disk_quota() {
  return query_string(_("Quota configuration"),
		      _("What is the maximum size of the datastore in MB?"),
		      _("The GNUnet datastore contains all content that "
			"GNUnet needs to store (indexed, inserted and migrated content)."),
		      "FS",
		      "QUOTA",
		      "1024");
}

static int user() {
  if (YES != os_modify_user(YES,
			    YES,
			    "gnunet",
			    "gnunet"))
    return last; /* ignore option */
  return query_string(_("Daemon configuration: user account"),
		      _("As which user should gnunetd be run?"),
		      _("For security reasons, it is a good idea to let this setup create "
			"a new user account under which the GNUnet service is started "
			"at system startup.\n\n"
			"However, GNUnet may not be able to access files other than its own. "
			"This includes files you want to publish in GNUnet. You'll have to "
			"grant read permissions to the user specified below.\n\n"
			"Leave the field empty to run GNUnet with system privileges.\n"),
		      "GNUNETD",
		      "USER",
		      "gnunet");
}

static int group() {
  if (YES != os_modify_user(YES,
			    YES,
			    "gnunet",
			    "gnunet"))
    return last; /* ignore option */
  return query_string(_("Daemon configuration: group account"),
		      _("As which group should gnunetd be run?"),
		      _("For security reasons, it is a good idea to let this setup create "
			"a new group for the chosen user account.\n\n"
			"You can also specify a already existant group here.\n\n"
			"Only members of this group will be allowed to start and stop the "
			"the GNUnet server and have access to GNUnet server data.\n"),
		      "GNUNETD",
		      "GROUP",
		      "gnunet");
}


static int autostart() {
  return query_yesno(_("GNUnet configuration"),
		     _("Do you want to automatically launch GNUnet as a system service?"),
		     _("If you say \"yes\" here, the GNUnet background process will be "
		       "automatically started when you turn on your computer. If you say \"no\""
		       " here, you have to launch GNUnet yourself each time you want to use it."),
		     "GNUNETD",
		     "AUTOSTART");
}

/**
 * Save configuration, setup username, group and autostart.
 */
static int finish() {
  const char * prefix;
  char * err;
  int ret;
  char * user_name;
  char * group_name;

  ret = OK;

  if ( (0 != GC_test_dirty(cfg)) &&
       (0 != GC_write_configuration(cfg, cfg_fn)) ) {
    prefix = _("Unable to save configuration file `%s':");
    err = MALLOC(strlen(cfg_fn) + strlen(prefix) + 1);
    sprintf(err, prefix, cfg_fn);
    showCursErr(err, STRERROR(errno));
    ret = SYSERR;
  }
  user_name = NULL;
  GC_get_configuration_value_string(cfg,
				    "GNUNETD",
				    "USER",
				    "",
				    &user_name);
  GC_get_configuration_value_string(cfg,
				    "GNUNETD",
				    "GROUP",
				    "",
				    &group_name);
  if ( ( (strlen(user_name) > 0) ||
	 (strlen(group_name) > 0) ) &&
       (OK == os_modify_user(YES,
			     YES,
			     user_name,
			     group_name)) &&
       (OK != os_modify_user(NO,
			     YES,
			     user_name,
			     group_name)) ) {
    showCursErr(_("Unable to create user account for daemon."),
		"");
    ret = SYSERR;
  }	
  if ( (YES == GC_get_configuration_value_yesno(cfg,
						"GNUNETD",
						"AUTOSTART",
						NO)) &&
       (YES != os_modify_autostart(ectx,
				   NO,
				   YES,
				   "gnunetd", /* specify full path? */
				   user_name,
				   group_name)) ) {
    showCursErr(_("Unable to setup autostart for daemon."),
		"");
    ret = SYSERR;
  }
  FREE(user_name);
  FREE(group_name);
  return ret;
}

static int save_config() {
  int ret;

  /* TODO: check configuration changed! */
  dialog_vars.help_button = 0;
  ret = dialog_yesno(_("Save configuration?"),
		     _("Save configuration now?"),
		     5,
		     60);
  switch(ret) {
  case DLG_EXIT_OK:
    if (OK != finish())
      return 0; /* error */
    return 1;
  case DLG_EXIT_CANCEL:
    return 1; /* advance */
  case DLG_EXIT_ESC:
    return 0; /* abort */
  case DLG_EXIT_EXTRA:
    return -1; /* back */
  default:
    GE_BREAK(ectx, 0);
    break;
  }
  return 1;
}

int wizard_curs_mainsetup_curses(int argc,
				 const char **argv,
				 struct PluginHandle * self,
				 struct GE_Context * e,
				 struct GC_Configuration * c,
				 struct GNS_Context * gns,
				 const char * filename,
				 int is_daemon) {
  struct termios ios_org;
  unsigned int phase;
  int ret;
  int dir;

  ectx = e;
  cfg = c;
  cfg_fn = filename;
#ifndef MINGW
  tcgetattr(1, &ios_org);
#endif
  dialog_vars.backtitle = _("GNUnet Configuration");
  dialog_vars.item_help = 1;
  dialog_vars.help_button = 1;
  dialog_vars.extra_button = 1;
  dialog_vars.extra_label = _("Back");
  init_dialog(stdin, stderr);

  phase = 0;
  ret = NO;
  while (ret == NO) {
    switch(phase) {
    case 0:
      dir = welcome();
      break;
    case 1:
      dir = network_interface();
      break;
    case 2:
      dir = nat_limited();
      break;
    case 3:
      dir = ip_address();
      break;
    case 4:
      dir = network_load_up();
      break;
    case 5:
      dir = network_load_down();
      break;
    case 6:
      dir = disk_quota();
      break;
    case 7:
      dir = user();
      break;
    case 8:
      dir = group();
      break;
    case 9:
      dir = autostart();
      break;
    case 10:
      dir = save_config();
      break;
    case 11:
      dir = 0;
      ret = OK;
      break;
    default:
      GE_BREAK(NULL, 0);
      dir = 0;
      break;
    }
    phase += dir;
    last = dir;
    if (dir == 0)
      ret = SYSERR;
  }
  end_dialog();
#ifndef MINGW
  tcsetattr(1, TCSAFLUSH, &ios_org);
#endif
  return ret;
}

/* end of wizard_curs.c */
