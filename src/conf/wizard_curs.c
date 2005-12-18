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
 * @file conf/wizard_curs.c
 * @brief A easy-to-use configuration assistant for curses
 * @author Nils Durner
 */

#include "gnunet_util.h"
#include "platform.h"

#ifndef MINGW
  #include <grp.h>
#endif

#define LKC_DIRECT_LINK
#include "lkc.h"

#include "mconf_dialog.h"
#include "wizard_util.h"
#include "mconf.h"
#include "wizard_curs.h"
#include "confdata.h"


extern int cols, rows;

static struct dialog_list_item **nic_items;
static int nic_item_count = 0;

void showCursErr(const char *prefix,
		 const char *error) {
  char *err;
	
  err = malloc(strlen(prefix) + strlen(error) + 2);
  sprintf(err,
	  "%s %s",
	  prefix,
	  error);
  dialog_msgbox(_("Error"),
		err,
		rows,
		cols - 5,
		1);
  free(err);	
}

void insert_nic_curs(const char *name,
		     int defaultNIC,
		     void * cls)
{
	struct dialog_list_item *item;

	/* Copy NIC data */	
	nic_items = (nic_item_count++) ?
		realloc(nic_items, nic_item_count * sizeof(struct dialog_list_item *)) :
		malloc(sizeof(struct dialog_list_item *));

	item = malloc(sizeof(struct dialog_list_item));
	memset(item, 0, sizeof(struct dialog_list_item));
	nic_items[nic_item_count-1] = item;
	item->name = STRDUP(name);
	item->namelen = strlen(name);
  item->selected = wiz_is_nic_default(name, defaultNIC);
}

int wizard_curs_main(int argc, char **argv)
{
  void *active_ptr = NULL;
  int idx, ret, autostart = 0, adv = 0;
  struct symbol *sym;
  char *defval;
  char * user_name = NULL;
  char * group_name = NULL;
  char *confFile;
  char * filename;
  char *defuser;
  const char *confUser;
  char *defgroup;
  const char *confGroup;

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

  init_dialog();
  init_wsize();
  dialog_clear();

  if (dialog_msgbox(_("GNUnet configuration"),
		    _("Welcome to GNUnet!\n\nThis assistant will ask you a few basic questions "
		      "in order to configure GNUnet.\n\nPlease visit our homepage at\n\t"
		      "http://gnunet.org/\nand join our community at\n\t"
		      "http://gnunet.org/drupal/\n\nHave a lot of fun,\n\nthe GNUnet team"),
		    rows, cols - 5, 1) == -1)
    goto end;

  dialog_clear();
  	
  enumNetworkIfs(insert_nic_curs, NULL);

  /* Network interface */
  if (nic_item_count) {
    while (true) {
      ret = dialog_menu(_("GNUnet configuration"),
			_("Choose the network interface that connects your computer to "
			  "the internet from the list below."), rows, cols - 5, 10,
			0, active_ptr, nic_item_count, nic_items);

      if (ret == 2) {
	/* Help */
	dialog_msgbox(_("Help"), _("The \"Network interface\" is the device "
				   "that connects your computer to the internet. This is usually a modem, "
				   "an ISDN card or a network card in case you are using DSL."), rows,
		      cols - 5, 1);
      }
      else if (ret <= 1) {
	/* Select or Exit */
#ifdef MINGW
	char nic[21];
	char *dst;
#else
	char *nic;
#endif
	for(idx = 0; idx < nic_item_count; idx++) {
	
	  if (nic_items[idx]->selected) {
#ifdef MINGW
	    char *src = strrchr(nic_items[idx]->name, '-') + 2;
	    dst = nic;
	    while(*src)
	      *dst++ = *src++;
	    dst[-1] = 0;
#else
	    nic = nic_items[idx]->name;
#endif
	    sym = sym_lookup("INTERFACE", "NETWORK", 0);
	    sym_set_string_value(sym, nic);
	    sym = sym_lookup("INTERFACES", "LOAD", 0);
	    sym_set_string_value(sym, nic);
	  }
	
	  free(nic_items[idx]->name);
	  free(nic_items[idx]);
	}
	free(nic_items);
	
	break;
      }
    }

    if (ret == 1 || ret == -1)
      goto end;
  }
  else {
    /* We are not root, just ask for the interface */
    while(true) {
      ret = dialog_inputbox(_("GNUnet configuration"),
			    _("What is the name of "			\
			      "the network interface that connects your computer to the Internet?"),
			    rows, cols - 5, "eth0");

      if (ret == 1) {
	/* Help */
	dialog_msgbox(_("Help"),
		      _("The \"Network interface\" is the device "
			"that connects your computer to the internet. This is usually a modem, "
			"an ISDN card or a network card in case you are using DSL."),
		      rows, cols - 5, 1);
      }
      else if (ret <= 0)
	break;
    }

    if (ret == -1)
      goto end;

    sym = sym_lookup("INTERFACE", "NETWORK", 0);
    sym_set_string_value(sym, dialog_input_result);
    sym = sym_lookup("INTERFACES", "LOAD", 0);
    sym_set_string_value(sym, dialog_input_result);
  }

  dialog_clear();

  /* IP address */
  if ((sym = sym_find("IP", "NETWORK"))) {
    sym_calc_value_ext(sym, 1);
    defval = (char *) sym_get_string_value(sym);
  }
  else
    defval = NULL;

  while(true) {
    ret = dialog_inputbox(_("GNUnet configuration"),
			  _("What is this computer's "
			    "public IP address or hostname?\n\nIf in doubt, leave this empty."),
			  rows, cols - 5, defval ? defval : "");

    if (ret == 1) {
      /* Help */
      dialog_msgbox(_("Help"),
		    _("If your provider always assigns the same "
		      "IP-Address to you (a \"static\" IP-Address), enter it into the "
		      "\"IP-Address\" field. If your IP-Address changes every now and then "
		      "(\"dynamic\" IP-Address) but there's a hostname that always points "
		      "to your actual IP-Address (\"Dynamic DNS\"), you can also enter it "
		      "here.\nIf in doubt, leave the field empty. GNUnet will then try to "
		      "determine your IP-Address."), rows, cols - 5, 1);
    }
    else if (ret <= 0)
      break;
  }

  if (ret == -1)
    goto end;

  sym_set_string_value(sym, dialog_input_result);

  dialog_clear();

  /* NAT? */
  sym = sym_find("LIMITED", "NAT");
  while(true) {
    ret = dialog_yesno(_("GNUnet configuration"),
		       _("Is this machine behind "
			 "NAT?\n\nIf you are connected to the internet through another computer "
			 "doing SNAT, a router or a \"hardware firewall\" and other computers "
			 "on the internet cannot connect to this computer, say \"yes\" here. "
			 "Answer \"no\" on direct connections through modems, ISDN cards and "
			 "DNAT (also known as \"port forwarding\")."), rows, cols - 5);

    if (ret != -2)
      break;
  }

  if (ret == -1)
    goto end;
  else
    sym_set_tristate_value(sym, !ret); /* ret is inverted */

  /* Upstream */
  if ((sym = sym_find("MAXNETUPBPSTOTAL", "LOAD"))) {
    sym_calc_value_ext(sym, 1);
    defval = (char *) sym_get_string_value(sym);
  }
  else
    defval = NULL;

  while(true) {
    ret = dialog_inputbox(_("GNUnet configuration"),
			  _("How much upstream "
			    "(Bytes/s) may be used?"), rows, cols - 5, defval ? defval : "");

    if (ret == 1) {
      /* Help */
      dialog_msgbox(_("Help"), _("You can limit GNUnet's resource usage "
				 "here.\n\nThe \"upstream\" is the data channel through which data "
				 "is *sent* to the internet. The limit is either the total maximum "
				 "for this computer or how much GNUnet itself is allowed to use. You "
				 "can specify that later. If you have a flatrate, you can set it to "
				 "the maximum speed of your internet connection."), rows, cols - 5, 1);
    }
    else if (ret <= 0)
      break;
  }

  if (ret == -1)
    goto end;

  sym_set_string_value(sym, dialog_input_result);

  dialog_clear();

  /* Downstram */
  if ((sym = sym_find("MAXNETDOWNBPSTOTAL", "LOAD"))) {
    sym_calc_value_ext(sym, 1);
    defval = (char *) sym_get_string_value(sym);
  }
  else
    defval = NULL;

  while(true) {
    ret = dialog_inputbox(_("GNUnet configuration"), _("How much downstream "
						       "(Bytes/s) may be used?"), rows, cols - 5, defval ? defval : "");

    if (ret == 1) {
      /* Help */
      dialog_msgbox(_("Help"),
		    _("You can limit GNUnet's resource usage "
		      "here.\n\nThe \"downstream\" is the data channel through which data "
		      "is *received* from the internet. The limit is either the total maximum "
		      "for this computer or how much GNUnet itself is allowed to use. You "
		      "can specify that later. If you have a flatrate you can set it to "
		      "the maximum speed of your internet connection."), rows, cols - 5, 1);
    }
    else if (ret <= 0)
      break;
  }

  if (ret == -1)
    goto end;

  sym_set_string_value(sym, dialog_input_result);

  dialog_clear();

  /* Bandwidth allocation */
  sym = sym_find("BASICLIMITING", "LOAD");
  while (true) {
    ret = dialog_yesno(_("GNUnet configuration"),
		       _("Share denoted bandwidth "
			 "with other applications?\n\nSay \"yes\" here, if you don't want other "
			 "network traffic to interfere with GNUnet's operation, but still wish to "
			 "constrain GNUnet's bandwidth usage to values entered in the previous "
			 "steps, or if you can't reliably measure the maximum capabilities "
			 "of your connection. \"No\" can be very useful if other applications "
			 "are causing a lot of traffic on your LAN.  In this case, you do not "
			 "want to limit the traffic that GNUnet can inflict on your internet "
			 "connection whenever your high-speed LAN gets used (e.g. by NFS)."),
		       rows, cols - 5);

    if (ret != -2)
      break;
  }

  if (ret == -1)
    goto end;
  else
    sym_set_tristate_value(sym, !ret); /* ret is inverted */

  dialog_clear();

  /* Max CPU */
  if ((sym = sym_find("MAXCPULOAD", "LOAD"))) {
    sym_calc_value_ext(sym, 1);
    defval = (char *) sym_get_string_value(sym);
  }
  else
    defval = NULL;

  while(true) {
    ret = dialog_inputbox(_("GNUnet configuration"),
			  _("How much CPU (in %) may "
			    "be used?"), rows, cols - 5, defval ? defval : "");

    if (ret == 1) {
      /* Help */
      dialog_msgbox(_("Help"),
		    _("You can limit GNUnet's resource usage "
		      "here.\n\nThis is the percentage of processor time GNUnet is allowed "
		      "to use."), rows, cols - 5, 1);
    }
    else if (ret <= 0)
      break;
  }

  if (ret == -1)
    goto end;

  sym_set_string_value(sym, dialog_input_result);

  dialog_clear();

  /* Migration */
  sym = sym_find("ACTIVEMIGRATION", "FS");
  while(true) {
    ret = dialog_yesno(_("GNUnet configuration"),
		       _("Store migrated content?"
			 "\n\nGNUnet is able to store data from other peers in your datastore. "
			 "This is useful if an adversary has access to your inserted content and "
			 "you need to deny that the content is yours. With \"content migration\" "
			 "on, the content could have \"migrated\" over the internet to your node"
			 " without your knowledge.\nIt also helps to spread popular content over "
			 "different peers to enhance availability."), rows, cols - 5);

    if (ret != -2)
      break;
  }

  if (ret == -1)
    goto end;
  else
    sym_set_tristate_value(sym, !ret); /* ret is inverted */

  dialog_clear();

  /* Quota */
  if ((sym = sym_find("QUOTA", "FS"))) {
    sym_calc_value_ext(sym, 1);
    defval = (char *) sym_get_string_value(sym);
  }
  else
    defval = NULL;

  while(true) {
    ret = dialog_inputbox(_("GNUnet configuration"),
			  _("What's the maximum "
			    "datastore size in MB?\n\nThe GNUnet datastore contains all data that "
			    "GNUnet generates (index data, inserted and migrated content)."),
			  rows, cols - 5, defval ? defval : "");

    if (ret == 1) {
      /* Help - not available */
    }
    else if (ret <= 0)
      break;
  }

  if (ret == -1)
    goto end;

  sym_set_string_value(sym, dialog_input_result);

  dialog_clear();

  /* Autostart */
  if (isOSAutostartCapable()) {
    while(true) {
      ret = dialog_yesno(_("GNUnet configuration"),
			 _("Do you want to launch "
			   "GNUnet as a system service?"
			   "\n\nIf you say \"yes\" here, the GNUnet background process will be "
			   "automatically started when you turn on your computer. If you say \"no\""
			   " here, you have to launch GNUnet yourself each time you want to use it."),
			 rows, cols - 5);

      if (ret != -2)
	break;
    }

    if (ret == -1)
      goto end;
    else
      autostart = !ret; /* ret is inverted */

    dialog_clear();
  }

  /* User */
  if (isOSUserAddCapable()) {
    while(true) {

      sym = sym_find("USER", "GNUNETD");
      if (sym)
	{
	  sym_calc_value_ext(sym, 1);
	  confUser = sym_get_string_value(sym);
	}
      else
        confUser = NULL;

#ifndef MINGW
      if ((NULL == confUser) || (strlen(confUser) == 0))
	{
	  if((geteuid() == 0) || (NULL != getpwnam("gnunet")))
	    defuser = STRDUP("gnunet");
	  else {
	    confUser = getenv("USER");
	    if (confUser != NULL)
	      defuser = STRDUP(confUser);
	    else
	      defuser = NULL;
	  }
	}
      else
        defuser = STRDUP(confUser);
#else
      if (NULL == confUser || strlen(confUser) == 0)
        defuser = STRDUP("");
      else
        defuser = STRDUP(confUser);
#endif

      ret = dialog_inputbox(_("GNUnet configuration"),
			    _("Define the user owning the GNUnet service.\n\n"
			      "For security reasons, it is a good idea to let this setup create "
			      "a new user account under which the GNUnet service is started "
			      "at system startup.\n\n"
			      "However, GNUnet may not be able to access files other than its own. "
			      "This includes files you want to publish in GNUnet. You'll have to "
			      "grant read permissions to the user specified below.\n\n"
			      "Leave the fields empty to run GNUnet with system privileges.\n\n"
			      "GNUnet user:"), rows, cols - 5, defuser);
      FREE(defuser);

      if (ret == 1) {
	/* Help */
      } else if (ret <= 0) {
	user_name = STRDUP(dialog_input_result);
	break;
      }
    }

    if (ret == -1)
      goto end;

    dialog_clear();

    /* Group */
    if (isOSGroupAddCapable()) {
      while(true) {
        sym = sym_find("GROUP", "GNUNETD");
        if (sym)
	  {
	    sym_calc_value_ext(sym, 1);
	    confGroup = sym_get_string_value(sym);
	  }
        else
          confGroup = NULL;
	
#ifndef MINGW
        if((NULL == confGroup) || (strlen(confGroup) == 0))
	  {
	    if((geteuid() == 0) || (NULL != getgrnam("gnunet")))
	      defgroup = STRDUP("gnunet");
	    else {
	      struct group * grp;
	      grp = getgrgid(getegid());
	      if ( (grp != NULL) &&
		   (grp->gr_name != NULL) )
		defgroup = STRDUP(grp->gr_name);
	      else
		defgroup = NULL;
	    }
	  }
        else
          defgroup = STRDUP(confGroup);
#else
        if ( (NULL == confGroup) ||
	     (strlen(confGroup) == 0) )
          defgroup = STRDUP("");
        else
          defgroup = STRDUP(defgroup);
#endif
	
	ret = dialog_inputbox(_("GNUnet configuration"),
			      _("Define the group owning the GNUnet service.\n\n"
				"For security reasons, it is a good idea to let this setup create "
				"a new group for the chosen user account.\n\n"
				"You can also specify a already existant group here.\n\n"
				"Only members of this group will be allowed to start and stop the "
				"the GNUnet server and have access to GNUnet server data.\n\n"
				"GNUnet group:"),
			      rows, cols - 5, defgroup);
        FREE(defgroup);
	
	if (ret == 1) {
	  /* Help */
	}
	else if (ret <= 0) {
	  group_name = STRDUP(dialog_input_result);
	  break;
	}
      }

      if (ret == -1)
	goto end;

      dialog_clear();
    }
  }

  dialog_clear();

  /* Advanced */
  while(true) {
    ret = dialog_yesno(_("GNUnet configuration"),
		       _("If you are an experienced "
			 "user, you may want to tweak your GNUnet installation using the enhanced "
			 "configurator.\n\nDo you want to start it after saving your configuration?"),
		       rows, cols - 5);

    if (ret != -2)
      break;
  }

  if (ret == -1)
    goto end;
  else
    adv = !ret;

  dialog_clear();
  end_dialog();

  /* Save config */
  if ( (user_name != NULL) &&
       (strlen(user_name) > 0) )
    if (!isOSUserAddCapable())
      showCursErr(_("Unable to create user account:"), STRERROR(errno));

  if (!isOSAutostartCapable())
    showCursErr(_("Unable to change startup process:"), STRERROR(errno));

  init_dialog();
  dialog_clear();

  while(true) {
    confFile = getConfigurationString("GNUNET-SETUP",
				      "FILENAME");
    if (conf_write(confFile) != 0) {
      char * err;
      const char * prefix;
      const char * strerr;

      prefix = _("Unable to save configuration file %s: %s.\n\nTry again?");
      strerr = STRERROR(errno);

      err = malloc(strlen(confFile) + strlen(prefix) + strlen(strerr) + 1);
      sprintf(err, prefix, confFile, strerr);

      ret = dialog_yesno(_("GNUnet configuration"),
			 err,
			 rows,
			 cols - 5);

      free(err);
    }
    else
      ret = 1;

    if (ret == 1 || ret == -1)
      break;
  }

end:
  end_dialog();

  FREENONNULL(user_name);
  FREENONNULL(group_name);

  if (adv) {
    mconf_main(argc, argv);
  }

  return 0;
}

/* end of wizard_curs.c */
