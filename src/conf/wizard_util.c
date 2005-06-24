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
 * @file conf/wizard_util.c
 * @brief Common helper functions
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_util.h"

#define LKC_DIRECT_LINK
#include "lkc.h"

/**
 * @brief Enumerate all network interfaces
 * @param callback the callback function
 */
void wiz_enum_nics(void (*callback) (char *, int)) {
#ifdef MINGW
		ListNICs(callback);
#else
		char entry[11], *dst;
		FILE *f;
		
		if (system("ifconfig 2> /dev/null"))
			if (system("/sbin/ifconfig 2> /dev/null") == 0)
				f = popen("/sbin/ifconfig 2> /dev/null", "r");
			else
				f = null;
		else
			f = popen("ifconfig 2> /dev/null", "r");
		
		if (!f)
			return;
			
		while(1)
		{
			int i = 0;
			int c = fgetc(f);
			
			if (c == EOF)
				break;

			dst = entry;
			
			/* Read interface name until the first space (or colon under OS X) */
			while (c != EOF && c != '\n' &&
#ifdef OSX
				c != ':'
#else
				c != ' '
#endif
				&& i < 10)
			{
				*dst++ = c;
				i++;
				c = fgetc(f);
			}
			*dst = 0;

			if (entry[0])
				callback(entry, strcmp(entry, "eth0") == 0);

			while(c != '\n' && c != EOF)
				c = fgetc(f);
		}

		pclose(f);
#endif
}

/**
 * @brief Determine whether a NIC makes a good default
 */
int wiz_is_nic_default(const char *name, int suggestion) {
	const char *nic = NULL;
	struct symbol *sym = sym_find("INTERFACE", "NETWORK");
  
  if (sym)
  {
  	sym_calc_value_ext(sym, 1);
  	nic = sym_get_string_value(sym);
#ifdef WINDOWS
		/* default NIC for unixes */
		if (strcmp(nic, "eth0") == 0)
			nic = NULL;
#endif
  }

  if (nic)
  {
  	/* The user has selected a NIC before */
  	suggestion = 0;
  	
  	int niclen = strlen(nic);
  	int inslen = strlen(name);
  	if (inslen >= niclen)
  	{
#ifdef WINDOWS
  		if (strncmp(name + inslen - niclen - 1, nic, niclen) == 0)
#else
  		if (strcmp(name, nic) == 0)
#endif
  			suggestion = 1; /* This is the previous selection */
  	}
  }
  
  return suggestion;
}

/**
 * @brief Checks if we can start GNUnet automatically
 * @return 1 if yes, 0 otherwise
 */
int wiz_autostart_capable() {
#ifdef WINDOWS
	return 1;
#endif
#ifdef LINUX
	if (ACCESS("/usr/sbin/update-rc.d", X_OK) == 0) {
		/* Debian */
		if (ACCESS("/etc/init.d/", W_OK) == 0)
			return 1;
	}
	
	return 0;
#endif
}

/**
 * @brief Make GNUnet start automatically
 * @param doAutoStart true to enable autostart, false to disable it
 * @param username name of the user account to use
 * @param groupname name of the group to use
 */
int wiz_autostart(int doAutoStart, char *username, char *groupname) {
#ifdef WINDOWS
	if (doAutoStart)
	{
		if (IsWinNT())
		{
			char *err = NULL;
			DWORD dwErr = 0;
			
			if (username && !strlen(username))
				username = NULL;
			
			/* Install service */
			switch(InstallAsService(username))
			{
				case 0:
				case 1:
					break;
				case 2:
					err = winErrorStr(_("Can't open Service Control Manager"),
						GetLastError());
				case 3:
					dwErr = GetLastError(); 
					if (dwErr != ERROR_SERVICE_EXISTS)
					{
						err = winErrorStr(_("Can't create service"),
							GetLastError());
					}
					break;
				default:
					err = winErrorStr(_("Unknown error"),
						GetLastError());
			}
			
			/* Grant permissions to the GNUnet directory */
			if ((!err || dwErr == ERROR_SERVICE_EXISTS) && username)
			{
				char szHome[_MAX_PATH + 1];

				plibc_conv_to_win_path("/", szHome);

				if (!AddPathAccessRights(szHome, username, GENERIC_ALL))
				{
					err = winErrorStr(_("Error changing the permissions of the GNUnet directory"),
						GetLastError());
				}
			}

			if (err && dwErr != ERROR_SERVICE_EXISTS)
			{
				MessageBox(GetActiveWindow(), err, _("Error"), MB_ICONSTOP | MB_OK);
				free(err);
				return 0;
			}
		}
		else
		{
			char szPath[_MAX_PATH + 1];
			plibc_conv_to_win_path("/bin/gnunetd.exe", szPath);
			
			if (RegSetValue(HKEY_LOCAL_MACHINE,
				"Software\\Microsoft\\Windows\\CurrentVersion\\Run", REG_SZ, szPath, 
				strlen(szPath)) != ERROR_SUCCESS)
			{
		  	MessageBox(GetActiveWindow(), _("Cannot write to the regisitry"),
		  		_("Error"), MB_ICONSTOP | MB_OK);					
			}
		}
	}
	else
	{
		if (IsWinNT())
		{
			char *err = NULL;
						
			switch (UninstallService())
			{
				case 0:
				case 1:
					break;
				case 2:
					err = winErrorStr(_("Can't open Service Control Manager"),
						GetLastError());				
					return 0;
				case 3:
					err = winErrorStr(_("Can't access the service"),
						GetLastError());				
					return 0;
				case 4:
					err = winErrorStr(_("Can't delete the service"),
						GetLastError());
					break;
				default:
					MessageBox(GetActiveWindow(), _("Unknown error"), _("Error"),
						MB_ICONSTOP | MB_OK);								
			}
			
			if (err)
			{
				MessageBox(GetActiveWindow(), err, _("Error"),
						MB_ICONSTOP | MB_OK);
				free(err);
			}
		}
		else
		{
			HKEY hKey;
			
		  if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		  	"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE,
		  	&hKey) == ERROR_SUCCESS)
		  {
		    RegDeleteValue(hKey, "GNUnet");
		
		    RegCloseKey(hKey);
		  }
		}
	}
#else
	/* Unix */
	if (ACCESS("/usr/sbin/update-rc.d", X_OK) == 0) {
		/* Debian */
		if (doAutoStart) {
			struct stat buf;
			if (STAT("/etc/init.d/gnunetd", &buf) == -1) {
				/* create init file */
				FILE *f = FOPEN("/etc/init.d/gnunetd", "w");
				if (! f)
					return 0;
					
				fputs("#! /bin/sh\n"
									"#\n"
									"# Automatically created by gnunet-setup\n"
									"#\n"
									"\n"
									"PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
									"PIDFILE=/var/run/gnunetd/gnunetd.pid\n"
									"\n"
									"case \"$1\" in\n"
									"	start)\n"
									"		echo -n \"Starting GNUnet: \"\n"
									"		gnunetd\n"
									"		echo \"gnunetd\"\n"
									"		;;\n"
									"	stop)\n"
									"		echo -n \"Stopping GNUnet: \"\n"
									"		kill `cat $PIDFILE`\n"
									"		echo \"gnunetd\"\n"
									"		;;\n"
									"	reload)\n"
									"		echo -n \"Reloading GNUnet: \"\n"
									"		kill -HUP `cat $PIDFILE`\n"
									"		echo \"gnunetd\"\n"
									"		;;\n"
									"	restart|force-reload)\n"
									"		echo \"Restarting GNUnet: gnunetd...\"\n"
									"		$0 stop\n"
									"		sleep 1\n"
									"		$0 start\n"
									"		;;\n"
									"	*)\n"
									"		echo \"Usage: /etc/init.d/gnunetd {start|stop|reload|restart|force-reload}\" >&2\n"
									"		exit 1\n"
									"		;;\n"
									"\n"
									"esac\n"
				      "exit 0\n", f);
					fclose(f);
					CHMOD("/etc/init.d/gnunetd", S_IRWXU | S_IRGRP | S_IXGRP |
						S_IROTH | S_IXOTH);
			}
			errno = system("/usr/sbin/update-rc.d gnunetd defaults");
			if (errno != 0)
				return 0;
		}
		else {
			if (UNLINK("/etc/init.d/gnunetd") != -1) {
				if (ACCESS("/usr/sbin/update-rc.d", X_OK) == 0) {
					errno = system("/usr/sbin/update-rc.d gnunetd remove");
					if (errno != 0)
						return 0;
				}
			}
			else
				return 0;
		}
	}
	else
		return 0;
		
#endif
	return 1;
}

/**
 * @brief Checks if we can add an user for the GNUnet service
 * @return 1 if yes, 0 otherwise
 * @todo support for useradd(8)
 */
int wiz_useradd_capable(){
#ifdef WINDOWS
	return IsWinNT();
#endif
#ifdef LINUX
	if (ACCESS("/usr/sbin/adduser", X_OK) == 0)
		return 1;
	else
		/* TODO: useradd */
#endif
		return 0;
}

/**
 * @brief Checks if we can add a group for the GNUnet service
 * @return 1 if yes, 0 otherwise
 * @todo support for groupadd(8)
 */
int wiz_groupadd_capable() {
#ifdef LINUX
	if (ACCESS("/usr/sbin/addgroup", X_OK) == 0) {
		return 1;
	}
	/* TODO: groupadd */
	else
#endif
		return 0;
}

/**
 * @brief Add a service account for GNUnet
 * @param group the group of the new user
 * @param name the name of the new user
 * @todo Check FreeBSD (adduser(8)), add support for useradd(8)
 */
int wiz_addServiceAccount(char *group_name, char *user_name) {
	
	if (!user_name || !strlen(user_name))
		return 1;
	
#ifdef WINDOWS
	if (IsWinNT())
	{
		char *err = NULL;

		switch(CreateServiceAccount(user_name, "GNUnet service account")) {
			case 0:
				; /* OK */
				break;
			case 1:
				MessageBox(0, _("This version of Windows does not support "
					"multiple users."), _("Error"), MB_ICONSTOP | MB_OK);
				return 0;
			case 2:
				err = winErrorStr(_("Error creating user"), GetLastError());
				break;
			case 3:
				err = winErrorStr(_("Error accessing local security policy"), GetLastError());
				break;
			case 4:
				err = winErrorStr(_("Error granting service right to user"), GetLastError());
				break;
			default:
				err = winErrorStr(_("Unknown error while creating a new user"), GetLastError());
				break;
		}
		
		if (err)
		{
			MessageBox(0, err, _("Error"), MB_ICONSTOP | MB_OK);
			free(err);
			
			return 0;
		}
	}
	else
		return 0;
#else
	int haveGroup;

	if (ACCESS("/usr/sbin/adduser", X_OK) == 0) {
		/* Debian */
		/* TODO: FreeBSD? http://www.freebsd.org/cgi/man.cgi?query=adduser&sektion=8 */
		char *cmd;

		haveGroup = group_name && strlen(group_name) > 0;		
		cmd = MALLOC(haveGroup ? strlen(group_name) : 0 + strlen(user_name) + 64);
		
		if (haveGroup) {
			sprintf(cmd, "/usr/sbin/addgroup --quiet --system %s", group_name);		
			system(cmd);
		}
		
		sprintf(cmd, "/usr/sbin/adduser --quiet --system %s %s "
			"--no-create-home %s", haveGroup ? "--ingroup" : "",
			haveGroup ? group_name : "", user_name);
		system(cmd);
		
		FREE(cmd);
	}
	/* TODO: useradd */
	else
		return 0;
#endif

	return 1;
}

/* end of wizard_util.c */
