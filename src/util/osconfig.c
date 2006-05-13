/*
     This file is part of GNUnet.
     (C) 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file util/osconfig.c
 * @brief functions to read or change the OS configuration
 * @author Nils Durner
 */
#include "platform.h"
#include "gnunet_util.h"

/**
 * @brief Enumerate all network interfaces
 * @param callback the callback function
 */
void enumNetworkIfs(void (*callback) (const char *, int, void *),
		    void * cls) {
#ifdef MINGW
  ListNICs(callback, cls);
#else
  char entry[11], *dst;
  FILE *f;

  if (system("ifconfig > /dev/null 2> /dev/null"))
    if (system("/sbin/ifconfig > /dev/null 2> /dev/null") == 0)
      f = popen("/sbin/ifconfig 2> /dev/null", "r");
    else
      f = NULL;
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
	callback(entry, strcmp(entry, "eth0") == 0, cls);

      while(c != '\n' && c != EOF)
	c = fgetc(f);
    }

  pclose(f);
#endif
}

/**
 * @brief Checks if we can start GNUnet automatically
 * @return 1 if yes, 0 otherwise
 */
int isOSAutostartCapable() {
#ifdef LINUX
  if (ACCESS("/usr/sbin/update-rc.d", X_OK) == 0) {
    /* Debian */
    if (ACCESS("/etc/init.d/", W_OK) == 0)
      return 1;
  }
  return 0;
#else
  #ifdef WINDOWS
    return 1;
  #else
    return 0;
  #endif
#endif
}

/**
 * @brief Make GNUnet start automatically
 * @param doAutoStart true to enable autostart, false to disable it
 * @param username name of the user account to use
 * @param groupname name of the group to use
 * @return 0 on success
 */
int autostartService(int doAutoStart, 
		     const char * username, 
		     const char * groupname) {
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
	      if (GetLastError() != ERROR_SERVICE_EXISTS)
		return 1;
	    case 3:
	      return 2;
	    default:
	      return -1;
	    }
	
	  /* Grant permissions to the GNUnet directory */
	  if ((!err || dwErr == ERROR_SERVICE_EXISTS) && username)
	    {
	      char szHome[_MAX_PATH + 1];
	
	      plibc_conv_to_win_path("/", szHome);
	
	      if (!AddPathAccessRights(szHome, username, GENERIC_ALL))
		return 3;
	    }
	}
      else
	{
	  char szPath[_MAX_PATH + 1];
    HKEY hKey;

	  plibc_conv_to_win_path("/bin/gnunetd.exe", szPath);
	
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_EXECUTE,
        &hKey) == ERROR_SUCCESS)
    {
      if (RegSetValueEx(hKey, "GNUnet", 0, REG_SZ, szPath, strlen(szPath)) !=
        ERROR_SUCCESS)
        return 4;

      RegCloseKey(hKey);
    }
    else
      return 4;
	}
    }
  else
    {
      if (IsWinNT())
	{
	  switch (UninstallService())
	    {
	    case 0:
	    case 1:
	      break;
	    case 2:
	      return 1;
	    case 3:
	      return 5;
	    case 4:
	      return 6;
	    default:
	      return -1;
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
	  return 1;
	
	fputs("#! /bin/sh\n"
	      "#\n"
	      "# Automatically created by gnunet-setup\n"
	      "#\n"
	      "\n"
	      "PATH=$PATH:" PREFIX_PATH "/bin"
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
	return 1;
    }
    else {
      if ( (UNLINK("/etc/init.d/gnunetd") != -1) ||
	   (errno != ENOENT)) {
	if (ACCESS("/usr/sbin/update-rc.d", X_OK) == 0) {
	  errno = system("/usr/sbin/update-rc.d gnunetd remove");
	  if (errno != 0) {
	    errno = EPERM;
	    return 1;
	  }
	}
	else {
	  errno = EPERM;
	  return 1;
	}
      }
      else
	return 0;
    }
  }
  else
    return 1;
#endif
  return 0;
}

/**
 * @brief Checks if we can add an user for the GNUnet service
 * @return 1 if yes, 0 otherwise
 * @todo support for useradd(8)
 */
int isOSUserAddCapable(){
#ifdef WINDOWS
	return IsWinNT();
#endif
#ifdef LINUX
	if (ACCESS("/usr/sbin/adduser", X_OK) == 0)
	  return (geteuid() == 0);
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
int isOSGroupAddCapable() {
#ifdef LINUX
	if (ACCESS("/usr/sbin/addgroup", X_OK) == 0) {
	  return (geteuid() == 0);
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
 * @return 0 on success
 */
int createGroupUser(const char *group_name, 
		    const char *user_name) {
	int haveGroup;

	if ( (user_name == NULL) ||
	     (0 == strlen(user_name)) ) 
		return 0;
	
#ifdef WINDOWS
	if (IsWinNT())
	{
		return CreateServiceAccount(user_name, "GNUnet service account");
	}
#else

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
		return 1;
#endif

	return 0;
}

char *winErrorStr(const char *prefix, int dwErr)
{
#ifdef WINDOWS
	char *err, *ret;
	int mem;
	
	if (! FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
  	NULL, (DWORD) dwErr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR) &err,
		0, NULL ))
	{
		err = "";
	}

	mem = strlen(err) + strlen(prefix) + 20;
	ret = (char *) malloc(mem);

  snprintf(ret, mem, "%s: %s (#%u)", prefix, err, dwErr);

  LocalFree(err);

  return ret;
#else
	return NULL;
#endif
}


/* end of osconfig.c */
