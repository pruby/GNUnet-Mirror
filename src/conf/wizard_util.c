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

#include "gnunet_util.h"
#include "platform.h"

#define LKC_DIRECT_LINK
#include "lkc.h"

#include "mconf_dialog.h"

/**
 * @brief Enumerate all network interfaces
 * @param callback the callback function
 */
void wiz_enum_nics(void (*callback) (char *, int)) {
#ifdef MINGW
		ListNICs(callback);
#else
		char entry[11], *dst;
		FILE *f = popen("ifconfig", "r");
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
				insert_nic(entry, strcmp(entry, "eth0") == 0);

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
	char *nic;	
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

/* @brief Make GNUnet start automatically */
void wiz_autostart(int doAutoStart) {
#ifdef WINDOWS
	if (doAutoStart)
	{
		if (IsWinNT())
		{
			char szErr[250];
			
			switch(InstallAsService())
			{
				case 0:
				case 1:
					break;
				case 2:
			    SetErrnoFromWinError(GetLastError());
			    sprintf(szErr, _("Error: can't open Service Control Manager: %s\n"),
			    	_win_strerror(errno));

					MessageBox(GetActiveWindow(), szErr, _("Error"), MB_ICONSTOP | MB_OK);
					return;
				case 3:
			    SetErrnoFromWinError(GetLastError());
			    sprintf(szErr, _("Error: can't create service: %s\n"),
			    	_win_strerror(errno));

					MessageBox(GetActiveWindow(), szErr, _("Error"), MB_ICONSTOP | MB_OK);
					return;
				default:
					MessageBox(GetActiveWindow(), _("Unknown error"), _("Error"),
						MB_ICONSTOP | MB_OK);
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
			char szErr[250];
			int iErr;
			
			switch (UninstallService())
			{
				case 0:
				case 1:
					break;
				case 2:
					iErr = GetLastError();
			    SetErrnoFromWinError(iErr);
			    sprintf(szErr, _("Error: can't open Service Control Manager: %s (#%i)\n"),
			    	_win_strerror(errno), iErr);

					MessageBox(GetActiveWindow(), szErr, _("Error"), MB_ICONSTOP | MB_OK);
					return;
				case 3:
					iErr = GetLastError();
			    SetErrnoFromWinError(iErr);
			    sprintf(szErr, _("Error: can't access the service: %s (#%i)\n"),
			    	_win_strerror(errno), iErr);

					MessageBox(GetActiveWindow(), szErr, _("Error"), MB_ICONSTOP | MB_OK);
					return;
				case 4:
					iErr = GetLastError();
			    SetErrnoFromWinError(iErr);
			    sprintf(szErr, _("Error: can't delete the service: %s (#%i)\n"),
			    	_win_strerror(errno), iErr);

					MessageBox(GetActiveWindow(), szErr, _("Error"), MB_ICONSTOP | MB_OK);
					break;
				default:
					MessageBox(GetActiveWindow(), _("Unknown error"), _("Error"),
						MB_ICONSTOP | MB_OK);								
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
#endif
}

/* end of wizard_util.c */
