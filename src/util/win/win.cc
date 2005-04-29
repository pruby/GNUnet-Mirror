/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file util/win.cc
 * @brief Helper functions for MS Windows in C++
 * @author Nils Durner
 **/

#ifndef _WIN_CC
#define _WIN_CC

#include "winproc.h"
#include "gnunet_util.h"

extern "C" {

/**
 * Enumerate all network adapters
 */
void EnumNICs(PMIB_IFTABLE *pIfTable, PMIB_IPADDRTABLE *pAddrTable)
{
  DWORD dwSize, dwRet;

  *pIfTable = NULL;
  
  if (pAddrTable)
    *pAddrTable = NULL;

  if (GNGetIfTable)
  {
    dwSize = dwRet = 0;

    *pIfTable = (MIB_IFTABLE *) GlobalAlloc(GPTR, sizeof(MIB_IFTABLE));

    /* Get size of table */
    if (GNGetIfTable(*pIfTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER)
    {
      GlobalFree(*pIfTable);
      *pIfTable = (MIB_IFTABLE *) GlobalAlloc(GPTR, dwSize);
    }

    if ((dwRet = GNGetIfTable(*pIfTable, &dwSize, 0)) == NO_ERROR &&
      pAddrTable)
    {
      DWORD dwIfIdx, dwSize = sizeof(MIB_IPADDRTABLE);
      *pAddrTable = (MIB_IPADDRTABLE *) GlobalAlloc(GPTR, dwSize);
      
      /* Make an initial call to GetIpAddrTable to get the
         necessary size */
      if (GNGetIpAddrTable(*pAddrTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER)
      {
        GlobalFree(*pAddrTable);
        *pAddrTable = (MIB_IPADDRTABLE *) GlobalAlloc(GPTR, dwSize);
      }
      GNGetIpAddrTable(*pAddrTable, &dwSize, 0);  	
    }
  }
}

/**
 * Lists all network interfaces in a combo box
 * Used by the basic GTK configurator
 * @param callback
 */
int ListNICs(void (*callback) (char *, int))
{
  PMIB_IFTABLE pTable;
  PMIB_IPADDRTABLE pAddrTable;
  DWORD dwIfIdx, dwExternalNIC;
  IPAddr theIP;
  
  /* Determine our external NIC  */
  theIP = inet_addr("192.0.34.166"); /* www.example.com */
  if ((! GNGetBestInterface) ||
      (GNGetBestInterface(theIP, &dwExternalNIC) != NO_ERROR))
  {
    dwExternalNIC = 0;
  }
  
  /* Enumerate NICs */
  EnumNICs(&pTable, &pAddrTable);
  
  if (pTable)
  {
    for(dwIfIdx=0; dwIfIdx <= pTable->dwNumEntries; dwIfIdx++)
    {
      char szEntry[1001];
      DWORD dwIP = 0;
      int iItm;
			PIP_ADAPTER_INFO pAdapterInfo;
			PIP_ADAPTER_INFO pAdapter = NULL;
			DWORD dwRetVal = 0;
      
      /* Get IP-Address */
      int i;
      for(i = 0; i < pAddrTable->dwNumEntries; i++)
      {
        if (pAddrTable->table[i].dwIndex == pTable->table[dwIfIdx].dwIndex)
        {
          dwIP = pAddrTable->table[i].dwAddr;
          break;
        }
      }

      if (dwIP)
      {
        BYTE bPhysAddr[MAXLEN_PHYSADDR];
			  char *pszIfName = NULL;
     
	      /* Get friendly interface name */
				pAdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof(IP_ADAPTER_INFO));
				ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
				
				/* Make an initial call to GetAdaptersInfo to get
				   the necessary size into the ulOutBufLen variable */
				if (GGetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
				  free(pAdapterInfo);
				  pAdapterInfo = (IP_ADAPTER_INFO *) malloc (ulOutBufLen); 
				}
				
				if ((dwRetVal = GGetAdaptersInfo( pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
				  pAdapter = pAdapterInfo;
				  while (pAdapter) {
				  	if (pTable->table[dwIfIdx].dwIndex == pAdapter->Index)
				  	{
				  		char szKey[251];
				  		long lLen = 250;
				  		
				  		sprintf(szKey, "SYSTEM\\CurrentControlSet\\Control\\Network\\"
				  			"{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection",
				  			pAdapter->AdapterName);
				  		pszIfName = (char *) malloc(251);
				  		if (QueryRegistry(HKEY_LOCAL_MACHINE, szKey, "Name", pszIfName,
				  			&lLen) != ERROR_SUCCESS)
				  		{
				  			free(pszIfName);
				  			pszIfName = NULL;
				  		}
				  	}
				    pAdapter = pAdapter->Next;
				  }
				}
				free(pAdapterInfo);

				/* Set entry */
        memset(bPhysAddr, 0, MAXLEN_PHYSADDR);
        memcpy(bPhysAddr,
          pTable->table[dwIfIdx].bPhysAddr,
          pTable->table[dwIfIdx].dwPhysAddrLen);
          
        snprintf(szEntry, 1000, "%s (%d.%d.%d.%d - %I64u)",
          pszIfName ? pszIfName : (char *) pTable->table[dwIfIdx].bDescr,
          PRIP(ntohl(dwIP)),
          *((unsigned long long *) bPhysAddr));
        szEntry[1000] = 0;
        
        if (pszIfName)
       		free(pszIfName);
        
        callback(szEntry, pAddrTable->table[dwIfIdx].dwIndex == dwExternalNIC);
      }
    }
    GlobalFree(pAddrTable);
    GlobalFree(pTable);
  }
  
  return YES;
}

/**
 * @brief Installs the Windows service
 * @returns 0 on success
 *          1 if the Windows version doesn't support services
 *          2 if the SCM could not be opened
 *          3 if the service could not be created
 */
int InstallAsService()
{
  SC_HANDLE hManager, hService;
  char szEXE[_MAX_PATH + 17] = "\"";

  if (! GNOpenSCManager)
    return 1;

  plibc_conv_to_win_path("/bin/gnunetd.exe", szEXE + 1);
  strcat(szEXE, "\" --win-service");
  hManager = GNOpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
  if (! hManager)
    return 2;

  hService = GNCreateService(hManager, "GNUnet", "GNUnet", 0,
    SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, szEXE,
    NULL, NULL, NULL, NULL, NULL);

  if (! hService)
    return 3;

  GNCloseServiceHandle(hService);

  return 0;
}

/**
 * @brief Uninstall Windows service
 * @returns 0 on success
 *          1 if the Windows version doesn't support services
 *          2 if the SCM could not be openend
 *          3 if the service cannot be accessed
 *          4 if the service cannot be deleted
 */
int UninstallService()
{
  SC_HANDLE hManager, hService;

  if (! GNOpenSCManager)
    return 1;

  hManager = GNOpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
  if (! hManager)
    return 2;

  if (! (hService = GNOpenService(hManager, "GNUnet", DELETE)))
    return 3;

  if (! GNDeleteService(hService))
    return 4;

  GNCloseServiceHandle(hService);

	return 0;
}

}

#endif
