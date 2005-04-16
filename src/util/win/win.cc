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

BOOL CreateShortcut(const char *pszSrc, const char *pszDest)
{
    /* Create shortcut */
    IShellLink *pLink;
    IPersistFile *pFile;
    WCHAR *pwszDest;
    char *pszFileLnk;
    HRESULT hRes;
    
    CoInitialize(NULL);
    
    if ((strlen(pszSrc) > _MAX_PATH) || (strlen(pszDest) + 4 > _MAX_PATH))
    {
      CoUninitialize();
      errno = ENAMETOOLONG;
      
      return FALSE;
    }
    
    /* Create Shortcut-Object */
    if (CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
        IID_IShellLink, (void **) &pLink) != S_OK)
    {
      CoUninitialize();
      errno = ESTALE;
      
      return FALSE;
    }
  
    /* Set target path */
    pLink->SetPath(pszSrc);
  
    /* Get File-Object */
    if (pLink->QueryInterface(IID_IPersistFile, (void **) &pFile) != S_OK)
    {
      free(pwszDest);
      pLink->Release();
      CoUninitialize();
      errno = ESTALE;
     
      return FALSE;
    }

    /* shortcuts have the extension .lnk */
    pszFileLnk = (char *) malloc(strlen(pszDest) + 5);
    sprintf(pszFileLnk, "%s.lnk", pszDest);
  
    /* Turn filename into widechars */
    pwszDest = (WCHAR *) malloc((_MAX_PATH + 5) * sizeof(WCHAR));
    MultiByteToWideChar(CP_ACP, 0, pszFileLnk, -1, pwszDest, _MAX_PATH);
    
    free(pszFileLnk);
    
    /* Save shortcut */
    if (FAILED(hRes = pFile->Save((LPCOLESTR) pwszDest, TRUE)))
    {
      free(pwszDest);
      pLink->Release();
      pFile->Release();
      CoUninitialize();
      SetErrnoFromHRESULT(hRes);
  
      return FALSE;
    }
  
    free(pwszDest);
    
    pFile->Release();
    pLink->Release();
    CoUninitialize();
    errno = 0;
      
    return TRUE;
}

BOOL DereferenceShortcut(char *pszShortcut)
{
  IShellLink *pLink;
  IPersistFile *pFile;
  WCHAR *pwszShortcut;
  char *pszLnk;
  int iErr, iLen;
  HRESULT hRes;
  HANDLE hLink;
  char szTarget[_MAX_PATH + 1];

  if (! *pszShortcut)
    return TRUE;

  CoInitialize(NULL);
  szTarget[0] = 0;
  
  /* Create Shortcut-Object */
  if (CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
      IID_IShellLink, (void **) &pLink) != S_OK)
  {
    CoUninitialize();
    errno = ESTALE;
    
    return FALSE;
  }

  /* Get File-Object */
  if (pLink->QueryInterface(IID_IPersistFile, (void **) &pFile) != S_OK)
  {
    pLink->Release();
    CoUninitialize();
    errno = ESTALE;
    
    return FALSE;
  }

  pwszShortcut = (WCHAR *) malloc((_MAX_PATH + 1) * sizeof(WCHAR));

  /* Shortcuts have the extension .lnk
     If it isn't there, append it */
  iLen = strlen(pszShortcut);
  if (iLen > 4 && (strcmp(pszShortcut + iLen - 4, ".lnk") != 0))
  {
    HANDLE hLink;
    
    pszLnk = (char *) malloc(iLen + 5);
    sprintf(pszLnk, "%s.lnk", pszShortcut);
  }
  else
    pszLnk = strdup(pszShortcut);

  /* Make sure the path refers to a file */
  hLink = CreateFile(pszLnk, FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                   NULL, OPEN_EXISTING, 0, NULL);
  if (hLink == INVALID_HANDLE_VALUE)
  {
    free(pszLnk);
    SetErrnoFromWinError(GetLastError());
    
    if (errno == ENOENT)
    {
      /* There's no path with the ".lnk" extension.
         We don't quit here, because we have to decide whether the path doesn't
         exist or the path isn't a link. */

      /* Is it a directory? */
      if (GetFileAttributes(pszShortcut) & FILE_ATTRIBUTE_DIRECTORY)
      {
        errno = EINVAL;
        return FALSE;
      }

      pszLnk = strdup(pszShortcut);
      
      hLink = CreateFile(pszLnk, FILE_READ_DATA, FILE_SHARE_READ |
                FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
      SetErrnoFromWinError(GetLastError());      
    }
    else
      return FALSE; /* File/link is there but unaccessible */
  }
    
  MultiByteToWideChar(CP_ACP, 0, pszLnk, -1, pwszShortcut, _MAX_PATH);
  
  /* Open shortcut */
  if (FAILED(hRes = pFile->Load((LPCOLESTR) pwszShortcut, STGM_READ)))
  {
    pLink->Release();
    pFile->Release();
    free(pwszShortcut);
    CoUninitialize();
    
    /* For some reason, opening an invalid link sometimes fails with ACCESSDENIED.
       Since we have opened the file previously, insufficient priviledges
       are rather not the problem. */
    if (hRes == E_FAIL || hRes == E_ACCESSDENIED)
    {
      /* Check file magic */
      if (hLink != INVALID_HANDLE_VALUE)
      {
        DWORD dwRead;
        char pMagic[4] = {0, 0, 0, 0};
        
        ReadFile(hLink, pMagic, 4, &dwRead, NULL);
        if (memcmp(pMagic, "L\0\0\0", 4) == 0)
          SetErrnoFromHRESULT(hRes);
        else
          errno = EINVAL; /* No link */
      }
      /* else: errno was set above! */
    }
    else
      SetErrnoFromHRESULT(hRes);

    free(pszLnk);
          
    CloseHandle(hLink);
    return FALSE;
  }
  
  CloseHandle(hLink);
  free(pszLnk);
  free(pwszShortcut);
  
  /* Get target file */
  if (FAILED(hRes = pLink->GetPath(szTarget, _MAX_PATH, NULL, 0)))
  {
    pLink->Release();
    pFile->Release();
    CoUninitialize();
    
    if (hRes == E_FAIL)
      errno = EINVAL; /* Not a symlink */
    else
      SetErrnoFromHRESULT(hRes);
    
    return FALSE;
  }

  pFile->Release();
  pLink->Release();
  CoUninitialize();
  errno = 0;
  
  if (szTarget[0] != 0)
    return TRUE;
  else
  {
    /* GetPath() did not return a valid path */
    errno = EINVAL;
    return FALSE;
  }
}

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

}

#endif
