/*
     This file is part of GNUnet.
     (C) 2001 - 2004 Christian Grothoff (and other contributing authors)

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
    
    CoInitialize(NULL);
    
    if ((strlen(pszSrc) > _MAX_PATH) || (strlen(pszDest) + 4 > _MAX_PATH))
    {
      CoUninitialize();
      return FALSE;
    }
    
    /* Create Shortcut-Object */
    if (CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
        IID_IShellLink, (void **) &pLink) != S_OK)
    {
      CoUninitialize();
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
    if (pFile->Save((LPCOLESTR) pwszDest, TRUE) != S_OK)
    {
      free(pwszDest);
      pLink->Release();
      pFile->Release();
      CoUninitialize();
  
      return FALSE;
    }
  
    free(pwszDest);
    
    pFile->Release();
    pLink->Release();
    CoUninitialize();
      
    return TRUE;
}

BOOL DereferenceShortcut(char *pszShortcut)
{
  IShellLink *pLink;
  IPersistFile *pFile;
  WCHAR *pwszShortcut;
  char *pszLnk;
  int iErr, iLen;

  CoInitialize(NULL);
  
  /* Create Shortcut-Object */
  if (CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
      IID_IShellLink, (void **) &pLink) != S_OK)
  {
    CoUninitialize();
    return FALSE;
  }

  /* Get File-Object */
  if (pLink->QueryInterface(IID_IPersistFile, (void **) &pFile) != S_OK)
  {
    pLink->Release();
    CoUninitialize();
    
    return FALSE;
  }

  pwszShortcut = (WCHAR *) malloc((_MAX_PATH + 1) * sizeof(WCHAR));

  /* Shortcuts have the extension .lnk
     If it isn't there, append it */
  iLen = strlen(pszShortcut);
  if (iLen > 4 && (strcmp(pszShortcut + iLen - 4, ".lnk") != 0))
  {
    pszLnk = (char *) malloc(iLen + 5);
    sprintf(pszLnk, "%s.lnk", pszShortcut);
  }
  else
    pszLnk = strdup(pszShortcut);

  MultiByteToWideChar(CP_ACP, 0, pszLnk, -1, pwszShortcut, _MAX_PATH);
  
  free(pszLnk);
  
  /* Open shortcut */
  if (pFile->Load((LPCOLESTR) pwszShortcut, STGM_READ) != S_OK)
  {
    pLink->Release();
    pFile->Release();
    free(pwszShortcut);
    CoUninitialize();
    
    return FALSE;
  }
  
  free(pwszShortcut);
  
  /* Get target file */
  if (pLink->GetPath(pszShortcut, _MAX_PATH, NULL, 0) != S_OK)
  {
    pLink->Release();
    pFile->Release();
    CoUninitialize();
    
    return FALSE;
  }

  pFile->Release();
  pLink->Release();
  CoUninitialize();
  
  return TRUE;
}

/**
 * Enumerate all network adapters
 */
void EnumNICs(PMIB_IFTABLE *pIfTable, PMIB_IPADDRTABLE *pAddrTable)
{
  DWORD dwSize, dwRet;

  *pIfTable = NULL;
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

    if ((dwRet = GNGetIfTable(*pIfTable, &dwSize, 0)) == NO_ERROR)
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
 * Used by the Windows installer
 */
int PopulateNICCombo(HWND hCombo)
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
      char szEntry[251];
      DWORD dwIP = 0;
      int iItm;
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
        snprintf(szEntry, 250, "%d.%d.%d.%d - %s - %i",
          PRIP(ntohl(dwIP)),
          pTable->table[dwIfIdx].bDescr, pTable->table[dwIfIdx].dwIndex);
        szEntry[250] = 0;
          
        iItm = SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM) szEntry);
        if (iItm == -1)        
          return NO;
        
        SendMessage(hCombo, CB_SETITEMDATA, (WPARAM) iItm,
          (LPARAM) dwIfIdx);
          
        if (pAddrTable->table[dwIfIdx].dwIndex == dwExternalNIC)
          SendMessage(hCombo, CB_SETCURSEL, iItm, 0);
      }
    }
    GlobalFree(pAddrTable);
    GlobalFree(pTable);
  }
  
  return YES;
}

}

#endif
