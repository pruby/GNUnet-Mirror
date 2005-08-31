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
 * @file conf/gnunet-win-tool.c
 * @brief tool for Windows specific tasks
 * @author Nils Durner
 */

#include "platform.h"
#include <conio.h>

#define WINTOOL_VERSION "0.1.0"

static int bPrintAdapters, bInstall, bUninstall, bConn;
static char *hashFile;
static char chunk1[] = {0x62, 0x13, 0x06, 0x00};
static char chunk2[] = {0xFE, 0xFF, 0xFF, 0x00};
static char chunk3[] = {0xBC, 0x28, 0x06, 0x00};
static char chunk4[] = {0xCF, 0x47, 0x06, 0x00};

/**
 * Prints the usage information for this command if the user errs.
 * Aborts the program.
 */
static void printhelp() {
  static Help help[] = {
    HELP_CONFIG,
    HELP_HELP,
    HELP_LOGLEVEL,
    { 'n', "netadapters", NULL, "list all network adapters" },
    { 'i', "install", NULL, "install GNUnet as Windows service" },
    { 'u', "uninstall", NULL, "uninstall GNUnet service" },
    { 'C', "increase-connections", NULL, "increase the maximum number of TCP/IP connections"},
    HELP_VERSION,
    HELP_END,
  };
  formatHelp("gnunet-win-tool [OPTIONS]",
	     "Tool for Windows specific tasks.",
	     help);
}

/**
 * Print all network adapters with their index number
 */
void PrintAdapters()
{
  PMIB_IFTABLE pTable;
  PMIB_IPADDRTABLE pAddrTable;
  DWORD dwIfIdx;

  EnumNICs(&pTable, &pAddrTable);

  if (pTable)
  {
    for(dwIfIdx=0; dwIfIdx <= pTable->dwNumEntries; dwIfIdx++)
    {
      BYTE bPhysAddr[MAXLEN_PHYSADDR];

      memset(bPhysAddr, 0, MAXLEN_PHYSADDR);
      memcpy(bPhysAddr,
        pTable->table[dwIfIdx].bPhysAddr,
        pTable->table[dwIfIdx].dwPhysAddrLen);

      printf("Index: %i\nAdapter name: %s\nID: %I64u\n",
        (int) pTable->table[dwIfIdx].dwIndex, pTable->table[dwIfIdx].bDescr,
        *((unsigned long long *) bPhysAddr));

      /* Get IP-Addresses */
      int i;
      for(i = 0; i < pAddrTable->dwNumEntries; i++)
      {
        if (pAddrTable->table[i].dwIndex == pTable->table[dwIfIdx].dwIndex)
          printf("Address: %u.%u.%u.%u\n",
            PRIP(ntohl(pAddrTable->table[i].dwAddr)));
      }
      printf("\n");
    }
    GlobalFree(pAddrTable);
    GlobalFree(pTable);
  }
}

/**
 * Install GNUnet as Windows service
 */
void Install()
{
	switch(InstallAsService(NULL))
	{
		case 0:
			printf(_("GNUnet service installed successfully.\n"));
			break;
		case 1:
			printf(_("This version of Windows doesn't support services.\n"));
			break;
		case 2:
	    SetErrnoFromWinError(GetLastError());
	    printf(_("Error: can't open Service Control Manager: %s\n"),
	    	_win_strerror(errno));
			break;
		case 3:
	    SetErrnoFromWinError(GetLastError());
	    printf(_("Error: can't create service: %s\n"), _win_strerror(errno));
			break;
		default:
			printf(_("Unknown error.\n"));			
	}
}

/**
 * Uninstall the service
 */
void Uninstall()
{
	switch(UninstallService())
	{
		case 0:
		  printf(_("Service deleted.\n"));
			break;
		case 1:
			printf(_("This version of Windows doesn't support services.\n"));
			break;
		case 2:
	    SetErrnoFromWinError(GetLastError());
	    printf(_("Error: can't open Service Control Manager: %s\n"),
	    	_win_strerror(errno));
			break;
		case 3:
	    SetErrnoFromWinError(GetLastError());
	    printf(_("Error: can't access service: %s\n"), _win_strerror(errno));
			break;
		case 4:
	    SetErrnoFromWinError(GetLastError());
	    printf(_("Error: can't delete service: %s\n"), _win_strerror(errno));
			break;
		default:
			printf(_("Unknown error.\n"));
	}
}

void PatchSys(char *szFn)
{
  FILE *pFile;
  unsigned long lMem;
  char *pMem;
  int iCrc;
	
  pFile = fopen(szFn, "r+b");
  if (!pFile)
  {
    printf("failed.\n Cannot open %s\n", szFn);
    return;
  }

  if (fseek(pFile, 0, SEEK_END))
  {
    printf("failed.\n Cannot seek.\n");
    return;
  }

  lMem = ftell(pFile);
  pMem = malloc(lMem);
  if (! pMem)
  {
    printf("failed.\n Not enough memory.\n");
    fclose(pFile);
    return;
  }

  fseek(pFile, 0, SEEK_SET);
  fread(pMem, 1, lMem, pFile);

  switch(iCrc = crc32N(pMem, lMem))
  {
    case 2151852539:
      memcpy(pMem + 0x130, chunk1, 4);
      memcpy(pMem + 0x4F322, chunk2, 4);
      break;
    case 3886810835:
    	memcpy(pMem + 0x130, chunk3, 4);
      memcpy(pMem + 0x4f5a2, chunk2, 4);
      break;
    case 3246854107:
    	memcpy(pMem + 0x130, chunk4, 4);
      memcpy(pMem + 0x4f5a2, chunk2, 4);
      break;
    case 2437296753:
    case 2826512337:
    case 1912882803:
      printf("already patched.\n");
      free(pMem);
      fclose(pFile);
      return;
    default:
      printf("Unknown DLL version. CRC: %u\n", iCrc);
      free(pMem);
      fclose(pFile);
      return;
  }

  fseek(pFile, 0, SEEK_SET);
  fwrite(pMem, 1, lMem, pFile);
  fclose(pFile);

  free(pMem);

  printf("OK.\n");
}

/**
 * Increase the maximum number of connections.
 * This is especially important under Windows XP Service Pack 2
 **/
void IncreaseConnections()
{
  HKEY hKey;
  char szSys[_MAX_PATH + 1];

  puts("Warning: This modifies your operating system. Use it at your own risk.\nContinue?[Y/n]");
  switch(_getch())
  {
    case 'Y':
    case 'y':
    case 13:
    case 10:
    case 32:
      break;
    default:
      return;
  }
  puts("Y\n");

  /* Step 1: Registry setting,
     see http://support.microsoft.com/default.aspx?scid=kb;EN-US;314053 */
  printf("Writing to registry... ");
  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\"
                                       "Tcpip\\Parameters\\Winsock", 0,
                   KEY_WRITE, &hKey) != ERROR_SUCCESS)
  {
    DWORD dwErr = GetLastError();
    SetErrnoFromWinError(dwErr);
    printf("failed.\n Error: %s (%i)\n", STRERROR(errno), (int) dwErr);
  }
  else
  {
    DWORD dwCon = 0xfffffe;
    if (RegSetValueEx(hKey, "TcpNumConnections", 0, REG_DWORD,
                      (const BYTE *) &dwCon, sizeof(dwCon)) != ERROR_SUCCESS)
    {
      DWORD dwErr = GetLastError();
      SetErrnoFromWinError(dwErr);
      printf("failed.\n Error: %s (%i)\n", STRERROR(errno), (int) dwErr);
    }
    else
      printf("OK.\n");
    RegCloseKey(hKey);
  }

  /* Step 2: Patch tcpip.sys */
  printf("Patching DLLCACHE\\tcpip.sys... ");
  snprintf(szSys, _MAX_PATH, "%s\\SYSTEM32\\DLLCACHE\\tcpip.sys", getenv("windir"));
  PatchSys(szSys);

  printf("Patching DRIVERS\\tcpip.sys... ");
  snprintf(szSys, _MAX_PATH, "%s\\SYSTEM32\\DRIVERS\\tcpip.sys", getenv("windir"));
  PatchSys(szSys);

  printf("OK.\n\nPress any key to continue...");
  getch();
}

/**
 * Print the hash of a file
 */
void doHash()
{
  HashCode512 code;
  EncName hex;
  char *c;

  getFileHash(hashFile, &code);
  hash2enc(&code, &hex);
  printf("RIPEMD160(%s)= ", hashFile);

  /* Flip byte order */
  c = (char *) hex.encoding;
  while(*c)
  {
    putchar(*(c + 1));
    putchar(*c);
    c += 2;
  }
  putchar('\n');
  FREE(hashFile);
  hashFile = NULL;
}

/**
 * Parse the options.
 *
 * @param argc the number of options
 * @param argv the option list (including keywords)
 * @return SYSERR if we should abort, OK to continue
 */
static int parseOptions(int argc, char ** argv) {
  int option_index;
  int c;
  BOOL bPrintHelp = TRUE;

  while (1) {
    static struct GNoption long_options[] = {
      { "netadapters",          0, 0, 'n' },
      { "install",              0, 0, 'i' },
      { "uninstall",            0, 0, 'u' },
      { "increase-connections", 0, 0, 'C' },
      { "filehash",             1, 0, 'R' },
      LONG_DEFAULT_OPTIONS,
      { 0,0,0,0 }
    };
    option_index = 0;
    c = GNgetopt_long(argc,
		      argv,
		      "vhdc:L:H:niuCR:",
		      long_options,
		      &option_index);
    if (c == -1)
      break;  /* No more flags to process */

    bPrintHelp = FALSE;

    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
      case 'v':
        printf("GNUnet v%s, gnunet-win-tool v%s\n",
  	      VERSION, WINTOOL_VERSION);
        return SYSERR;
      case 'h':
        printhelp();
        return SYSERR;
      case 'n':
        bPrintAdapters = YES;
        break;
      case 'i':
        bInstall = YES;
        break;
      case 'u':
        bUninstall = YES;
        break;
      case 'C':
        bConn = YES;
        break;
      case 'R':
        hashFile = MALLOC(strlen(GNoptarg) + 1);
        strcpy(hashFile, GNoptarg);
        break;
      default:
        LOG(LOG_FAILURE,
        	  "Unknown option %c. Aborting.\n"\
        	  "Use --help to get a list of options.\n",
  	  c);
        return -1;
    } /* end of parsing commandline */
  } /* while (1) */

  if (bPrintHelp) {
    printhelp();

    return SYSERR;
  }

  return OK;
}

/**
 * The main function.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int main(int argc, char ** argv) {
  int res;

  res = OK;
  hashFile = NULL;
  bPrintAdapters = bInstall = bUninstall = bConn = NO;

  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return 0;

  if (bPrintAdapters)
    PrintAdapters();
  if (bUninstall)
    Uninstall();
  else if (bInstall)
    Install();
  if (bConn)
    IncreaseConnections();
  if (hashFile)
    doHash();

  doneUtil();

  return (res == OK) ? 0 : 1;
}

/* end of gnunet-win-tool.c */
