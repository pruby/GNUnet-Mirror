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
 * @file util/winproc.c
 * @brief Functions for MS Windows
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_util.h"

#define DEBUG_WINPROC 0

#ifdef MINGW

static HINSTANCE hNTDLL, hIphlpapi, hAdvapi;
TNtQuerySystemInformation GNNtQuerySystemInformation;
TGetIfEntry GNGetIfEntry;
TGetIpAddrTable GNGetIpAddrTable;
TGetIfTable GNGetIfTable;
TOpenSCManager GNOpenSCManager;
TCreateService GNCreateService;
TCloseServiceHandle GNCloseServiceHandle;
TDeleteService GNDeleteService;
TRegisterServiceCtrlHandler GNRegisterServiceCtrlHandler;
TSetServiceStatus GNSetServiceStatus;
TStartServiceCtrlDispatcher GNStartServiceCtrlDispatcher;
TControlService GNControlService;
TOpenService GNOpenService;
TGetBestInterface GNGetBestInterface;
TGetAdaptersInfo GGetAdaptersInfo;

/**
 * Log (panic) messages from PlibC
 */
void plibc_panic(int err, char *msg) {
	LOG((err = INT_MAX) ? LOG_DEBUG : LOG_FAILURE, "%s", msg);
}

/**
 * Initialize PlibC and set up Windows environment
 * @return Error code from winerror.h, ERROR_SUCCESS on success
*/
void InitWinEnv()
{
	plibc_init("GNU", PACKAGE);
	plibc_set_panic_proc(plibc_panic);

  hNTDLL = LoadLibrary("ntdll.dll");

  /* Function to get CPU usage under Win NT */
  if (hNTDLL)
  {
    GNNtQuerySystemInformation = (TNtQuerySystemInformation)
      GetProcAddress(hNTDLL, "NtQuerySystemInformation");
  }
  else
  {
    GNNtQuerySystemInformation = NULL;
  }

  /* Functions to get information about a network adapter */
  hIphlpapi = LoadLibrary("iphlpapi.dll");
  if (hIphlpapi)
  {
    GNGetIfEntry = (TGetIfEntry) GetProcAddress(hIphlpapi, "GetIfEntry");
    GNGetIpAddrTable = (TGetIpAddrTable) GetProcAddress(hIphlpapi,
      "GetIpAddrTable");
    GNGetIfTable = (TGetIfTable) GetProcAddress(hIphlpapi, "GetIfTable");
    GNGetBestInterface = (TGetBestInterface) GetProcAddress(hIphlpapi,
      "GetBestInterface");
    GGetAdaptersInfo = (TGetAdaptersInfo) GetProcAddress(hIphlpapi,
    	"GetAdaptersInfo");
  }
  else
  {
    GNGetIfEntry = NULL;
    GNGetIpAddrTable = NULL;
    GNGetIfTable = NULL;
    GNGetBestInterface = NULL;
    GGetAdaptersInfo = NULL;
  }

  /* Service functions */
  hAdvapi = LoadLibrary("advapi32.dll");
  if (hAdvapi)
  {
    GNOpenSCManager = (TOpenSCManager)
      GetProcAddress(hAdvapi, "OpenSCManagerA");
    GNCreateService = (TCreateService)
      GetProcAddress(hAdvapi, "CreateServiceA");
    GNCloseServiceHandle = (TCloseServiceHandle)
      GetProcAddress(hAdvapi, "CloseServiceHandle");
    GNDeleteService = (TDeleteService)
      GetProcAddress(hAdvapi, "DeleteService");
    GNRegisterServiceCtrlHandler = (TRegisterServiceCtrlHandler)
      GetProcAddress(hAdvapi, "RegisterServiceCtrlHandlerA");
    GNSetServiceStatus = (TSetServiceStatus)
      GetProcAddress(hAdvapi, "SetServiceStatus");
    GNStartServiceCtrlDispatcher = (TStartServiceCtrlDispatcher)
      GetProcAddress(hAdvapi, "StartServiceCtrlDispatcherA");
    GNControlService = (TControlService)
      GetProcAddress(hAdvapi, "ControlService");
    GNOpenService = (TOpenService)
      GetProcAddress(hAdvapi, "OpenServiceA");
  }
}

/**
 * Clean up Windows environment
 */
void ShutdownWinEnv()
{
	plibc_shutdown();

  FreeLibrary(hNTDLL);
  FreeLibrary(hIphlpapi);
  FreeLibrary(hAdvapi);

  CoUninitialize();
}

#endif /* MINGW */

#if !HAVE_ATOLL
long long atoll(const char *nptr)
{
  return atol(nptr);
}
#endif
