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

const char *errlist[] = {
  "No error",
  "Unknown host",                       /* 1 HOST_NOT_FOUND */
  "Host name lookup failure",           /* 2 TRY_AGAIN */
  "Unknown server error",               /* 3 NO_RECOVERY */
  "No address associated with name",    /* 4 NO_ADDRESS */
  "Internal resolver error",            /* errno < 0 */
  "Unknown resolver error"              /* errno > 4 */
};

typedef struct {
  char *pStart;
  HANDLE hMapping;
} TMapping;

static char szRootDir[_MAX_PATH + 1];
static long lRootDirLen;
static char szHomeDir[_MAX_PATH + 2];
static long lHomeDirLen;
static char szUser[261] = "";
static OSVERSIONINFO theWinVersion;
unsigned int uiSockCount = 0;
Winsock *pSocks;
HANDLE hSocksLock;
static char __langinfo[251];
static unsigned int uiMappingsCount = 0;
static TMapping *pMappings;
HANDLE hMappingsLock;

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

BOOL __win_IsHandleMarkedAsBlocking(SOCKET hHandle)
{
  BOOL bBlocking;
  unsigned int uiIndex;

  bBlocking = TRUE;
  WaitForSingleObject(hSocksLock, INFINITE);
  for(uiIndex = 0; uiIndex <= uiSockCount; uiIndex++)
  {
    if (pSocks[uiIndex].s == hHandle)
    {
      bBlocking = pSocks[uiIndex].bBlocking;
      break;
    }
  }
  ReleaseMutex(hSocksLock);

  return bBlocking;
}

void __win_SetHandleBlockingMode(SOCKET s, BOOL bBlocking)
{
  unsigned int uiIndex = 0;
  int bFound = 0;

  WaitForSingleObject(hSocksLock, INFINITE);

  for(uiIndex = 0; uiIndex <= uiSockCount; uiIndex++)
  {
    if (pSocks[uiIndex].s == s)
    {
      bFound = 1;
      break;
    }
  }

  if (bFound)
    pSocks[uiIndex].bBlocking = bBlocking;
  else
  {
    uiIndex = 0;

    while(TRUE)
    {
      if (pSocks[uiIndex].s == -1)
      {
        pSocks[uiIndex].s = s;
        pSocks[uiIndex].bBlocking = bBlocking;
      }
      if (uiIndex == uiSockCount)
      {
        uiSockCount++;
        pSocks = (Winsock *) realloc(pSocks, (uiSockCount + 1) * sizeof(Winsock));
        pSocks[uiSockCount].s = -1;

        break;
      }
      uiIndex++;
    }
  }
  ReleaseMutex(hSocksLock);
}

void __win_DiscardHandleBlockingMode(SOCKET s)
{
  unsigned int uiIndex;

  WaitForSingleObject(hSocksLock, INFINITE);
  for(uiIndex = 0; uiIndex < uiSockCount; uiIndex++)
    if (pSocks[uiIndex].s == s)
      pSocks[uiIndex].s = -1;
  ReleaseMutex(hSocksLock);
}

/**
 * @author Prof. A Olowofoyeku (The African Chief)
 * @author Frank Heckenbach
 * @author Nils Durner
 * source: http://gd.tuwien.ac.at/gnu/mingw/os-hacks.h
 */

int truncate(const char *fname, int distance)
{
  int i;
  HANDLE hFile;
  char pszFile[_MAX_PATH + 1];
  long lRet;

  errno = 0;

  if ((lRet = conv_to_win_path(fname, pszFile)) != ERROR_SUCCESS)
  {
    SetErrnoFromWinError(lRet);
    return -1;
  }

  i = -1;
  hFile = CreateFile(pszFile, GENERIC_READ | GENERIC_WRITE,
                     FILE_SHARE_READ | FILE_SHARE_WRITE,
                     NULL, OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, NULL);
  if(hFile != INVALID_HANDLE_VALUE)
  {
    if(SetFilePointer(hFile, distance, NULL, FILE_BEGIN) != 0xFFFFFFFF)
    {
      if(SetEndOfFile(hFile))
        i = 0;
    }
    CloseHandle(hFile);
  }

  return i;
}

/*********************** statfs ****************************/

/**
 * @author Prof. A Olowofoyeku (The African Chief)
 * @author Frank Heckenbach
 * source: http://gd.tuwien.ac.at/gnu/mingw/os-hacks.h
 */

int statfs(const char *path, struct statfs *buf)
{
  HINSTANCE h;
  FARPROC f;
  char tmp[MAX_PATH], resolved_path[MAX_PATH];
  int retval = 0;

  errno = 0;

  realpath(path, resolved_path);
  if(!resolved_path)
    retval = -1;
  else
  {
    /* check whether GetDiskFreeSpaceExA is supported */
    h = LoadLibraryA("kernel32.dll");
    if(h)
      f = GetProcAddress(h, "GetDiskFreeSpaceExA");
    else
      f = NULL;
    if(f)
    {
      ULARGE_INTEGER bytes_free, bytes_total, bytes_free2;
      if(!f(resolved_path, &bytes_free2, &bytes_total, &bytes_free))
      {
        errno = ENOENT;
        retval = -1;
      }
      else
      {
        buf->f_bsize = FAKED_BLOCK_SIZE;
        buf->f_bfree = (bytes_free.QuadPart) / FAKED_BLOCK_SIZE;
        buf->f_files = buf->f_blocks =
          (bytes_total.QuadPart) / FAKED_BLOCK_SIZE;
        buf->f_ffree = buf->f_bavail =
          (bytes_free2.QuadPart) / FAKED_BLOCK_SIZE;
      }
    }
    else
    {
      DWORD sectors_per_cluster, bytes_per_sector;
      if(h)
        FreeLibrary(h);
      if(!GetDiskFreeSpaceA(resolved_path, &sectors_per_cluster,
                            &bytes_per_sector, &buf->f_bavail,
                            &buf->f_blocks))
      {
        errno = ENOENT;
        retval = -1;
      }
      else
      {
        buf->f_bsize = sectors_per_cluster * bytes_per_sector;
        buf->f_files = buf->f_blocks;
        buf->f_ffree = buf->f_bavail;
        buf->f_bfree = buf->f_bavail;
      }
    }
    if(h)
      FreeLibrary(h);
  }

  /* get the FS volume information */
  if(strspn(":", resolved_path) > 0)
    resolved_path[3] = '\0';    /* we want only the root */
  if(GetVolumeInformation
     (resolved_path, NULL, 0, &buf->f_fsid, &buf->f_namelen, NULL, tmp,
      MAX_PATH))
  {
    if(strcasecmp("NTFS", tmp) == 0)
    {
      buf->f_type = NTFS_SUPER_MAGIC;
    }
    else
    {
      buf->f_type = MSDOS_SUPER_MAGIC;
    }
  }
  else
  {
    errno = ENOENT;
    retval = -1;
  }
  return retval;
}

/*********************** End of statfs **********************/

const char *hstrerror(int err)
{
  if(err < 0)
    err = 5;
  else if(err > 4)
    err = 6;

  return errlist[err];
}

void gettimeofday(struct timeval *tp, void *tzp)
{
  struct _timeb theTime;

  errno = 0;

  _ftime(&theTime);
  tp->tv_sec = theTime.time;
  tp->tv_usec = theTime.millitm * 1000;
}

int mkstemp(char *tmplate)
{
  static const char letters[]
    = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  int iLen, iRnd;
  char *pChr;
  char szDest[_MAX_PATH + 1];

  errno = 0;

  iLen = strlen(tmplate);
  if(iLen >= 6)
  {
    pChr = tmplate + iLen - 6;
    srand((unsigned int) time(NULL));

    if(strncmp(pChr, "XXXXXX", 6) == 0)
    {
      int iChr;
      for(iChr = 0; iChr < 6; iChr++)
      {
        /* 528.5 = RAND_MAX / letters */
        iRnd = rand() / 528.5;
        *(pChr++) = letters[iRnd > 0 ? iRnd - 1 : 0];
      }
    }
    else
    {
      errno = EINVAL;
      return -1;
    }
  }
  else
  {
    errno = EINVAL;
    return -1;
  }

  conv_to_win_path(tmplate, szDest);

  return _open(szDest, _O_CREAT | _O_EXCL, _S_IREAD | _S_IWRITE);
}

/*********************** posix path -> win path ****************************/

/**
 * Get information from the Windows registry
 * @param hMainKey handle to (main-)key to query (HKEY_LOCAL_MACHINE etc.)
 * @param pszKey name of key to query
 * @param pszSubKey name of subkey to query
 * @param pszBuffer buffer for returned string
 * @param pdLength receives size of returned string
 * @return Error code from winerror.h, ERROR_SUCCESS on success
 */
long QueryRegistry(HKEY hMainKey, char *pszKey, char *pszSubKey,
              char *pszBuffer, long *pdLength)
{
  HKEY hKey;
  long lRet;

  if((lRet = RegOpenKeyEx(hMainKey, pszKey, 0, KEY_EXECUTE, &hKey)) ==
     ERROR_SUCCESS)
  {
    lRet = RegQueryValueEx(hKey, pszSubKey, 0, NULL, pszBuffer, pdLength);

    RegCloseKey(hKey);
  }

  return lRet;
}

/**
 * Determine the Windows path of our / directory
 * @return Error code from winerror.h, ERROR_SUCCESS on success
 */
long DetermineRootDir()
{
  char szModule[_MAX_PATH], szDrv[_MAX_DRIVE], szDir[_MAX_DIR];
  long lDirLen;

  /* Get the path of the calling module.
     It should be located in one of the "bin" directories */
  GetModuleFileName(NULL, szModule, MAX_PATH);
  _splitpath(szModule, szDrv, szDir, NULL, NULL);

  lDirLen = strlen(szDir);

  if(stricmp(szDir + lDirLen - 15, "\\usr\\local\\bin\\") == 0)
    szDir[lDirLen -= 14] = 0;
  /* "\\local\\bin" is right, "/usr" points to "/" under MinGW */
  else if(stricmp(szDir + lDirLen - 11, "\\local\\bin\\") == 0)
    szDir[lDirLen -= 10] = 0;
  else if(stricmp(szDir + lDirLen - 9, "\\usr\\bin\\") == 0)
    szDir[lDirLen -= 8] = 0;
  else if(stricmp(szDir + lDirLen - 5, "\\bin\\") == 0)
    szDir[lDirLen -= 4] = 0;
  else
  {
    /* Get the installation path from the registry */
    lDirLen = _MAX_PATH - 1;

    if(QueryRegistry
       (HKEY_CURRENT_USER, "Software\\GNU\\GNUnet", "InstallDir",
        szRootDir, &lDirLen) != ERROR_SUCCESS)
    {
      lDirLen = _MAX_PATH - 1;

      if(QueryRegistry
         (HKEY_LOCAL_MACHINE, "Software\\GNU\\GNUnet", "InstallDir",
          szRootDir, &lDirLen) != ERROR_SUCCESS)
      {
        return ERROR_BAD_ENVIRONMENT;
      }
    }
    strcat(szRootDir, "\\");
    lRootDirLen = lDirLen;
    szDrv[0] = 0;
  }

  if(szDrv[0])
  {
    strcpy(szRootDir, szDrv);
    lRootDirLen = 3 + lDirLen - 1;      /* 3 = strlen(szDir) */
    if(lRootDirLen > _MAX_PATH)
      return ERROR_BUFFER_OVERFLOW;

    strcat(szRootDir, szDir);
  }

  return ERROR_SUCCESS;
}

/**
 * Determine the user's home directory
 * @return Error code from winerror.h, ERROR_SUCCESS on success
*/
long DetermineHomeDir()
{
  char *lpszProfile = getenv("USERPROFILE");
  if(lpszProfile != NULL && lpszProfile[0] != 0)        /* Windows NT */
  {
    lHomeDirLen = strlen(lpszProfile);
    if(lHomeDirLen + 1 > _MAX_PATH)
      return ERROR_BUFFER_OVERFLOW;

    strcpy(szHomeDir, lpszProfile);
    if(szHomeDir[lHomeDirLen - 1] != '\\')
    {
      szHomeDir[lHomeDirLen] = '\\';
      szHomeDir[++lHomeDirLen] = 0;
    }
  }
  else
  {
    /* C:\My Documents */
    long lRet;

    lHomeDirLen = _MAX_PATH;
    lRet = QueryRegistry(HKEY_CURRENT_USER,
                         "Software\\Microsoft\\Windows\\CurrentVersion\\"
                         "Explorer\\Shell Folders",
                         "Personal", szHomeDir, &lHomeDirLen);

    if(lRet == ERROR_BUFFER_OVERFLOW)
      return ERROR_BUFFER_OVERFLOW;
    else if(lRet == ERROR_SUCCESS)
    {
      /* lHomeDirLen includes \0 */
      if (lHomeDirLen <= _MAX_PATH)
        strcat(szHomeDir, "\\");
      else
        return ERROR_BUFFER_OVERFLOW;
    }
    else
    {
      /* C:\Program Files\GNUnet\home\... */
      /* 5 = strlen("home\\") */
      lHomeDirLen = strlen(szRootDir) + strlen(szUser) + 5 + 1;

      if(_MAX_PATH < lHomeDirLen)
        return ERROR_BUFFER_OVERFLOW;

      strcpy(szHomeDir, szRootDir);
      strcat(szHomeDir, "home\\");
      strcat(szHomeDir, szUser);
      strcat(szHomeDir, "\\");
    }
  }

  return ERROR_SUCCESS;
}

/**
 * Initialize POSIX emulation and set up Windows environment
 * @return Error code from winerror.h, ERROR_SUCCESS on success
*/
void InitWinEnv()
{
  long lRet;
  WSADATA wsaData;
  enum {ROOT, USER, HOME} eAction = ROOT;

  /* Init path translation */
  if((lRet = DetermineRootDir()) == ERROR_SUCCESS)
  {
    DWORD dwSize = 261;

    eAction = USER;
    GetUserName(szUser, &dwSize);

    eAction = HOME;
    lRet = DetermineHomeDir();
  }

  if(lRet != ERROR_SUCCESS)
  {
    char *pszMsg, *pszMsg2;

    lRet =
      FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                    FORMAT_MESSAGE_FROM_SYSTEM |
                    FORMAT_MESSAGE_IGNORE_INSERTS, NULL, lRet, 0,
                    (LPTSTR) & pszMsg, 0, NULL);

    pszMsg2 = (char *) MALLOC(lRet + 1);
    strcpy(pszMsg2, pszMsg);
    if(pszMsg2[lRet - 2] == '\r')
      pszMsg2[lRet - 2] = 0;

    LOG(LOG_FAILURE, "Cannot determine %s (%s)\n",
            eAction == ROOT ? "root directory" :
              "home directory", pszMsg2);
    LocalFree(pszMsg);
    FREE(pszMsg2);

    exit(1);
  }

  /* Init Winsock */
  if (WSAStartup(257, &wsaData) != 0)
  {
    LOG(LOG_FAILURE, "Cannot initialize Winsock.\n");

    exit(1);
  }

  /* To keep track of blocking/non-blocking sockets */
  pSocks = (Winsock *) malloc(sizeof(Winsock) + (uiSockCount + 1));
  pSocks[0].s = -1;
  hSocksLock = CreateMutex(NULL, FALSE, NULL);

  /* To keep track of mapped files */
  pMappings = (TMapping *) malloc(sizeof(TMapping));
  pMappings[0].pStart = NULL;
  hMappingsLock = CreateMutex(NULL, FALSE, NULL);

  /* Open files in binary mode */
  _fmode = _O_BINARY;

  /* Get Windows version */
  theWinVersion.dwOSVersionInfoSize = sizeof(theWinVersion);
  GetVersionEx(&theWinVersion);

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
  }
  else
  {
    GNGetIfEntry = NULL;
    GNGetIpAddrTable = NULL;
    GNGetIfTable = NULL;
    GNGetBestInterface = NULL;
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

  /* Use ANSI codepage for console IO */
  SetConsoleCP(CP_ACP);
  SetConsoleOutputCP(CP_ACP);
  setlocale( LC_ALL, ".OCP" );

  /* Initialize COM library */
  CoInitializeEx(NULL, COINIT_MULTITHREADED);
}

/**
 * Clean up Windows environment
 */
void ShutdownWinEnv()
{
  WSACleanup();
  free(pSocks);
  CloseHandle(hSocksLock);

  free(pMappings);
  CloseHandle(hMappingsLock);

  FreeLibrary(hNTDLL);
  FreeLibrary(hIphlpapi);
  FreeLibrary(hAdvapi);

  CoUninitialize();
}

/**
 * Dereference a symlink recursively
 */
int __win_deref(char *path)
{
  int iDepth = 0;

  errno = 0;

  while (DereferenceShortcut(path))
  {
    if (iDepth++ > 10)
    {
      errno = ELOOP;
      return -1;
    }
  }

  return errno ? -1 : 0;
}

/**
 * Convert a POSIX-sytle path to a Windows-style path
 * @param pszUnix POSIX path
 * @param pszWindows Windows path
 * @param derefLinks 1 to dereference links
 * @return Error code from winerror.h, ERROR_SUCCESS on success
*/
int conv_to_win_path_ex(const char *pszUnix, char *pszWindows, int derefLinks)
{
  char *pSrc, *pDest;
  long iSpaceUsed;
  int iUnixLen;

  iUnixLen = strlen(pszUnix);

  /* Check if we already have a windows path */
  if((strchr(pszUnix, '\\') != NULL) || (strchr(pszUnix, ':') != NULL))
  {
    if(iUnixLen > MAX_PATH)
      return ERROR_BUFFER_OVERFLOW;
    strcpy(pszWindows, pszUnix);
  }

  /* Is the unix path a full path? */
  if(pszUnix[0] == '/')
  {
    strcpy(pszWindows, szRootDir);
    iSpaceUsed = lRootDirLen;
    pDest = pszWindows + lRootDirLen;
    pSrc = (char *) pszUnix + 1;
  }
  /* Temp. dir? */
  else if(strncmp(pszUnix, "/tmp/", 5) == 0)
  {
    iSpaceUsed = GetTempPath(_MAX_PATH, pszWindows);
    if (iSpaceUsed > _MAX_PATH)
      return ERROR_BUFFER_OVERFLOW;
    pDest = pszWindows + iSpaceUsed;
    pSrc = (char *) pszUnix + 5;
  }
  /* Home dir? */
  else if(strncmp(pszUnix, "~/", 2) == 0)
  {
    strcpy(pszWindows, szHomeDir);
    iSpaceUsed = lHomeDirLen;
    pDest = pszWindows + lHomeDirLen;
    pSrc = (char *) pszUnix + 2;
  }
  /* Bit bucket? */
  else if (strncmp(pszUnix, "/dev/null", 9) == 0)
  {
    strcpy(pszWindows, "nul");
    iSpaceUsed = 3;
    pDest = pszWindows + lHomeDirLen;
    pSrc = (char *) pszUnix + 9;
  }
  else
  {
    pDest = pszWindows;
    iSpaceUsed = 0;
    pSrc = (char *) pszUnix;
  }

  if(iSpaceUsed + strlen(pSrc) + 1 > _MAX_PATH)
    return ERROR_BUFFER_OVERFLOW;

  /* substitute all slashes */
  while(*pSrc)
  {
    if(*pSrc == '/')
      *pDest = '\\';
    else
      *pDest = *pSrc;

    pDest++;
    pSrc++;
  }
  *pDest = 0;

  if (derefLinks)
    __win_deref(pszWindows);

#if DEBUG_WINPROC
  LOG(LOG_EVERYTHING, "Posix path %s resolved to %s\n", pszUnix, pszWindows);
#endif

  return ERROR_SUCCESS;
}

/*********************** posix path -> win path ****************************/

/**
 * Set errno according to a Windows error
 * @param lWinError Error code defined in winerror.h
 */
void _SetErrnoFromWinError(long lWinError, char *pszCaller, int iLine)
{
  switch(lWinError)
  {
    case ERROR_SUCCESS:
      errno = 0;
      break;

    case ERROR_INVALID_FUNCTION:
      errno = EBADRQC;
      break;

    case ERROR_FILE_NOT_FOUND:
      errno = ENOENT;
      break;

    case ERROR_PATH_NOT_FOUND:
      errno = ENOENT;
      break;

    case ERROR_TOO_MANY_OPEN_FILES:
      errno = EMFILE;
      break;

    case ERROR_ACCESS_DENIED:
      errno = EACCES;
      break;

    case ERROR_INVALID_HANDLE:
      errno = EBADF;
      break;

    case ERROR_NOT_ENOUGH_MEMORY:
      errno = ENOMEM;
      break;

    case ERROR_INVALID_DATA:
      errno = EINVAL;
      break;

    case ERROR_OUTOFMEMORY:
      errno = ENOMEM;
      break;

    case ERROR_INVALID_DRIVE:
      errno = ENODEV;
      break;

    case ERROR_NOT_SAME_DEVICE:
      errno = EXDEV;
      break;

    case ERROR_NO_MORE_FILES:
      errno = ENMFILE;
      break;

    case ERROR_WRITE_PROTECT:
      errno = EROFS;
      break;

    case ERROR_BAD_UNIT:
      errno = ENODEV;
      break;

    case ERROR_SHARING_VIOLATION:
      errno = EACCES;
      break;

    case ERROR_LOCK_VIOLATION:
      errno = EACCES;
      break;

    case ERROR_SHARING_BUFFER_EXCEEDED:
      errno = ENOLCK;
      break;

    case ERROR_HANDLE_EOF:
      errno = ENODATA;
      break;

    case ERROR_HANDLE_DISK_FULL:
      errno = ENOSPC;
      break;

    case ERROR_NOT_SUPPORTED:
      errno = ENOSYS;
      break;

    case ERROR_REM_NOT_LIST:
      errno = ENONET;
      break;

    case ERROR_DUP_NAME:
      errno = ENOTUNIQ;
      break;

    case ERROR_BAD_NETPATH:
      errno = ENOSHARE;
      break;

    case ERROR_BAD_NET_NAME:
      errno = ENOSHARE;
      break;

    case ERROR_FILE_EXISTS:
      errno = EEXIST;
      break;

    case ERROR_CANNOT_MAKE:
      errno = EPERM;
      break;

    case ERROR_INVALID_PARAMETER:
      errno = EINVAL;
      break;

    case ERROR_NO_PROC_SLOTS:
      errno = EAGAIN;
      break;

    case ERROR_BROKEN_PIPE:
      errno = EPIPE;
      break;

    case ERROR_OPEN_FAILED:
      errno = EIO;
      break;

    case ERROR_NO_MORE_SEARCH_HANDLES:
      errno = ENFILE;
      break;

    case ERROR_CALL_NOT_IMPLEMENTED:
      errno = ENOSYS;
      break;

    case ERROR_INVALID_NAME:
      errno = ENOENT;
      break;

    case ERROR_WAIT_NO_CHILDREN:
      errno = ECHILD;
      break;

    case ERROR_CHILD_NOT_COMPLETE:
      errno = EBUSY;
      break;

    case ERROR_DIR_NOT_EMPTY:
      errno = ENOTEMPTY;
      break;

    case ERROR_SIGNAL_REFUSED:
      errno = EIO;
      break;

    case ERROR_BAD_PATHNAME:
      errno = ENOENT;
      break;

    case ERROR_SIGNAL_PENDING:
      errno = EBUSY;
      break;

    case ERROR_MAX_THRDS_REACHED:
      errno = EAGAIN;
      break;

    case ERROR_BUSY:
      errno = EBUSY;
      break;

    case ERROR_ALREADY_EXISTS:
      errno = EEXIST;
      break;

    case ERROR_NO_SIGNAL_SENT:
      errno = EIO;
      break;

    case ERROR_FILENAME_EXCED_RANGE:
      errno = EINVAL;
      break;

    case ERROR_META_EXPANSION_TOO_LONG:
      errno = EINVAL;
      break;

    case ERROR_INVALID_SIGNAL_NUMBER:
      errno = EINVAL;
      break;

    case ERROR_THREAD_1_INACTIVE:
      errno = EINVAL;
      break;

    case ERROR_BAD_PIPE:
      errno = EINVAL;
      break;

    case ERROR_PIPE_BUSY:
      errno = EBUSY;
      break;

    case ERROR_NO_DATA:
      errno = EPIPE;
      break;

    case ERROR_PIPE_NOT_CONNECTED:
      errno = ECOMM;
      break;

    case ERROR_MORE_DATA:
      errno = EAGAIN;
      break;

    case ERROR_DIRECTORY:
      errno = ENOTDIR;
      break;

    case ERROR_PIPE_CONNECTED:
      errno = EBUSY;
      break;

    case ERROR_PIPE_LISTENING:
      errno = ECOMM;
      break;

    case ERROR_NO_TOKEN:
      errno = EINVAL;
      break;

    case ERROR_PROCESS_ABORTED:
      errno = EFAULT;
      break;

    case ERROR_BAD_DEVICE:
      errno = ENODEV;
      break;

    case ERROR_BAD_USERNAME:
      errno = EINVAL;
      break;

    case ERROR_NOT_CONNECTED:
      errno = ENOLINK;
      break;

    case ERROR_OPEN_FILES:
      errno = EAGAIN;
      break;

    case ERROR_ACTIVE_CONNECTIONS:
      errno = EAGAIN;
      break;

    case ERROR_DEVICE_IN_USE:
      errno = EAGAIN;
      break;

    case ERROR_INVALID_AT_INTERRUPT_TIME:
      errno = EINTR;
      break;

    case ERROR_IO_DEVICE:
      errno = EIO;
      break;

    case ERROR_NOT_OWNER:
      errno = EPERM;
      break;

    case ERROR_END_OF_MEDIA:
      errno = ENOSPC;
      break;

    case ERROR_EOM_OVERFLOW:
      errno = ENOSPC;
      break;

    case ERROR_BEGINNING_OF_MEDIA:
      errno = ESPIPE;
      break;

    case ERROR_SETMARK_DETECTED:
      errno = ESPIPE;
      break;

    case ERROR_NO_DATA_DETECTED:
      errno = ENOSPC;
      break;

    case ERROR_POSSIBLE_DEADLOCK:
      errno = EDEADLOCK;
      break;

    case ERROR_CRC:
      errno = EIO;
      break;

    case ERROR_NEGATIVE_SEEK:
      errno = EINVAL;
      break;

    case ERROR_NOT_READY:
      errno = ENOMEDIUM;
      break;

    case ERROR_DISK_FULL:
      errno = ENOSPC;
      break;

    case ERROR_NOACCESS:
      errno = EFAULT;
      break;

    case ERROR_FILE_INVALID:
      errno = ENXIO;
      break;

    case ERROR_INVALID_ADDRESS:
      errno = EFAULT;
      break;

    case ERROR_BUFFER_OVERFLOW:
      errno = ENOMEM;
      break;

    case ERROR_SERVICE_DOES_NOT_EXIST:
      errno = ESRCH;
      break;

    case ERROR_SERVICE_EXISTS:
      errno = EEXIST;
      break;

    default:
      errno = ESTALE;
      LOG(LOG_ERROR, " Unknown error %i in SetErrnoFromWinError(). " \
          "Source: %s:%i\n", lWinError, pszCaller, iLine);
      break;
  }
}

/**
 * Set errno according to a Winsock error
 * @param lWinError Error code defined in winsock.h
 */
void SetErrnoFromWinsockError(long lWinError)
{
  switch(lWinError)
  {
    case 0:
      errno = 0;
      break;
    case WSAEINTR:
      errno = EINTR;
      break;

    case WSAEWOULDBLOCK:
      errno = EWOULDBLOCK;
      break;

    case WSAEINPROGRESS:
      errno = EINPROGRESS;
      break;

    case WSAEALREADY:
      errno = EALREADY;
      break;

    case WSAENOTSOCK:
      errno = ENOTSOCK;
      break;

    case WSAEDESTADDRREQ:
      errno = EDESTADDRREQ;
      break;

    case WSAEMSGSIZE:
      errno = EMSGSIZE;
      break;

    case WSAEPROTOTYPE:
      errno = EPROTOTYPE;
      break;

    case WSAENOPROTOOPT:
      errno = ENOPROTOOPT;
      break;

    case WSAEPROTONOSUPPORT:
      errno = EPROTONOSUPPORT;
      break;

    case WSAESOCKTNOSUPPORT:
      errno = ESOCKTNOSUPPORT;
      break;

    case WSAEOPNOTSUPP:
      errno = EOPNOTSUPP;
      break;

    case WSAEPFNOSUPPORT:
      errno = EPFNOSUPPORT;
      break;

    case WSAEAFNOSUPPORT:
      errno = EAFNOSUPPORT;
      break;

    case WSAEADDRINUSE:
      errno = EADDRINUSE;
      break;

    case WSAEADDRNOTAVAIL:
      errno = EADDRNOTAVAIL;
      break;

    case WSAENETDOWN:
      errno = ENETDOWN;
      break;

    case WSAENETUNREACH:
      errno = ENETUNREACH;
      break;

    case WSAENETRESET:
      errno = ENETRESET;
      break;

    case WSAECONNABORTED:
      errno = ECONNABORTED;
      break;

    case WSAECONNRESET:
      errno = ECONNRESET;
      break;

    case WSAENOBUFS:
      errno = ENOBUFS;
      break;

    case WSAEISCONN:
      errno = EISCONN;
      break;

    case WSAENOTCONN:
      errno = ENOTCONN;
      break;

    case WSAESHUTDOWN:
      errno = ESHUTDOWN;
      break;

    case WSAETOOMANYREFS:
      errno = ETOOMANYREFS;
      break;

    case WSAETIMEDOUT:
      errno = ETIMEDOUT;
      break;

    case WSAECONNREFUSED:
      errno = ECONNREFUSED;
      break;

    case WSAELOOP:
      errno = ELOOP;
      break;

    case WSAENAMETOOLONG:
      errno = ENAMETOOLONG;
      break;

    case WSAEHOSTDOWN:
      errno = EHOSTDOWN;
      break;

    case WSAEHOSTUNREACH:
      errno = EHOSTUNREACH;
      break;

    case WSAENOTEMPTY:
      errno = ENOTEMPTY;
      break;

    case WSAEPROCLIM:
      errno = EPROCLIM;
      break;

    case WSAEUSERS:
      errno = EUSERS;
      break;

    case WSAEDQUOT:
      errno = EDQUOT;
      break;

    case WSAESTALE:
      errno = ESTALE;
      break;

    case WSAEREMOTE:
      errno = EREMOTE;
      break;

    case WSAEINVAL:
      errno = EINVAL;
      break;

    case WSAEFAULT:
      errno = EFAULT;
      break;

    default:
      errno = ESTALE;
      LOG(LOG_ERROR, " Unknown error %i in SetErrnoFromWinsockError()\n",
          lWinError);
      break;
  }
}

/**
 * Set errno according to a HRESULT (COM error code)
 */
void SetErrnoFromHRESULT(HRESULT hRes)
{
  switch(hRes)
  {
    case NOERROR:
      errno = 0;
      break;
    case E_UNEXPECTED:
    case E_FAIL:
    case S_FALSE:
      errno = ESTALE;
    case E_NOTIMPL:
      errno = ENOSYS;
      break;
    case E_OUTOFMEMORY:
      errno = ENOMEM;
      break;
    case E_INVALIDARG:
    case E_NOINTERFACE:
      errno = EINVAL;
      break;
    case E_POINTER:
    case E_ABORT:
      errno = EFAULT;
      break;
    case E_HANDLE:
      errno = EBADF;
      break;
    case E_ACCESSDENIED:
      errno = EACCES;
      break;
    case E_PENDING:
      errno = EBUSY;
      break;
    default:
      SetErrnoFromWinError(HRESULT_CODE(hRes));
  }
}

/**
 * Set h_errno according to a Windows error
 * @param lWinError Error code defined in winerror.h
 */
void SetHErrnoFromWinError(long lWinError)
{
  switch(lWinError)
  {
    case WSAHOST_NOT_FOUND:
      /* h_errno is defined as WSAGetLastError */
      WSASetLastError(HOST_NOT_FOUND);
      break;

    case WSATRY_AGAIN:
      WSASetLastError(TRY_AGAIN);
      break;

    case WSANO_RECOVERY:
      WSASetLastError(NO_RECOVERY);
      break;

    case WSANO_DATA:
      WSASetLastError(NO_DATA);
      break;
  }
}

/**
 * Apply or remove an advisory lock on an open file
 */
int flock(int fd, int operation)
{
  DWORD dwFlags;
  HANDLE hFile;
  OVERLAPPED theOvInfo;
  BOOL bRet;

  errno = 0;

  hFile = (HANDLE) _get_osfhandle(fd);
  memset(&theOvInfo, sizeof(OVERLAPPED), 0);

  /* Don't deadlock ourselves */
  if (theWinVersion.dwPlatformId == VER_PLATFORM_WIN32_NT)
    bRet = UnlockFileEx(hFile, 0, 1, 0, &theOvInfo);
  else
    bRet = UnlockFile(hFile, 0, 0, 1, 0);

  if (operation & LOCK_UN)
  {
    if (!bRet && ((dwFlags = GetLastError()) != ERROR_NOT_LOCKED))
    {
      SetErrnoFromWinError(dwFlags);
      return -1;
    }
    else
      return 0;
  }

  if (operation & LOCK_EX)
  {
    dwFlags = LOCKFILE_EXCLUSIVE_LOCK;
  }
  else if (operation & LOCK_SH)
  {
    dwFlags = 0;
  }
  else
  {
    errno = EINVAL;
    return -1;
  }

  if (operation & LOCK_NB)
    dwFlags |= LOCKFILE_FAIL_IMMEDIATELY;

  if (theWinVersion.dwPlatformId == VER_PLATFORM_WIN32_NT)
    bRet = LockFileEx(hFile, dwFlags, 0, 1, 0, &theOvInfo);
  else
    bRet = LockFile(hFile, 0, 0, 1, 0);

  if (! bRet)
  {
    SetErrnoFromWinError(GetLastError());
    return -1;
  }
  else
    return 0;
}

/**
 * Synchronize changes to a file
 */
int fsync(int fildes)
{
  if (!FlushFileBuffers((HANDLE) _get_osfhandle(fildes)))
  {
    SetErrnoFromWinError(GetLastError());
    return -1;
  }
  else
  {
    errno = 0;
    return 0;
  }
}

/**
 * Open a file
 */
FILE *_win_fopen(const char *filename, const char *mode)
{
  char szFile[_MAX_PATH + 1];
  FILE *hFile;
  int i;

  if ((i = conv_to_win_path(filename, szFile)) != ERROR_SUCCESS)
  {
    SetErrnoFromWinError(i);

    return NULL;
  }

  hFile = fopen(szFile, mode);
  SetErrnoFromWinError(GetLastError());

  return hFile;
}

/**
 * Open a directory
 */
DIR *_win_opendir(const char *dirname)
{
  char szDir[_MAX_PATH + 1];
  long lRet;

  if ((lRet = conv_to_win_path(dirname, szDir)) != ERROR_SUCCESS)
  {
    SetErrnoFromWinError(lRet);
    return NULL;
  }

  /* opendir sets errno */
  return opendir(szDir);
}

/**
 * Change directory
 */
int _win_chdir(const char *path)
{
  char szDir[_MAX_PATH + 1];
  long lRet;

  if ((lRet = conv_to_win_path(path, szDir)) != ERROR_SUCCESS)
  {
    SetErrnoFromWinError(lRet);
    return -1;
  }

  /* chdir sets errno */
  return chdir(szDir);
}

/**
 * Get information about an open file.
 */
int _win_fstat(int handle, struct stat *buffer)
{
  errno = 0;

  /* File */
  if (fstat(handle, buffer) == -1)
  {
    /* We just check for a valid handle here */

    /* Handle */
    memset(buffer, sizeof(struct stat), 0);
    GetFileType((HANDLE) handle);
    if (GetLastError() != NO_ERROR)
    {
      /* socket */
      unsigned long lRead;
      if (ioctlsocket(handle, FIONREAD, &lRead) == SOCKET_ERROR)
        /* Invalid handle */
        return -1;
    }
  }

  return 0;
}

/**
 * Remove directory
 */
int _win_rmdir(const char *path)
{
  char szDir[_MAX_PATH + 1];
  long lRet;

  if ((lRet = conv_to_win_path(path, szDir)) != ERROR_SUCCESS)
  {
    SetErrnoFromWinError(lRet);
    return -1;
  }

  /* rmdir sets errno */
  return rmdir(szDir);
}

/**
 * Create a pipe for reading and writing
 */
int _win_pipe(int *phandles)
{
  /* To get non-blocking pipes we could use CreateNamedPipe here. But it isn't
     implemented under Win9x. */
  if (!CreatePipe((HANDLE *) &phandles[0],(HANDLE *) &phandles[1], NULL, 0))
  {
    SetErrnoFromWinError(GetLastError());

    return -1;
  }
  else
  {
    errno = 0;
    return 0;
  }
}

/**
 * Determine file-access permission.
 */
int _win_access( const char *path, int mode )
{
  char szFile[_MAX_PATH + 1];
  long lRet;

  if ((lRet = conv_to_win_path(path, szFile)) != ERROR_SUCCESS)
  {
    SetErrnoFromWinError(lRet);
    return -1;
  }

  /* access sets errno */
  return access(szFile, mode);
}

/**
 * Change the file-permission settings.
 */
int _win_chmod(const char *filename, int pmode)
{
  char szFile[_MAX_PATH + 1];
  long lRet;

  if ((lRet = conv_to_win_path(filename, szFile)) != ERROR_SUCCESS)
  {
    SetErrnoFromWinError(lRet);
    return -1;
  }

  /* chmod sets errno */
  return access(szFile, pmode);
}


char *realpath(const char *file_name, char *resolved_name)
{
  char szFile[_MAX_PATH + 1];
  long lRet;
  char *pszRet;

  if ((lRet = conv_to_win_path(file_name, szFile)) != ERROR_SUCCESS)
  {
    SetErrnoFromWinError(lRet);
    return NULL;
  }

  pszRet = _fullpath(szFile, resolved_name, MAX_PATH);
  SetErrnoFromWinError(GetLastError());

  return pszRet;
}

/**
 * Delete a file
 * If path is a link, the link itself is removed
 */
int _win_remove(const char *path)
{
  char szFile[_MAX_PATH + 1];
  long lRet;

  if ((lRet = conv_to_win_path_ex(path, szFile, 0)) != ERROR_SUCCESS)
  {
    SetErrnoFromWinError(lRet);
    return -1;
  }

  /* remove sets errno */
  return remove(szFile);
}

/**
 * Rename a file
 * If oldname is a link, the link itself is renamed
 */
int _win_rename(const char *oldname, const char *newname)
{
  char szOldName[_MAX_PATH + 1];
  char szNewName[_MAX_PATH + 1];
  long lRet;

  if ((lRet = conv_to_win_path_ex(oldname, szOldName, 0)) != ERROR_SUCCESS)
  {
    SetErrnoFromWinError(lRet);
    return -1;
  }

  if ((lRet = conv_to_win_path(newname, szNewName)) != ERROR_SUCCESS)
  {
    SetErrnoFromWinError(lRet);
    return -1;
  }

  /* rename sets errno */
  return rename(szOldName, szNewName);
}

/**
 * Get status information on a file
 */
int __win_stat(const char *path, struct stat *buffer, int iDeref)
{
  char szFile[_MAX_PATH + 1];
  long lRet;

  if ((lRet = conv_to_win_path(path, szFile)) != ERROR_SUCCESS)
  {
    SetErrnoFromWinError(lRet);
    return -1;
  }

  /* Remove trailing slash */
  lRet = strlen(szFile) - 1;
  if (szFile[lRet] == '\\')
  {
    szFile[lRet] = 0;
  }

  /* Dereference symlinks */
  if (iDeref)
  {
    if (__win_deref(szFile) == -1 && errno != EINVAL)
      return -1;
  }

  /* stat sets errno */
  return stat(szFile, buffer);
}

/**
 * Get status information on a file
 */
int _win_stat(const char *path, struct stat *buffer)
{
  return __win_stat(path, buffer, 1);
}

/**
 * Delete a file
 * If filename is a link, the link itself it removed.
 */
int _win_unlink(const char *filename)
{
  char szFile[_MAX_PATH + 1];
  long lRet;

  if ((lRet = conv_to_win_path_ex(filename, szFile, 0)) != ERROR_SUCCESS)
  {
    SetErrnoFromWinError(lRet);
    return -1;
  }

  /* unlink sets errno */
  return unlink(szFile);
}

DWORD WINAPI __win_Write(TReadWriteInfo *pInfo)
{
  int iRet;

  errno = 0;
  if ((iRet = write(pInfo->fildes, pInfo->buf, pInfo->nbyte)) == -1)
  {
    DWORD dwWritten;
    if (!WriteFile((HANDLE) pInfo->fildes, pInfo->buf, pInfo->nbyte,
      &dwWritten, NULL))
    {
      SetErrnoFromWinError(GetLastError());
      return -1;
    }
    else
      return dwWritten;
  }
  else
    return iRet;
}

/**
 * Write on a file
 * If the handle is in non-blocking mode, this function
 * always returns 1 for non-sockets.
 */
int _win_write(int fildes, const void *buf, size_t nbyte)
{
  if (isSocketValid(fildes))
  {
    return _win_send(fildes, buf, nbyte, 0);
  }
  else
  {
    TReadWriteInfo theInfo;
    theInfo.fildes = fildes;
    theInfo.buf = (void *) buf;
    theInfo.nbyte = nbyte;

    if (__win_IsHandleMarkedAsBlocking(fildes))
      return __win_Write(&theInfo);
    else
    {
      DWORD dwTID; /* Last ptr of CreateThread my not be NULL under Win9x */
      CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) __win_Write, &theInfo, 0, &dwTID);
      return 1;
    }
  }
}

DWORD WINAPI __win_Read(TReadWriteInfo *pInfo)
{
  int iRet;

  errno = 0;
  if ((iRet = read(pInfo->fildes, pInfo->buf, pInfo->nbyte)) == -1)
  {
    DWORD dwRead;
    if (!ReadFile((HANDLE) pInfo->fildes, pInfo->buf, pInfo->nbyte, &dwRead,
      NULL))
    {
      SetErrnoFromWinError(GetLastError());
      return -1;
    }
    else
      return dwRead;
  }
  else
    return iRet;
}

/**
 * Reads data from a file.
 * If the handle is in non-blocking mode, this function
 * always returns 1 for non-sockets.
 */
int _win_read(int fildes, void *buf, size_t nbyte)
{
  if (isSocketValid(fildes))
  {
    return _win_recv(fildes, (char *) buf, nbyte, 0);
  }
  else
  {
    TReadWriteInfo theInfo;
    theInfo.fildes = fildes;
    theInfo.buf = buf;
    theInfo.nbyte = nbyte;

    if (__win_IsHandleMarkedAsBlocking(fildes))
      return __win_Read(&theInfo);
    else
    {
      DWORD dwTID; /* Last ptr of CreateThread my not be NULL under Win9x */
      CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) __win_Read, &theInfo, 0, &dwTID);
      return 1;
    }
  }
}

/**
 * Writes data to a stream
 */
size_t _win_fwrite(const void *buffer, size_t size, size_t count, FILE *stream)
{
  DWORD dwWritten;

  WriteFile((HANDLE) _get_osfhandle(fileno(stream)), buffer, size, &dwWritten,
            NULL);
  SetErrnoFromWinError(GetLastError());

  return dwWritten;
}

/**
 * Reads data from a stream
 */
size_t _win_fread( void *buffer, size_t size, size_t count, FILE *stream )
{
  DWORD dwRead;
  int iItemsRead;
  void *pDest = buffer;

  for(iItemsRead = 0; iItemsRead < count; iItemsRead++)
  {
    if (!ReadFile((HANDLE) _get_osfhandle(fileno(stream)), pDest, size,
                  &dwRead, NULL))
      break;
    pDest += size;
  }

  SetErrnoFromWinError(GetLastError());

  return iItemsRead;
}

/***
 * Make a link to a file
 **/
int _win_symlink(const char *path1, const char *path2)
{
  char szFile1[_MAX_PATH + 1], szFile2[_MAX_PATH + 1];
  long lRet;

  if ((lRet = conv_to_win_path(path1, szFile1)) != ERROR_SUCCESS)
  {
    SetErrnoFromWinError(lRet);
    return -1;
  }

  if ((lRet = conv_to_win_path(path2, szFile2)) != ERROR_SUCCESS)
  {
    SetErrnoFromWinError(lRet);
    return -1;
  }

  /* CreateShortcut sets errno */
  lRet = CreateShortcut(szFile1, szFile2);

  return lRet ? 0 : -1;
}

/**
 * map files into memory
 * @author Cygwin team
 * @author Nils Durner
 */
void *_win_mmap(void *start, size_t len, int access, int flags, int fd,
                unsigned long long off) {
  DWORD protect, high, low, access_param;
  HANDLE h, hFile;
  SECURITY_ATTRIBUTES sec_none;
  void *base;
  BOOL bFound = FALSE;
  unsigned int uiIndex;

  errno = 0;

  switch(access)
  {
    case PROT_WRITE:
      protect = PAGE_READWRITE;
      access_param = FILE_MAP_WRITE;
      break;
    case PROT_READ:
      protect = PAGE_READONLY;
      access_param = FILE_MAP_READ;
      break;
    default:
      protect = PAGE_WRITECOPY;
      access_param = FILE_MAP_COPY;
      break;
  }

  sec_none.nLength = sizeof(SECURITY_ATTRIBUTES);
  sec_none.bInheritHandle = TRUE;
  sec_none.lpSecurityDescriptor = NULL;

  hFile = (HANDLE) _get_osfhandle(fd);

  h = CreateFileMapping(hFile, &sec_none, protect, 0, 0, NULL);

  if (! h)
  {
    SetErrnoFromWinError(GetLastError());
    return (void *) -1;
  }

  high = off >> 32;
  low = off & ULONG_MAX;
  base = NULL;

  /* If a non-zero start is given, try mapping using the given address first.
     If it fails and flags is not MAP_FIXED, try again with NULL address. */
  if (start)
    base = MapViewOfFileEx(h, access_param, high, low, len, start);
  if (!base && !(flags & MAP_FIXED))
    base = MapViewOfFileEx(h, access_param, high, low, len, NULL);

  if (!base || ((flags & MAP_FIXED) && base != start))
  {
    if (!base)
      SetErrnoFromWinError(GetLastError());
    else
      errno = EINVAL;

    CloseHandle(h);
    return (void *) -1;
  }

  /* Save mapping handle */
  WaitForSingleObject(hMappingsLock, INFINITE);

  for(uiIndex = 0; uiIndex <= uiMappingsCount; uiIndex++)
  {
    if (pMappings[uiIndex].pStart == base)
    {
      bFound = 1;
      break;
    }
  }

  if (! bFound)
  {
    uiIndex = 0;

    while(TRUE)
    {
      if (pMappings[uiIndex].pStart == NULL)
      {
        pMappings[uiIndex].pStart = base;
        pMappings[uiIndex].hMapping = h;
      }
      if (uiIndex == uiMappingsCount)
      {
        uiMappingsCount++;
        pMappings = (TMapping *) realloc(pMappings, (uiMappingsCount + 1) * sizeof(TMapping));
        pMappings[uiMappingsCount].pStart = NULL;

        break;
      }
      uiIndex++;
    }
  }
  ReleaseMutex(hMappingsLock);

  return base;
}

/**
 * Unmap files from memory
 * @author Cygwin team
 * @author Nils Durner
 */
int _win_munmap(void *start, size_t length)
{
  unsigned uiIndex;
  BOOL success = UnmapViewOfFile(start);
  SetErrnoFromWinError(GetLastError());

  if (success)
  {
    /* Release mapping handle */
    WaitForSingleObject(hMappingsLock, INFINITE);

    for(uiIndex = 0; uiIndex <= uiMappingsCount; uiIndex++)
    {
      if (pMappings[uiIndex].pStart == start)
      {
        success = CloseHandle(pMappings[uiIndex].hMapping);
        SetErrnoFromWinError(GetLastError());
        pMappings[uiIndex].pStart = NULL;
        pMappings[uiIndex].hMapping = NULL;

        break;
      }
    }

    ReleaseMutex(hMappingsLock);
  }

  return success ? 0 : -1;
}

/**
 * Get symbolic link status
 */
int _win_lstat(const char *path, struct stat *buf)
{
  return __win_stat(path, buf, 0);
}

/**
 * Read the contents of a symbolic link
 */
int _win_readlink(const char *path, char *buf, size_t bufsize)
{
  char szDeref[_MAX_PATH + 1];
  int iLen;

  if(strlen(path) > _MAX_PATH)
  {
    errno = ENAMETOOLONG;
    return -1;
  }

  strcpy(szDeref, path);

  if (__win_deref(szDeref) == -1)
    return -1;

  if ((iLen = strlen(szDeref)) > bufsize)
  {
    errno = ENAMETOOLONG;
    return -1;
  }

  errno = 0;
  return iLen;
}

/**
 * language information
 */
#ifndef HAVE_LANGINFO_H
char *nl_langinfo(int item)
{
  unsigned int loc;

  loc = GetThreadLocale();

  switch(item)
  {
    case CODESET:
      {
        unsigned int cp = GetACP();

        if (cp)
          sprintf(__langinfo, "CP%u", cp);
        else
          strcpy(__langinfo, "UTF-8"); /* ? */
        return __langinfo;
      }
    case D_T_FMT:
    case T_FMT_AMPM:
    case ERA_D_T_FMT:
      strcpy(__langinfo, "%c");
      return __langinfo;
    case D_FMT:
    case ERA_D_FMT:
      strcpy(__langinfo, "%x");
      return __langinfo;
    case T_FMT:
    case ERA_T_FMT:
      strcpy(__langinfo, "%X");
      return __langinfo;
    case AM_STR:
      GetLocaleInfo(loc, LOCALE_S1159, __langinfo, 251);
      return __langinfo;
    case PM_STR:
      GetLocaleInfo(loc, LOCALE_S2359, __langinfo, 251);
      return __langinfo;
    case DAY_1:
      GetLocaleInfo(loc, LOCALE_SDAYNAME1, __langinfo, 251);
      return __langinfo;
    case DAY_2:
      GetLocaleInfo(loc, LOCALE_SDAYNAME2, __langinfo, 251);
      return __langinfo;
    case DAY_3:
      GetLocaleInfo(loc, LOCALE_SDAYNAME3, __langinfo, 251);
      return __langinfo;
    case DAY_4:
      GetLocaleInfo(loc, LOCALE_SDAYNAME4, __langinfo, 251);
      return __langinfo;
    case DAY_5:
      GetLocaleInfo(loc, LOCALE_SDAYNAME5, __langinfo, 251);
      return __langinfo;
    case DAY_6:
      GetLocaleInfo(loc, LOCALE_SDAYNAME6, __langinfo, 251);
      return __langinfo;
    case DAY_7:
      GetLocaleInfo(loc, LOCALE_SDAYNAME7, __langinfo, 251);
      return __langinfo;
    case ABDAY_1:
      GetLocaleInfo(loc, LOCALE_SABBREVDAYNAME1, __langinfo, 251);
      return __langinfo;
    case ABDAY_2:
      GetLocaleInfo(loc, LOCALE_SABBREVDAYNAME2, __langinfo, 251);
      return __langinfo;
    case ABDAY_3:
      GetLocaleInfo(loc, LOCALE_SABBREVDAYNAME3, __langinfo, 251);
      return __langinfo;
    case ABDAY_4:
      GetLocaleInfo(loc, LOCALE_SABBREVDAYNAME4, __langinfo, 251);
      return __langinfo;
    case ABDAY_5:
      GetLocaleInfo(loc, LOCALE_SABBREVDAYNAME5, __langinfo, 251);
      return __langinfo;
    case ABDAY_6:
      GetLocaleInfo(loc, LOCALE_SABBREVDAYNAME6, __langinfo, 251);
      return __langinfo;
    case ABDAY_7:
      GetLocaleInfo(loc, LOCALE_SABBREVDAYNAME7, __langinfo, 251);
      return __langinfo;
    case MON_1:
      GetLocaleInfo(loc, LOCALE_SMONTHNAME1, __langinfo, 251);
      return __langinfo;
    case MON_2:
      GetLocaleInfo(loc, LOCALE_SMONTHNAME2, __langinfo, 251);
      return __langinfo;
    case MON_3:
      GetLocaleInfo(loc, LOCALE_SMONTHNAME3, __langinfo, 251);
      return __langinfo;
    case MON_4:
      GetLocaleInfo(loc, LOCALE_SMONTHNAME4, __langinfo, 251);
      return __langinfo;
    case MON_5:
      GetLocaleInfo(loc, LOCALE_SMONTHNAME5, __langinfo, 251);
      return __langinfo;
    case MON_6:
      GetLocaleInfo(loc, LOCALE_SMONTHNAME6, __langinfo, 251);
      return __langinfo;
    case MON_7:
      GetLocaleInfo(loc, LOCALE_SMONTHNAME7, __langinfo, 251);
      return __langinfo;
    case MON_8:
      GetLocaleInfo(loc, LOCALE_SMONTHNAME8, __langinfo, 251);
      return __langinfo;
    case MON_9:
      GetLocaleInfo(loc, LOCALE_SMONTHNAME9, __langinfo, 251);
      return __langinfo;
    case MON_10:
      GetLocaleInfo(loc, LOCALE_SMONTHNAME10, __langinfo, 251);
      return __langinfo;
    case MON_11:
      GetLocaleInfo(loc, LOCALE_SMONTHNAME11, __langinfo, 251);
      return __langinfo;
    case MON_12:
      GetLocaleInfo(loc, LOCALE_SMONTHNAME12, __langinfo, 251);
      return __langinfo;
    case ABMON_1:
      GetLocaleInfo(loc, LOCALE_SABBREVMONTHNAME1, __langinfo, 251);
      return __langinfo;
    case ABMON_2:
      GetLocaleInfo(loc, LOCALE_SABBREVMONTHNAME2, __langinfo, 251);
      return __langinfo;
    case ABMON_3:
      GetLocaleInfo(loc, LOCALE_SABBREVMONTHNAME3, __langinfo, 251);
      return __langinfo;
    case ABMON_4:
      GetLocaleInfo(loc, LOCALE_SABBREVMONTHNAME4, __langinfo, 251);
      return __langinfo;
    case ABMON_5:
      GetLocaleInfo(loc, LOCALE_SABBREVMONTHNAME5, __langinfo, 251);
      return __langinfo;
    case ABMON_6:
      GetLocaleInfo(loc, LOCALE_SABBREVMONTHNAME6, __langinfo, 251);
      return __langinfo;
    case ABMON_7:
      GetLocaleInfo(loc, LOCALE_SABBREVMONTHNAME7, __langinfo, 251);
      return __langinfo;
    case ABMON_8:
      GetLocaleInfo(loc, LOCALE_SABBREVMONTHNAME8, __langinfo, 251);
      return __langinfo;
    case ABMON_9:
      GetLocaleInfo(loc, LOCALE_SABBREVMONTHNAME9, __langinfo, 251);
      return __langinfo;
    case ABMON_10:
      GetLocaleInfo(loc, LOCALE_SABBREVMONTHNAME10, __langinfo, 251);
      return __langinfo;
    case ABMON_11:
      GetLocaleInfo(loc, LOCALE_SABBREVMONTHNAME11, __langinfo, 251);
      return __langinfo;
    case ABMON_12:
      GetLocaleInfo(loc, LOCALE_SABBREVMONTHNAME12, __langinfo, 251);
      return __langinfo;
    case ERA:
      /* Not implemented */
      __langinfo[0] = 0;
      return __langinfo;
    case ALT_DIGITS:
      GetLocaleInfo(loc, LOCALE_SNATIVEDIGITS, __langinfo, 251);
      return __langinfo;
    case RADIXCHAR:
      GetLocaleInfo(loc, LOCALE_SDECIMAL, __langinfo, 251);
      return __langinfo;
    case THOUSEP:
      GetLocaleInfo(loc, LOCALE_STHOUSAND, __langinfo, 251);
      return __langinfo;
    case YESEXPR:
      /* Not localized */
      strcpy(__langinfo, "^[yY]");
      return __langinfo;
    case NOEXPR:
      /* Not localized */
      strcpy(__langinfo, "^[nN]");
      return __langinfo;
    case CRNCYSTR:
      GetLocaleInfo(loc, LOCALE_STHOUSAND, __langinfo, 251);
      if (__langinfo[0] == '0' || __langinfo[0] == '2')
        __langinfo[0] = '-';
      else
        __langinfo[0] = '+';
      GetLocaleInfo(loc, LOCALE_SCURRENCY, __langinfo + 1, 251);
    default:
      __langinfo[0] = 0;
      return __langinfo;
  }
}
#endif

/**
 * Accepts an incoming connection attempt on a socket
 */
int _win_accept(SOCKET s, struct sockaddr *addr, int *addrlen)
{
  int iRet = accept(s, addr, addrlen);

  SetErrnoFromWinsockError(WSAGetLastError());

  return iRet;
}

/**
 * Accept a new connection on a socket
 */
int _win_bind(SOCKET s, const struct sockaddr *name, int namelen)
{
  int iRet = bind(s, name, namelen);

  SetErrnoFromWinsockError(WSAGetLastError());

  return iRet;
}

/**
 * Initiate a connection on a socket
 */
int _win_connect(SOCKET s,const struct sockaddr *name, int namelen)
{
  int iRet, iWSErr;
  BOOL bBlocking;

  /* connect()ing a non-blocking socket always fails under Windows.
     Check whether it is blocking */
  bBlocking = __win_IsHandleMarkedAsBlocking(s);
  if (! bBlocking)
  {
    u_long l;
    l = 0;
    ioctlsocket(s, FIONBIO, &l);
  }

  iRet = connect(s, name, namelen);
  iWSErr = WSAGetLastError();

  if (! bBlocking)
  {
    u_long l;
    l = 1;
    ioctlsocket(s, FIONBIO, &l);
  }

  SetErrnoFromWinsockError(iWSErr);

  return iRet;
}

/**
 * Get the name of the peer socket
 */
int _win_getpeername(SOCKET s, struct sockaddr *name,
                int *namelen)
{
  int iRet = getpeername(s, name, namelen);

  SetErrnoFromWinsockError(WSAGetLastError());

  return iRet;
}

/**
 * Get the socket name
 */
int _win_getsockname(SOCKET s, struct sockaddr *name,
                int *namelen)
{
  int iRet = getsockname(s, name, namelen);

  SetErrnoFromWinsockError(WSAGetLastError());

  return iRet;
}

/**
 * Get the socket options
 */
int _win_getsockopt(SOCKET s, int level, int optname, char *optval, int *optlen)
{
  int iRet = getsockopt(s, level, optname, optval, optlen);

  SetErrnoFromWinsockError(WSAGetLastError());

  return iRet;
}

/**
 * Listen for socket connections and limit the queue of incoming connections
 */
int _win_listen(SOCKET s, int backlog)
{
  int iRet = listen(s, backlog);

  SetErrnoFromWinsockError(WSAGetLastError());

  return iRet;
}

/**
 * Receive a message from a connected socket
 */
int _win_recv(SOCKET s, char *buf, int len, int flags)
{
  int iRet = recv(s, buf, len, flags);

  SetErrnoFromWinsockError(WSAGetLastError());

  return iRet;
}

/**
 * Receive a message from a socket
 */
int _win_recvfrom(SOCKET s, void *buf, int len, int flags,
             struct sockaddr *from, int *fromlen)
{
  int iRet = recvfrom(s, buf, len, flags, from, fromlen);

  SetErrnoFromWinsockError(WSAGetLastError());

  return iRet;
}

/**
 * Send a message on a socket
 */
int _win_send(SOCKET s, const char *buf, int len, int flags)
{
  int iRet = send(s, buf, len, flags);

  SetErrnoFromWinsockError(WSAGetLastError());

  return iRet;
}

/**
 * Send a message on a socket
 */
int _win_sendto(SOCKET s, const char *buf, int len, int flags,
                const struct sockaddr *to, int tolen)
{
  int iRet = sendto(s, buf, len, flags, to, tolen);

  SetErrnoFromWinsockError(WSAGetLastError());

  return iRet;
}

/**
 * Set the socket options
 */
int _win_setsockopt(SOCKET s, int level, int optname, const void *optval,
                    int optlen)
{
  int iRet = setsockopt(s, level, optname, (const char *) optval, optlen);

  SetErrnoFromWinsockError(WSAGetLastError());

  return iRet;
}

/**
 * Shut down socket send and receive operations
 */
int _win_shutdown(SOCKET s, int how)
{
  int iRet = shutdown(s, how);

  SetErrnoFromWinsockError(WSAGetLastError());

  return iRet;
}

/**
 * Create an endpoint for communication
 */
SOCKET _win_socket(int af, int type, int protocol)
{
  int iRet;

  errno = 0;

  iRet = socket(af, type, protocol);
  if (iRet == SOCKET_ERROR)
  {
    SetErrnoFromWinsockError(WSAGetLastError());

    return -1;
  }
  else
  {
    /* Sockets are not blocking by default under Windows 9x */
    u_long l;
    l = 0;
    ioctlsocket(iRet, FIONBIO, &l);

    return iRet;
  }
}

/**
 * Retrieve the host information corresponding to a network address
 */
struct hostent *_win_gethostbyaddr(const char *addr, int len, int type)
{
  struct hostent *pHost = gethostbyaddr(addr, len, type);

  SetHErrnoFromWinError(WSAGetLastError());
  SetErrnoFromWinsockError(WSAGetLastError());

  return pHost;
}

/**
 * Retrieves host information corresponding to a host name from a host database
 */
struct hostent *_win_gethostbyname(const char *name)
{
  struct hostent *pHost = gethostbyname(name);

  SetHErrnoFromWinError(WSAGetLastError());
  SetErrnoFromWinsockError(WSAGetLastError());

  return pHost;
}

/**
 * Get a system error message
 */
char *_win_strerror(int errnum)
{
  char *error;

  switch (errnum)
    {
#ifdef EPERM
    case EPERM:
      error = "Not super-user";
      break;
#endif
#ifdef ENOENT
    case ENOENT:
      error = "No such file or directory";
      break;
#endif
#ifdef ESRCH
    case ESRCH:
      error = "No such process";
      break;
#endif
#ifdef EINTR
    case EINTR:
      error = "Interrupted system call";
      break;
#endif
#ifdef EIO
    case EIO:
      error = "I/O error";
      break;
#endif
#ifdef ENXIO
    case ENXIO:
      error = "No such device or address";
      break;
#endif
#ifdef E2BIG
    case E2BIG:
      error = "Arg list too long";
      break;
#endif
#ifdef ENOEXEC
    case ENOEXEC:
      error = "Exec format error";
      break;
#endif
#ifdef EBADF
    case EBADF:
      error = "Bad file number";
      break;
#endif
#ifdef ECHILD
    case ECHILD:
      error = "No children";
      break;
#endif
#ifdef EAGAIN
    case EAGAIN:
      error = "Resource unavailable or operation would block, try again";
      break;
#endif
#ifdef ENOMEM
    case ENOMEM:
      error = "Not enough memory";
      break;
#endif
#ifdef EACCES
    case EACCES:
      error = "Permission denied";
      break;
#endif
#ifdef EFAULT
    case EFAULT:
      error = "Bad address";
      break;
#endif
#ifdef ENOTBLK
    case ENOTBLK:
      error = "Block device required";
      break;
#endif
#ifdef EBUSY
    case EBUSY:
      error = "Mount device busy";
      break;
#endif
#ifdef EEXIST
    case EEXIST:
      error = "File exists";
      break;
#endif
#ifdef EXDEV
    case EXDEV:
      error = "Cross-device link";
      break;
#endif
#ifdef ENODEV
    case ENODEV:
      error = "No such device";
      break;
#endif
#ifdef ENOTDIR
    case ENOTDIR:
      error = "Not a directory";
      break;
#endif
#ifdef EISDIR
    case EISDIR:
      error = "Is a directory";
      break;
#endif
#ifdef EINVAL
    case EINVAL:
      error = "Invalid argument";
      break;
#endif
#ifdef ENFILE
    case ENFILE:
      error = "Too many open files in system";
      break;
#endif
#ifdef EMFILE
    case EMFILE:
      error = "Too many open files";
      break;
#endif
#ifdef ENOTTY
    case ENOTTY:
      error = "Not a typewriter";
      break;
#endif
#ifdef ETXTBSY
    case ETXTBSY:
      error = "Text file busy";
      break;
#endif
#ifdef EFBIG
    case EFBIG:
      error = "File too large";
      break;
#endif
#ifdef ENOSPC
    case ENOSPC:
      error = "No space left on device";
      break;
#endif
#ifdef ESPIPE
    case ESPIPE:
      error = "Illegal seek";
      break;
#endif
#ifdef EROFS
    case EROFS:
      error = "Read only file system";
      break;
#endif
#ifdef EMLINK
    case EMLINK:
      error = "Too many links";
      break;
#endif
#ifdef EPIPE
    case EPIPE:
      error = "Broken pipe";
      break;
#endif
#ifdef EDOM
    case EDOM:
      error = "Math arg out of domain of func";
      break;
#endif
#ifdef ERANGE
    case ERANGE:
      error = "Math result not representable";
      break;
#endif
#ifdef ENOMSG
    case ENOMSG:
      error = "No message of desired type";
      break;
#endif
#ifdef EIDRM
    case EIDRM:
      error = "Identifier removed";
      break;
#endif
#ifdef ECHRNG
    case ECHRNG:
      error = "Channel number out of range";
      break;
#endif
#ifdef EL2NSYNC
    case EL2NSYNC:
      error = "Level 2 not synchronized";
      break;
#endif
#ifdef L3HLT
    case L3HLT:
      error = "Level 3 halted";
      break;
#endif
#ifdef EL3RST
    case EL3RST:
      error = "Level 3 reset";
      break;
#endif
#ifdef ELNRNG
    case ELNRNG:
      error = "Link number out of range";
      break;
#endif
#ifdef EUNATCH
    case EUNATCH:
      error = "Protocol driver not attached";
      break;
#endif
#ifdef ENOCSI
    case ENOCSI:
      error = "No CSI structure available";
      break;
#endif
#ifdef EL2HLT
    case EL2HLT:
      error = "Level 2 halted";
      break;
#endif
#ifdef EDEADLK
    case EDEADLK:
      error = "Deadlock condition";
      break;
#endif
#ifdef ENOLCK
    case ENOLCK:
      error = "No record locks available";
      break;
#endif
#ifdef EBADE
    case EBADE:
      error = "Invalid exchange";
      break;
#endif
#ifdef EBADR
    case EBADR:
      error = "Invalid request descriptor";
      break;
#endif
#ifdef EXFULL
    case EXFULL:
      error = "Exchange full";
      break;
#endif
#ifdef ENOANO
    case ENOANO:
      error = "No anode";
      break;
#endif
#ifdef EBADRQC
    case EBADRQC:
      error = "Invalid request code";
      break;
#endif
#ifdef EBADSLT
    case EBADSLT:
      error = "Invalid slot";
      break;
#endif
#ifdef EDEADLOCK
    case EDEADLOCK:
      error = "File locking deadlock error";
      break;
#endif
#ifdef EBFONT
    case EBFONT:
      error = "Bad font file fmt";
      break;
#endif
#ifdef ENOSTR
    case ENOSTR:
      error = "Device not a stream";
      break;
#endif
#ifdef ENODATA
    case ENODATA:
      error = "No data (for no delay io)";
      break;
#endif
#ifdef ETIME
    case ETIME:
      error = "Timer expired";
      break;
#endif
#ifdef ENOSR
    case ENOSR:
      error = "Out of streams resources";
      break;
#endif
#ifdef ENONET
    case ENONET:
      error = "Machine is not on the network";
      break;
#endif
#ifdef ENOPKG
    case ENOPKG:
      error = "Package not installed";
      break;
#endif
#ifdef EREMOTE
    case EREMOTE:
      error = "The object is remote";
      break;
#endif
#ifdef ENOLINK
    case ENOLINK:
      error = "The link has been severed";
      break;
#endif
#ifdef EADV
    case EADV:
      error = "Advertise error";
      break;
#endif
#ifdef ESRMNT
    case ESRMNT:
      error = "Srmount error";
      break;
#endif
#ifdef ECOMM
    case ECOMM:
      error = "Communication error on send";
      break;
#endif
#ifdef EPROTO
    case EPROTO:
      error = "Protocol error";
      break;
#endif
#ifdef EMULTIHOP
    case EMULTIHOP:
      error = "Multihop attempted";
      break;
#endif
#ifdef ELBIN
    case ELBIN:
      error = "Inode is remote (not really error)";
      break;
#endif
#ifdef EDOTDOT
    case EDOTDOT:
      error = "Cross mount point (not really error)";
      break;
#endif
#ifdef EBADMSG
    case EBADMSG:
      error = "Trying to read unreadable message";
      break;
#endif
#ifdef ENOTUNIQ
    case ENOTUNIQ:
      error = "Given log. name not unique";
      break;
#endif
#ifdef EBADFD
    case EBADFD:
      error = "f.d. invalid for this operation";
      break;
#endif
#ifdef EREMCHG
    case EREMCHG:
      error = "Remote address changed";
      break;
#endif
#ifdef ELIBACC
    case ELIBACC:
      error = "Can't access a needed shared lib";
      break;
#endif
#ifdef ELIBBAD
    case ELIBBAD:
      error = "Accessing a corrupted shared lib";
      break;
#endif
#ifdef ELIBSCN
    case ELIBSCN:
      error = ".lib section in a.out corrupted";
      break;
#endif
#ifdef ELIBMAX
    case ELIBMAX:
      error = "Attempting to link in too many libs";
      break;
#endif
#ifdef ELIBEXEC
    case ELIBEXEC:
      error = "Attempting to exec a shared library";
      break;
#endif
#ifdef ENOSYS
    case ENOSYS:
      error = "Function not implemented";
      break;
#endif
#ifdef ENMFILE
    case ENMFILE:
      error = "No more files";
      break;
#endif
#ifdef ENOTEMPTY
    case ENOTEMPTY:
      error = "Directory not empty";
      break;
#endif
#ifdef ENAMETOOLONG
    case ENAMETOOLONG:
      error = "File or path name too long";
      break;
#endif
#ifdef ELOOP
    case ELOOP:
      error = "Too many symbolic links";
      break;
#endif
#ifdef EOPNOTSUPP
    case EOPNOTSUPP:
      error = "Operation not supported on transport endpoint";
      break;
#endif
#ifdef EPFNOSUPPORT
    case EPFNOSUPPORT:
      error = "Protocol family not supported";
      break;
#endif
#ifdef ECONNRESET
    case ECONNRESET:
      error = "Connection reset by peer";
      break;
#endif
#ifdef ENOBUFS
    case ENOBUFS:
      error = "No buffer space available";
      break;
#endif
#ifdef EAFNOSUPPORT
    case EAFNOSUPPORT:
      error = "Address family not supported by protocol family";
      break;
#endif
#ifdef EPROTOTYPE
    case EPROTOTYPE:
      error = "Protocol wrong type for socket";
      break;
#endif
#ifdef ENOTSOCK
    case ENOTSOCK:
      error = "Socket operation on non-socket";
      break;
#endif
#ifdef ENOPROTOOPT
    case ENOPROTOOPT:
      error = "Protocol not available";
      break;
#endif
#ifdef ESHUTDOWN
    case ESHUTDOWN:
      error = "Can't send after socket shutdown";
      break;
#endif
#ifdef ECONNREFUSED
    case ECONNREFUSED:
      error = "Connection refused";
      break;
#endif
#ifdef EADDRINUSE
    case EADDRINUSE:
      error = "Address already in use";
      break;
#endif
#ifdef ECONNABORTED
    case ECONNABORTED:
      error = "Connection aborted";
      break;
#endif
#ifdef ENETUNREACH
    case ENETUNREACH:
      error = "Network is unreachable";
      break;
#endif
#ifdef ENETDOWN
    case ENETDOWN:
      error = "Network interface is not configured";
      break;
#endif
#ifdef ETIMEDOUT
    case ETIMEDOUT:
      error = "Connection timed out";
      break;
#endif
#ifdef EHOSTDOWN
    case EHOSTDOWN:
      error = "Host is down";
      break;
#endif
#ifdef EHOSTUNREACH
    case EHOSTUNREACH:
      error = "Host is unreachable";
      break;
#endif
#ifdef EINPROGRESS
    case EINPROGRESS:
      error = "Connection already in progress";
      break;
#endif
#ifdef EALREADY
    case EALREADY:
      error = "Socket already connected";
      break;
#endif
#ifdef EDESTADDRREQ
    case EDESTADDRREQ:
      error = "Destination address required";
      break;
#endif
#ifdef EMSGSIZE
    case EMSGSIZE:
      error = "Message too long";
      break;
#endif
#ifdef EPROTONOSUPPORT
    case EPROTONOSUPPORT:
      error = "Unknown protocol";
      break;
#endif
#ifdef ESOCKTNOSUPPORT
    case ESOCKTNOSUPPORT:
      error = "Socket type not supported";
      break;
#endif
#ifdef EADDRNOTAVAIL
    case EADDRNOTAVAIL:
      error = "Address not available";
      break;
#endif
#ifdef ENETRESET
    case ENETRESET:
      error = "Connection aborted by network";
      break;
#endif
#ifdef EISCONN
    case EISCONN:
      error = "Socket is already connected";
      break;
#endif
#ifdef ENOTCONN
    case ENOTCONN:
      error = "Socket is not connected";
      break;
#endif
#ifdef ETOOMANYREFS
    case ETOOMANYREFS:
      error = "Too many references: cannot splice";
      break;
#endif
#ifdef EPROCLIM
    case EPROCLIM:
      error = "Too many processes";
      break;
#endif
#ifdef EUSERS
    case EUSERS:
      error = "Too many users";
      break;
#endif
#ifdef EDQUOT
    case EDQUOT:
      error = "Disk quota exceeded";
      break;
#endif
#ifdef ESTALE
    case ESTALE:
      error = "Unknown error";
      break;
#endif
#ifdef ENOTSUP
    case ENOTSUP:
      error = "Not supported";
      break;
#endif
#ifdef ENOMEDIUM
    case ENOMEDIUM:
      error = "No medium (in tape drive)";
      break;
#endif
#ifdef ENOSHARE
    case ENOSHARE:
      error = "No such host or network path";
      break;
#endif
#ifdef ECASECLASH
    case ECASECLASH:
      error = "Filename exists with different case";
      break;
#endif
    case 0:
      error = "No error";
      break;
    default:
      error = "Unknown error";
      LOG(LOG_ERROR, " Unknown error %i in _win_strerror()\n",
          errnum);
      break;
    }

  return error;
}

int IsWinNT()
{
  return theWinVersion.dwPlatformId == VER_PLATFORM_WIN32_NT;
}

#endif /* MINGW */

#if !HAVE_ATOLL
long long atoll(const char *nptr)
{
  return atol(nptr);
}
#endif
