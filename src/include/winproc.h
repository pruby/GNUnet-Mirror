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
 * @file util/winproc.h
 * @brief Definitions for MS Windows
 * @author Nils Durner
 **/

#ifndef _WINPROC_H
#define _WINPROC_H

#include <io.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/timeb.h>
#include <dirent.h>
#include <windows.h>
#include <winsock.h>
#include <winerror.h>
#include <iphlpapi.h>
#include <shlobj.h>
#include <objbase.h>
#include <sys/param.h>  /* #define BYTE_ORDER */
#include "gnunet_util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN

/* Conflicts with our definitions */
#define __G_WIN32_H__

/* Convert LARGE_INTEGER to double */
#define Li2Double(x) ((double)((x).HighPart) * 4.294967296E9 + \
  (double)((x).LowPart))

#define socklen_t int
#define ssize_t int
#define ftruncate chsize
#define off_t int

/* Thanks to the Cygwin project */
#define EPERM 1		/* Not super-user */
#define ENOENT 2	/* No such file or directory */
#define ESRCH 3		/* No such process */
#define EINTR 4		/* Interrupted system call */
#define EIO 5		/* I/O error */
#define ENXIO 6		/* No such device or address */
#define E2BIG 7		/* Arg list too long */
#define ENOEXEC 8	/* Exec format error */
#define EBADF 9		/* Bad file number */
#define ECHILD 10	/* No children */
#define EAGAIN 11	/* Resource unavailable or operation would block, try again */
#define ENOMEM 12	/* Not enough memory */
#define EACCES 13	/* Permission denied */
#define EFAULT 14	/* Bad address */
#define ENOTBLK 15	/* Block device required */
#define EBUSY 16	/* Mount device busy */
#define EEXIST 17	/* File exists */
#define EXDEV 18	/* Cross-device link */
#define ENODEV 19	/* No such device */
#define ENOTDIR 20	/* Not a directory */
#define EISDIR 21	/* Is a directory */
#define EINVAL 22	/* Invalid argument */
#define ENFILE 23	/* Too many open files in system */
#define EMFILE 24	/* Too many open files */
#define ENOTTY 25	/* Not a typewriter */
#define ETXTBSY 26	/* Text file busy */
#define EFBIG 27	/* File too large */
#define ENOSPC 28	/* No space left on device */
#define ESPIPE 29	/* Illegal seek */
#define EROFS 30	/* Read only file system */
#define EMLINK 31	/* Too many links */
#define EPIPE 32	/* Broken pipe */
#define EDOM 33		/* Math arg out of domain of func */
#define ERANGE 34	/* Math result not representable */
#define ENOMSG 35	/* No message of desired type */
#define EIDRM 36	/* Identifier removed */
#define ECHRNG 37	/* Channel number out of range */
#define EL2NSYNC 38	/* Level 2 not synchronized */
#define L3HLT 39	/* Level 3 halted */
#define EL3RST 40	/* Level 3 reset */
#define ELNRNG 41	/* Link number out of range */
#define EUNATCH 42	/* Protocol driver not attached */
#define ENOCSI 43	/* No CSI structure available */
#define EL2HLT 44	/* Level 2 halted */
#undef  EDEADLK
#define EDEADLK 45	/* Deadlock condition */
#undef  ENOLCK
#define ENOLCK 46	/* No record locks available */
#define EBADE 50	/* Invalid exchange */
#define EBADR 51	/* Invalid request descriptor */
#define EXFULL 52	/* Exchange full */
#define ENOANO 53	/* No anode */
#define EBADRQC 54	/* Invalid request code */
#define EBADSLT 55	/* Invalid slot */
#undef  EDEADLOCK
#define EDEADLOCK 56	/* File locking deadlock error */
#define EBFONT 57	/* Bad font file fmt */
#define ENOSTR 60	/* Device not a stream */
#define ENODATA 61	/* No data (for no delay io) */
#define ETIME 62	/* Timer expired */
#define ENOSR 63	/* Out of streams resources */
#define ENONET 64	/* Machine is not on the network */
#define ENOPKG 65	/* Package not installed */
#define EREMOTE 66	/* The object is remote */
#define ENOLINK 67	/* The link has been severed */
#define EADV 68		/* Advertise error */
#define ESRMNT 69	/* Srmount error */
#define ECOMM 70	/* Communication error on send */
#define EPROTO 71	/* Protocol error */
#define EMULTIHOP 74	/* Multihop attempted */
#define ELBIN 75	/* Inode is remote (not really error) */
#define EDOTDOT 76	/* Cross mount point (not really error) */
#define EBADMSG 77	/* Trying to read unreadable message */
#define ENOTUNIQ 80	/* Given log. name not unique */
#define EBADFD 81	/* f.d. invalid for this operation */
#define EREMCHG 82	/* Remote address changed */
#define ELIBACC 83	/* Can't access a needed shared lib */
#define ELIBBAD 84	/* Accessing a corrupted shared lib */
#define ELIBSCN 85	/* .lib section in a.out corrupted */
#define ELIBMAX 86	/* Attempting to link in too many libs */
#define ELIBEXEC 87	/* Attempting to exec a shared library */
#undef  ENOSYS
#define ENOSYS 88	/* Function not implemented */
#define ENMFILE 89      /* No more files */
#undef  ENOTEMPTY
#define ENOTEMPTY 90	/* Directory not empty */
#undef  ENAMETOOLONG
#define ENAMETOOLONG 91	/* File or path name too long */
#define ELOOP 92	/* Too many symbolic links */
#define EOPNOTSUPP 95	/* Operation not supported on transport endpoint */
#define EPFNOSUPPORT 96 /* Protocol family not supported */
#define ECONNRESET 104  /* Connection reset by peer */
#define ENOBUFS 105	/* No buffer space available */
#define EAFNOSUPPORT 106 /* Address family not supported by protocol family */
#define EPROTOTYPE 107	/* Protocol wrong type for socket */
#define ENOTSOCK 108	/* Socket operation on non-socket */
#define ENOPROTOOPT 109	/* Protocol not available */
#define ESHUTDOWN 110	/* Can't send after socket shutdown */
#define ECONNREFUSED 111	/* Connection refused */
#define EADDRINUSE 112		/* Address already in use */
#define ECONNABORTED 113	/* Connection aborted */
#define ENETUNREACH 114		/* Network is unreachable */
#define ENETDOWN 115		/* Network interface is not configured */
#undef  ETIMEDOUT
#define ETIMEDOUT 116		/* Connection timed out */
#define EHOSTDOWN 117		/* Host is down */
#define EHOSTUNREACH 118	/* Host is unreachable */
#define EINPROGRESS 119		/* Connection already in progress */
#define EALREADY 120		/* Socket already connected */
#define EDESTADDRREQ 121	/* Destination address required */
#define EMSGSIZE 122		/* Message too long */
#define EPROTONOSUPPORT 123	/* Unknown protocol */
#define ESOCKTNOSUPPORT 124	/* Socket type not supported */
#define EADDRNOTAVAIL 125	/* Address not available */
#define ENETRESET 126		/* Connection aborted by network */
#define EISCONN 127		    /* Socket is already connected */
#define ENOTCONN 128		/* Socket is not connected */
#define ETOOMANYREFS 129	/* Too many references: cannot splice */
#define EPROCLIM 130		/* Too many processes */
#define EUSERS 131			/* Too many users */
#define EDQUOT 132			/* Disk quota exceeded */
#define ESTALE 133          /* Unknown error */
#undef  ENOTSUP
#define ENOTSUP 134		    /* Not supported */
#define ENOMEDIUM 135       /* No medium (in tape drive) */
#define ENOSHARE 136        /* No such host or network path */
#define ECASECLASH 137      /* Filename exists with different case */
#define EWOULDBLOCK EAGAIN	/* Operation would block */

#undef HOST_NOT_FOUND
#define HOST_NOT_FOUND 1
#undef TRY_AGAIN
#define TRY_AGAIN 2
#undef NO_RECOVERY
#define NO_RECOVERY 3
#undef NO_ADDRESS
#define NO_ADDRESS 4
 
struct statfs
{
  long f_type;                  /* type of filesystem (see below) */
  long f_bsize;                 /* optimal transfer block size */
  long f_blocks;                /* total data blocks in file system */
  long f_bfree;                 /* free blocks in fs */
  long f_bavail;                /* free blocks avail to non-superuser */
  long f_files;                 /* total file nodes in file system */
  long f_ffree;                 /* free file nodes in fs */
  long f_fsid;                  /* file system id */
  long f_namelen;               /* maximum length of filenames */
  long f_spare[6];              /* spare for later */
};

/* Taken from the Wine project <http://www.winehq.org>
    /wine/include/winternl.h */
enum SYSTEM_INFORMATION_CLASS
{
  SystemBasicInformation = 0,
  Unknown1,
  SystemPerformanceInformation = 2,
  SystemTimeOfDayInformation = 3, /* was SystemTimeInformation */
  Unknown4,
  SystemProcessInformation = 5,
  Unknown6,
  Unknown7,
  SystemProcessorPerformanceInformation = 8,
  Unknown9,
  Unknown10,
  SystemDriverInformation,
  Unknown12,
  Unknown13,
  Unknown14,
  Unknown15,
  SystemHandleList,
  Unknown17,
  Unknown18,
  Unknown19,
  Unknown20,
  SystemCacheInformation,
  Unknown22,
  SystemInterruptInformation = 23,
  SystemExceptionInformation = 33,
  SystemRegistryQuotaInformation = 37,
  SystemLookasideInformation = 45
};

typedef struct
{
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER Reserved1[2];
    ULONG Reserved2;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

#define sleep(secs) (Sleep(secs * 1000))

/*********************** statfs *****************************/
/* fake block size */
#define FAKED_BLOCK_SIZE 512

/* linux-compatible values for fs type */
#define MSDOS_SUPER_MAGIC     0x4d44
#define NTFS_SUPER_MAGIC      0x5346544E

/*********************** End of statfs ***********************/

typedef struct
{
  SOCKET s;
  BOOL bBlocking;
} Winsock;
extern Winsock *pSocks;
extern unsigned int uiSockCount;
extern HANDLE hSocksLock;

typedef struct
{
  int fildes;
  void *buf;
  size_t nbyte;
} TReadWriteInfo;

#define SHUT_RDWR SD_BOTH

/* Operations for flock() */
#define LOCK_SH  1       /* shared lock */
#define LOCK_EX  2       /* exclusive lock */
#define LOCK_NB  4       /* or'd with one of the above to prevent
                            blocking */
#define LOCK_UN  8       /* remove lock */

/* Not supported under MinGW */
#define S_IRGRP 0
#define S_IWGRP 0
#define S_IROTH 0
#define S_IXGRP 0
#define S_IWOTH 0
#define S_IXOTH 0
#define S_ISUID 0
#define S_ISGID 0
#define S_ISVTX 0
#define S_IRWXG 0
#define S_IRWXO 0

#define conv_to_win_path(u, w) conv_to_win_path_ex(u, w, 1)

typedef DWORD WINAPI (*TNtQuerySystemInformation) (int, PVOID, ULONG, PULONG);
typedef DWORD WINAPI (*TGetIfEntry) (PMIB_IFROW pIfRow);
typedef DWORD WINAPI (*TGetIpAddrTable) (PMIB_IPADDRTABLE pIpAddrTable,
                      PULONG pdwSize, BOOL bOrder);
typedef DWORD WINAPI (*TGetIfTable) (PMIB_IFTABLE pIfTable, PULONG pdwSize,
                      BOOL bOrder);
typedef DWORD WINAPI (*TCreateHardLink) (LPCTSTR lpFileName,
                      LPCTSTR lpExistingFileName, LPSECURITY_ATTRIBUTES
                      lpSecurityAttributes);
typedef SC_HANDLE WINAPI (*TOpenSCManager) (LPCTSTR lpMachineName,
                          LPCTSTR lpDatabaseName, DWORD dwDesiredAccess);
typedef SC_HANDLE WINAPI (*TCreateService) (SC_HANDLE hSCManager,
                           LPCTSTR lpServiceName, LPCTSTR lpDisplayName,
                           DWORD dwDesiredAccess, DWORD dwServiceType,
                           DWORD dwStartType, DWORD dwErrorControl,
                           LPCTSTR lpBinaryPathName, LPCTSTR lpLoadOrderGroup,
                           LPDWORD lpdwTagId, LPCTSTR lpDependencies,
                           LPCTSTR lpServiceStartName, LPCTSTR lpPassword);
typedef BOOL WINAPI (*TCloseServiceHandle) (SC_HANDLE hSCObject);
typedef BOOL WINAPI (*TDeleteService) (SC_HANDLE hService);
typedef SERVICE_STATUS_HANDLE WINAPI (*TRegisterServiceCtrlHandler) (
                                      LPCTSTR lpServiceName,
                                      LPHANDLER_FUNCTION lpHandlerProc);
typedef BOOL WINAPI (*TSetServiceStatus) (SERVICE_STATUS_HANDLE hServiceStatus,
                      LPSERVICE_STATUS lpServiceStatus);
typedef BOOL WINAPI (*TStartServiceCtrlDispatcher) (const LPSERVICE_TABLE_ENTRY
                     lpServiceTable);
typedef BOOL WINAPI (*TControlService) (SC_HANDLE hService, DWORD dwControl,
                     LPSERVICE_STATUS lpServiceStatus);
typedef SC_HANDLE WINAPI (*TOpenService) (SC_HANDLE hSCManager, LPCTSTR lpServiceName,
                          DWORD dwDesiredAccess);
typedef DWORD WINAPI (*TGetBestInterface) (IPAddr dwDestAddr, PDWORD pdwBestIfIndex);

#define SetErrnoFromWinError(e) _SetErrnoFromWinError(e, __FILE__, __LINE__)

extern TNtQuerySystemInformation GNNtQuerySystemInformation;
extern TGetIfEntry GNGetIfEntry;
extern TGetIpAddrTable GNGetIpAddrTable;
extern TGetIfTable GNGetIfTable;
extern TCreateHardLink GNCreateHardLink;
extern TOpenSCManager GNOpenSCManager;
extern TCreateService GNCreateService;
extern TCloseServiceHandle GNCloseServiceHandle;
extern TDeleteService GNDeleteService;
extern TRegisterServiceCtrlHandler GNRegisterServiceCtrlHandler;
extern TSetServiceStatus GNSetServiceStatus;
extern TStartServiceCtrlDispatcher GNStartServiceCtrlDispatcher;
extern TControlService GNControlService;
extern TOpenService GNOpenService;
extern TGetBestInterface GNGetBestInterface;

BOOL CreateShortcut(const char *pszSrc, const char *pszDest);
BOOL DereferenceShortcut(char *pszShortcut);

BOOL __win_IsHandleMarkedAsBlocking(SOCKET hHandle);
void __win_SetHandleBlockingMode(SOCKET s, BOOL bBlocking);
void __win_DiscardHandleBlockingMode(SOCKET s);

int flock(int fd, int operation);
int fsync(int fildes);
int inet_pton(int af, const char *src, void *dst);
int inet_pton4(const char *src, u_char *dst, int pton);
#if USE_IPV6
int inet_pton6(const char *src, u_char *dst);
#endif
int truncate(const char *fname, int distance);
int statfs(const char *path, struct statfs *buf);
const char *hstrerror(int err);
void gettimeofday(struct timeval *tp, void *tzp);
int mkstemp(char *tmplate);
char *strptime (const char *buf, const char *format, struct tm *tm);
void InitWinEnv();
void ShutdownWinEnv();
int conv_to_win_path_ex(const char *pszUnix, char *pszWindows, int derefLinks);
void _SetErrnoFromWinError(long lWinError, char *pszCaller, int iLine);
void SetErrnoFromWinsockError(long lWinError);
void SetHErrnoFromWinError(long lWinError);
FILE *_win_fopen(const char *filename, const char *mode);
DIR *_win_opendir(const char *dirname);
int _win_chdir(const char *path);
int _win_fstat(int handle, struct stat *buffer);
int _win_pipe(int *phandles);
int _win_rmdir(const char *path);
int _win_access( const char *path, int mode );
int _win_chmod(const char *filename, int pmode);
char *realpath(const char *file_name, char *resolved_name);
int _win_remove(const char *path);
int _win_rename(const char *oldname, const char *newname);
int _win_stat(const char *path, struct stat *buffer);
int _win_unlink(const char *filename);
int _win_write(int fildes, const void *buf, size_t nbyte);
int _win_read(int fildes, void *buf, size_t nbyte);
size_t _win_fwrite(const void *buffer, size_t size, size_t count, FILE *stream);
size_t _win_fread( void *buffer, size_t size, size_t count, FILE *stream );
int _win_symlink(const char *path1, const char *path2);
int _win_accept(SOCKET s, struct sockaddr *addr, int *addrlen);
int _win_bind(SOCKET s, const struct sockaddr *name, int namelen);
int _win_connect(SOCKET s,const struct sockaddr *name, int namelen);
int _win_getpeername(SOCKET s, struct sockaddr *name,
                int *namelen);
int _win_getsockname(SOCKET s, struct sockaddr *name, 
                int *namelen);
int _win_getsockopt(SOCKET s, int level, int optname, char *optval,
				int *optlen);
int _win_listen(SOCKET s, int backlog);
int _win_recv(SOCKET s, char *buf, int len, int flags);
int _win_recvfrom(SOCKET s, void *buf, int len, int flags,
             struct sockaddr *from, int *fromlen);
int _win_select(int max_fd, fd_set * rfds, fd_set * wfds, fd_set * efds,
                const struct timeval *tv);
int _win_send(SOCKET s, const char *buf, int len, int flags);
int _win_sendto(SOCKET s, const char *buf, int len, int flags,
                const struct sockaddr *to, int tolen);
int _win_setsockopt(SOCKET s, int level, int optname, const void *optval,
                    int optlen);
int _win_shutdown(SOCKET s, int how);
SOCKET _win_socket(int af, int type, int protocol);
struct hostent *_win_gethostbyaddr(const char *addr, int len, int type);
struct hostent *_win_gethostbyname(const char *name);
char *_win_strerror(int errnum);
int IsWinNT();

#ifdef __cplusplus
}
#endif

#endif
