/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file src/util/os/installpath.c
 * @brief get paths used by the program
 * @author Milan
 */

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "platform.h"
#include "gnunet_util_string.h"
#include "gnunet_util_config.h"
#include "gnunet_util_disk.h"
#include "gnunet_util_os.h"

#if LINUX
/**
 * Try to determine path by reading /proc/PID/exe
 */
static char *
get_path_from_proc_exe() {
  char fn[64];
  char * lnk;
  size_t size;

  SNPRINTF(fn,
	   64,
	   "/proc/%u/exe",
	   getpid());
  lnk = MALLOC(1024);
  size = readlink(fn, lnk, 1023);
  if ( (size == 0) || (size >= 1024) ) {
    GE_LOG_STRERROR_FILE(NULL,
			 GE_ERROR | GE_USER | GE_ADMIN | GE_IMMEDIATE,
			 "readlink",
			 fn);
    FREE(lnk);
    return NULL;
  }
  lnk[size] = '\0';
  while ( (lnk[size] != '/') &&
	  (size > 0) )
    size--;
  if ( (size < 4) ||
       (lnk[size-4] != '/') ) {
    /* not installed in "/bin/" -- binary path probably useless */
    FREE(lnk);
    return NULL;
  }
  lnk[size] = '\0';
  return lnk;
}
#endif

#if WINDOWS
/**
 * Try to determine path with win32-specific function
 */
static char * get_path_from_module_filename() {
  char * path;
  char * idx;

  path = MALLOC(4097);
  GetModuleFileName(NULL, path, 4096);
  idx = path + strlen(path);
  while ( (idx > path) &&
	  (*idx != '\\') &&
	  (*idx != '/') )
    idx--;
  *idx = '\0';
  return path;
}
#endif

static char *
get_path_from_PATH() {
  char * path;
  char * pos;
  char * end;
  char * buf;
  const char * p;
  size_t size;

  p = getenv("PATH");
  if (p == NULL)
    return NULL;
  path = STRDUP(p); /* because we write on it */
  buf = MALLOC(strlen(path) + 20);
  size = strlen(path);
  pos = path;

  while (NULL != (end = strchr(pos, ':'))) {
    *end = '\0';
    sprintf(buf, "%s/%s", pos, "gnunetd");
    if (disk_file_test(NULL, buf) == YES) {
      pos = STRDUP(pos);
      FREE(buf);
      FREE(path);
      return pos;
    }
    pos = end + 1;
  }
  sprintf(buf, "%s/%s", pos, "gnunetd");
  if (disk_file_test(NULL, buf) == YES) {
    pos = STRDUP(pos);
    FREE(buf);
    FREE(path);
    return pos;
  }
  FREE(buf);
  FREE(path);
  return NULL;
}

static char *
get_path_from_GNUNET_PREFIX() {
  const char * p;

  p = getenv("GNUNET_PREFIX");
  if (p != NULL)
    return STRDUP(p);
  return NULL;
}

/*
 * @brief get the path to the executable, including the binary itself
 * @author Milan
 *
 * @return a pointer to the executable path, or NULL on error
 */
static char *
os_get_exec_path() {
  char * ret;

  ret = get_path_from_GNUNET_PREFIX();
  if (ret != NULL)
    return ret;
#if LINUX
  ret = get_path_from_proc_exe();
  if (ret != NULL)
    return ret;
#endif
#if WINDOWS
  ret = get_path_from_module_filename();
  if (ret != NULL)
    return ret;
#endif
  ret = get_path_from_PATH();
  if (ret != NULL)
    return ret;
  /* other attempts here */
  return NULL;
}



/*
 * @brief get the path to a specific app dir
 * @author Milan
 * @return a pointer to the dir path (to be freed by the caller)
 */
char * os_get_installation_path(enum InstallPathKind dirkind) {
  size_t n;
  const char * dirname;
  char * execpath;
  char * tmp;

  execpath = os_get_exec_path();
  if (execpath == NULL)
    return NULL;

  n = strlen(execpath);
  if (n == 0) {
    /* should never happen, but better safe than sorry */
    FREE(execpath);
    return NULL;
  }
  if (execpath[n-1] == DIR_SEPARATOR)
    execpath[--n] = '\0';

  if ( (n > 3) &&
       (0 == strcasecmp(&execpath[n-3], "bin")) ) {
    /* good, strip of '/bin'! */
    execpath[n-3] = '\0';
    n -= 3;
  }
  switch(dirkind) {
  case IPK_PREFIX:
    dirname = "";
    break;
  case IPK_BINDIR:
    dirname = DIR_SEPARATOR_STR "bin" DIR_SEPARATOR_STR;
    break;
  case IPK_LIBDIR:
    dirname = DIR_SEPARATOR_STR "lib" DIR_SEPARATOR_STR "GNUnet" DIR_SEPARATOR_STR;
    break;
  case IPK_DATADIR:
    dirname = DIR_SEPARATOR_STR "share" DIR_SEPARATOR_STR "GNUnet" DIR_SEPARATOR_STR;
    break;
  case IPK_LOCALEDIR:
    dirname = DIR_SEPARATOR_STR "share" DIR_SEPARATOR_STR "locale" DIR_SEPARATOR_STR ;
    break;
  default:
    FREE(execpath);
    return NULL;
  }
  tmp = MALLOC(strlen(execpath)+strlen(dirname)+1);
  sprintf(tmp,
	  "%s%s",
	  execpath,
	  dirname);
  FREE(execpath);
  return tmp;
}

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif
/* end of installpath.c */
