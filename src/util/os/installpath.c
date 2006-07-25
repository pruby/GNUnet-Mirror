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
#include "gnunet_util_os.h"

/* assumed math size for a path
 * used to try allocating less memory than PATH_MAX */
#define PATH_TRY 96


/*
 * @brief get the path to the executable, including the binary itself
 * @author Milan
 * @param ectx the context to report the errors to
 * @param cfg the context to get configuration values from
 * @return a pointer to the executable path, owned by the function (don't free it)
 */
static char *os_get_exec_path(struct GE_Context * ectx,
                              struct GC_Configuration * cfg) {
#ifdef WINDOWS
/* FIXME: get the path
 * set found and execpath so the end of the function is valid */

#else /* Should work on all Unices, else we won't run */
  static char *execpath = NULL; /* save it between calls */

  /* FIXME: we assume PATH_MAX is the same for all used files */
  const long path_max = pathconf(".", _PC_PATH_MAX);
  const long name_max = pathconf(".", _PC_NAME_MAX);

  char *tmp, *path1, *path2, *path3;
  size_t size, size1, size2;
  struct stat dummy_stat;
  int found;

  if(execpath) /* already got the path, don't work more */
     return execpath;

  /* I. get the path from /proc */
  tmp = MALLOC(name_max+10);
  SNPRINTF(tmp, 
	   name_max+10,
	   "/proc/%u/exe",
	   getpid());
  path1 = MALLOC(PATH_TRY); /* let's try with a little buffer */
  size = readlink(tmp, path1, PATH_TRY-1);
  if(size == PATH_TRY) { /* buffer too small */
    path1 = REALLOC(path1, path_max);
    size = readlink(tmp, path1, path_max-1); }
  FREE(tmp);
  if (size > 0) { /* this method worked well */
    path1[size] = '\0';

    execpath = STRDUP(path1);
    FREE(path1);
    return execpath; }

  FREE(path1);


  /* II. reading /proc failed, trying with argv[0] */
  found = 0;
  GC_get_configuration_value_string(cfg, "ARGV", "0", "gnunetd", &path1);

  /* 1. absolute path */
  if(*path1 == '/') {
    execpath = path1;
    found = 1; }

  /* 2. relative path */
  else if(strchr(path1, '/')) {
    tmp = MALLOC(PATH_TRY); /* let's try with a little buffer */
    if( !getcwd(tmp, PATH_TRY-1) ) { /* buffer too small */
      tmp = REALLOC(tmp, path_max);
      getcwd(tmp, path_max-1); }
    
    if( (*path1 == '.') && (*(path1+1) == '.') ) { /* ../ so go one level higher */
      strchr(tmp, '/')[0] = '\0';
      path2 = path1+3; 
    } /* and jump */
    else if (*path1 == '.') /* ./ so just jump */
      path2 = path1+2;
    else
      path2 = path1;
 
    if(tmp[strlen(tmp)-1] == '/') /* just to clean final '/' */
      tmp[strlen(tmp)-1] = '\0';

    execpath = MALLOC(strlen(tmp)+strlen(path1)+2);
    sprintf(execpath, "%s/%s", tmp, path1);
    FREE(tmp);
    FREE(path1);
    found = 1; }

  /* 3. program in PATH */
  else {
    path3 = MALLOC(PATH_TRY);
    tmp = STRDUP(getenv("PATH")); /* because we write on it */
    size = strlen(path1);
    size1 = PATH_TRY;

    while(strchr(tmp, ':')) {
      path2 = (strrchr(tmp, ':')+1);
      size2 = strlen(path2)+size+2;
      if(size2 > size1) {
        path3 = REALLOC(path3, size2); /* not nice, but best to do: */
        size1 = size2; }               /* malloc PATH_MAX bytes is too much */

      sprintf(path3, "%s/%s", path2, path1);
      if(stat(path3, &dummy_stat) == 0) {
        found = 1;
        break; }
       *(path2-1) = '\0';
    }

    if(!found) { /* first dir in PATH */
      path2 = tmp;
      sprintf(path3, "%s/%s", path2, path1);
      if(STAT(path3, &dummy_stat) == 0)
        found = 1; }

    execpath = STRDUP(path3);

    FREE(path1);
    FREE(path3);
    FREE(tmp); }

#endif
  if(found) {
      return execpath; }
  else { /* we can do nothing to run normally */
    GE_LOG(ectx, /* This error should not occur on standard Unices */
	   GE_ERROR | GE_USER | GE_ADMIN | GE_DEVELOPER | GE_IMMEDIATE,
	   _("Cannot determine the path to the executable, your system may be broken or not supported.\n"));
     return NULL; }
}

/*
 * @brief get the path to a specific app dir
 * @author Milan
 * @param ectx the context to report the errors to
 * @param cfg the context to get configuration values from
 * @return a pointer to the dir path (to be freed by the caller)
 */
char * os_get_installation_path(struct GE_Context * ectx,
                                struct GC_Configuration * cfg,
                                enum InstallPathKind dirkind) {

  static char *prefix = NULL; /*save it between calls */

  unsigned int n;
  char *dirname, *final_dir, *appname;
  char *execpath, *tmp, *ptr;

  if(!prefix) { /* if we already got the prefix once, don't work more */
    if( !(execpath = os_get_exec_path(ectx, cfg)) )
      return NULL;
  
    tmp = STRDUP(execpath);
    ptr = strrchr(tmp, DIR_SEPARATOR); /* get prefix from prefix/bin/app */
    *ptr = '\0';
    n = 1;
    while( *(ptr-n) == DIR_SEPARATOR ) { /* manage "//" in the path */
      *(ptr-n) = '\0';
      n++; }
    ptr = strrchr(tmp, DIR_SEPARATOR);

    if( !( (*(ptr+1) == 'b')
	   && (*(ptr+2) == 'i')
	   && (*(ptr+3) == 'n')) )
      GE_LOG(ectx,
             GE_WARNING | GE_ADMIN | GE_IMMEDIATE,
	      _("GNUnet executables are not in a directory named 'bin'. This may signal a broken installation.\n"));

    *(ptr+1) = '\0';
    n = 1;
    while( *(ptr-n) == DIR_SEPARATOR ) { /* same, but keep the final '/' */
      *(ptr-n+1) = '\0';
      n++; }

    if(*tmp == '\0') { /* no prefix at all */
      GE_LOG(ectx,
             GE_ERROR | GE_USER | GE_ADMIN | GE_DEVELOPER | GE_IMMEDIATE,
	      _("Cannot determine the installation prefix. Unknown error.\n"));
     return NULL; }

    prefix = STRDUP(tmp);
    FREE(tmp); }


  /* what do we have to return ? */
  GC_get_configuration_value_string(cfg, "ARGV", "0", "gnunetd", &appname);

  switch(dirkind) {
    case PREFIX:
      dirname = STRDUP("\0");
      break;
    case BINDIR:
      dirname = STRDUP("bin/\0");
      break;
    case LIBDIR:
      dirname = STRDUP("lib/\0");
      break;
    case GNDATADIR:
      dirname = STRDUP("share/\0");
      break;
    case PACKAGEDATADIR:
      tmp = MALLOC(9+strlen(prefix)+strlen(appname));
      sprintf(tmp, "share/%s/%s/", prefix, appname);
      dirname = STRDUP(tmp);
      FREE(tmp);
      break;
    case LOCALEDIR:
      dirname = STRDUP("share/locale/\0");
      break;
    default:
      return NULL; }

  tmp = MALLOC(strlen(prefix)+strlen(dirname)+1);

  final_dir = STRDUP(tmp);

  FREE(tmp);
  FREENONNULL(dirname);
  return final_dir;
}

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif
/* end of installpath.c */
