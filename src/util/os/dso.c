/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/os/dso.c
 * @brief Methods to access plugins (or dynamic shared objects (DSOs)).
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_os.h"
#include "gnunet_util_string.h"

typedef struct PluginHandle {
  struct GE_Context * ectx;
  char * libprefix;
  char * dsoname;
  void * handle;
} Plugin;


static char * old_dlsearchpath;

/* NILS: this method will need to be
   ported for Win32 and other non-linux
   systems */
#if LINUX
static char * getPluginPath() {
  char * fn;
  char * lnk;
  size_t size;

  fn = MALLOC(64);
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
    FREE(fn);
    FREE(lnk);
    return NULL;
  }
  FREE(fn);
  lnk[size] = '\0';
  while ( (lnk[size] != '/') &&
	  (size > 0) )
    size--;
  if ( (size < 4) ||
       (lnk[size-4] != '/') ) {
    GE_LOG(NULL,
	   GE_ERROR | GE_USER | GE_ADMIN | GE_IMMEDIATE,
	   _("Cannot determine plugin path, application must be installed in directory ending with `%s'.\n"),
	   "bin/");
    FREE(lnk);
    return NULL;
  }
  lnk[  size] = '\0';
  lnk[--size] = 'b';
  lnk[--size] = 'i';
  lnk[--size] = 'l';
  return lnk;
}
#endif

/* using libtool, needs init! */
void __attribute__ ((constructor)) gnc_ltdl_init(void) {
  int err;
  const char * opath;
  char * path;

  err = lt_dlinit();
  if (err > 0) {
    fprintf(stderr,
	    _("Initialization of plugin mechanism failed: %s!\n"),
	    lt_dlerror());
    return;
  }
  opath = lt_dlgetsearchpath();
  if (opath != NULL)
    old_dlsearchpath = STRDUP(opath);
  path = getPluginPath();
  lt_dlsetsearchpath(path);
  FREE(path);
}

void __attribute__ ((destructor)) gnc_ltdl_fini(void) {
  lt_dlsetsearchpath(old_dlsearchpath);
  if (old_dlsearchpath != NULL) {
    FREE(old_dlsearchpath);
    old_dlsearchpath = NULL;
  }
  lt_dlexit ();
}

struct PluginHandle * 
os_plugin_load(struct GE_Context * ectx,
	       const char * libprefix,
	       const char * dsoname) {
  void * libhandle;
  char * libname;
  Plugin * plug;

  libname = MALLOC(strlen(dsoname) +
		   strlen(libprefix) + 1);
  strcpy(libname, libprefix);
  strcat(libname, dsoname);
  libhandle = lt_dlopenext(libname);
  if (libhandle == NULL) {
    GE_LOG(ectx,
	   GE_ERROR | GE_USER | GE_ADMIN | GE_IMMEDIATE,
	   _("`%s' failed for library `%s' with error: %s\n"),
	   "lt_dlopenext",
	   libname,
	   lt_dlerror());
    FREE(libname);
    return NULL;
  }
  FREE(libname);
  plug = MALLOC(sizeof(Plugin));
  plug->handle = libhandle;
  plug->libprefix = STRDUP(libprefix);
  plug->dsoname = STRDUP(dsoname);
  plug->ectx = ectx;
  return plug;
}

void os_plugin_unload(struct PluginHandle * plugin) {
  lt_dlclose(plugin->handle);
  FREE(plugin->libprefix);
  FREE(plugin->dsoname);
  FREE(plugin);
}

void * 
os_plugin_resolve_function(struct PluginHandle * plug,
			   const char * methodprefix,
			   int logError) {
  char * initName;
  void * mptr;

  initName = MALLOC(strlen(plug->dsoname) +
		    strlen(methodprefix) + 2);
  strcpy(initName, "_");
  strcat(initName, methodprefix);
  strcat(initName, plug->dsoname);
  mptr = lt_dlsym(plug->handle, &initName[1]);
  if (mptr == NULL) 
    mptr = lt_dlsym(plug->handle, initName);
  if ( (mptr == NULL) &&
       (logError) )
    GE_LOG(plug->ectx,
	   GE_ERROR | GE_USER | GE_DEVELOPER | GE_IMMEDIATE,
	   _("`%s' failed to resolve method '%s' with error: %s\n"),
	   "lt_dlsym",
	   &initName[1],
	   lt_dlerror());
  FREE(initName);
  return mptr;
}

/* end of dso.c */			
