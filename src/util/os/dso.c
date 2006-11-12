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


/* using libtool, needs init! */
void __attribute__ ((constructor)) gnc_ltdl_init() {
  int err;
  const char * opath;
  char * path;
  char * cpath;

#ifdef MINGW
  InitWinEnv(NULL);
#endif

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
  path = os_get_installation_path(IPK_LIBDIR);
  if (path != NULL) {
    if (opath != NULL) {
      cpath = MALLOC(strlen(path) + strlen(opath) + 4);
      strcpy(cpath, opath);
      strcat(cpath, ":");
      strcat(cpath, path);
      lt_dlsetsearchpath(cpath);
      FREE(path);
      FREE(cpath);
    } else {
      lt_dlsetsearchpath(path);
      FREE(path);
    }
  }
}

void __attribute__ ((destructor)) gnc_ltdl_fini() {
  lt_dlsetsearchpath(old_dlsearchpath);
  if (old_dlsearchpath != NULL) {
    FREE(old_dlsearchpath);
    old_dlsearchpath = NULL;
  }

#ifdef MINGW
  ShutdownWinEnv();
#endif

  // lt_dlexit();
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
  // lt_dlclose(plugin->handle);
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
