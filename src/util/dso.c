/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file util/dso.c
 * @brief Methods to access dynamic shared objects (DSOs).
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"

static int using_valgrind;

static char * old_dlsearchpath = NULL;

/* using libtool, needs init! */
void __attribute__ ((constructor)) gnc_ltdl_init(void) {
  int err;

  err = lt_dlinit ();
  if (err > 0)
    {
#if DEBUG
      fprintf(stderr,
	      _("Initialization of plugin mechanism failed: %s!\n"),
	      lt_dlerror());
#endif
      return;
    }
  if (lt_dlgetsearchpath() != NULL)
    old_dlsearchpath = strdup(lt_dlgetsearchpath());
  if (lt_dlgetsearchpath () == NULL)
    lt_dladdsearchdir ("/usr/lib/GNUnet");
  else if (strstr (lt_dlgetsearchpath (), "/usr/lib/GNUnet") == NULL)
    lt_dladdsearchdir ("/usr/lib/GNUnet");
  if (strstr (lt_dlgetsearchpath (), "/usr/local/lib/GNUnet") == NULL)
    lt_dladdsearchdir ("/usr/local/lib/GNUnet");
#ifdef PLUGIN_PATH
  if (strstr (lt_dlgetsearchpath (), PLUGIN_PATH) == NULL)
    lt_dladdsearchdir (PLUGIN_PATH);
#endif
}

void __attribute__ ((destructor)) gnc_ltdl_fini(void) {
  lt_dlsetsearchpath(old_dlsearchpath);
  if (old_dlsearchpath != NULL) {
    free(old_dlsearchpath);
    old_dlsearchpath = NULL;
  }
  if (0 != using_valgrind)
    lt_dlexit ();
}


static char * buildLibName(const char * prefix,
			   const char * dso) {
  char * libname;

  libname = MALLOC(strlen(dso) +
		   strlen(prefix) + 1);
  libname[0] = '\0';
  strcat(libname, prefix);
  strcat(libname, dso);
  return libname;
}

void * loadDynamicLibrary(const char * libprefix,
			  const char * dsoname) {
  void * libhandle;
  char * libname;

  if (0 != lt_dlinit())
    DIE_STRERROR("lt_dlinit");
  /* finally, load the library */
  libname = buildLibName(libprefix,
			 dsoname);
  libhandle = lt_dlopenext(libname);
  if (libhandle == NULL) {
    LOG(LOG_ERROR,
	_("`%s' failed for library `%s' at %s:%d with error: %s\n"),
	"lt_dlopenext",
	libname,
	__FILE__, __LINE__,
	lt_dlerror());
  }
  FREE(libname);
  return libhandle;
}

void unloadDynamicLibrary(void * libhandle) {
  /* when valgrinding, comment out these lines
     to get decent traces for memory leaks on exit */
  if (0 != getConfigurationInt("GNUNETD",
			       "VALGRIND")) {
    lt_dlclose(libhandle);
    if (0 != lt_dlexit())
      LOG_STRERROR(LOG_WARNING, "lt_dlexit");
  } else
    using_valgrind = 1;
}

void * trybindDynamicMethod(void * libhandle,
			    const char * methodprefix,
			    const char * dsoname) {
  char * initName;
  void * mptr;

  initName = MALLOC(strlen(dsoname) +
		    strlen(methodprefix) + 2);
  initName[0] = '\0';
  strcat(initName, "_");
  strcat(initName, methodprefix);
  strcat(initName, dsoname);
  mptr = lt_dlsym(libhandle, &initName[1]);
  if (mptr == NULL) {
    /* try again with "_" prefix; some systems use that
       variant. */
    mptr = lt_dlsym(libhandle, initName);
  }
  FREE(initName);
  return mptr;
}

void * bindDynamicMethod(void * libhandle,
			 const char * methodprefix,
			 const char * dsoname) {
  void * mptr;

  mptr = trybindDynamicMethod(libhandle,
			      methodprefix,
			      dsoname);
  if (mptr == NULL)
    LOG(LOG_ERROR,
	_("`%s' failed to resolve method '%s%s' at %s:%d with error: %s\n"),
	"lt_dlsym",
	methodprefix, dsoname,
	__FILE__, __LINE__,
	lt_dlerror());
  return mptr;
}

/* end of dso.c */			
