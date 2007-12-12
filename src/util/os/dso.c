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

typedef struct GNUNET_PluginHandle
{
  struct GNUNET_GE_Context *ectx;
  char *libprefix;
  char *dsoname;
  void *handle;
} Plugin;


static char *old_dlsearchpath;


/* using libtool, needs init! */
void __attribute__ ((constructor)) GNUNET_dso_ltdl_init ()
{
  int err;
  const char *opath;
  char *path;
  char *cpath;

#ifdef MINGW
  InitWinEnv (NULL);
#endif

  err = lt_dlinit ();
  if (err > 0)
    {
      fprintf (stderr,
               _("Initialization of plugin mechanism failed: %s!\n"),
               lt_dlerror ());
      return;
    }
  opath = lt_dlgetsearchpath ();
  if (opath != NULL)
    old_dlsearchpath = GNUNET_strdup (opath);
  path = GNUNET_get_installation_path (GNUNET_IPK_LIBDIR);
  if (path != NULL)
    {
      if (opath != NULL)
        {
          cpath = GNUNET_malloc (strlen (path) + strlen (opath) + 4);
          strcpy (cpath, opath);
          strcat (cpath, ":");
          strcat (cpath, path);
          lt_dlsetsearchpath (cpath);
          GNUNET_free (path);
          GNUNET_free (cpath);
        }
      else
        {
          lt_dlsetsearchpath (path);
          GNUNET_free (path);
        }
    }
}

void __attribute__ ((destructor)) GNUNET_dso_ltdl_fini ()
{
  lt_dlsetsearchpath (old_dlsearchpath);
  if (old_dlsearchpath != NULL)
    {
      GNUNET_free (old_dlsearchpath);
      old_dlsearchpath = NULL;
    }

#ifdef MINGW
  ShutdownWinEnv ();
#endif

  // lt_dlexit();
}

struct GNUNET_PluginHandle *
GNUNET_plugin_load (struct GNUNET_GE_Context *ectx,
                    const char *libprefix, const char *dsoname)
{
  void *libhandle;
  char *libname;
  Plugin *plug;

  libname = GNUNET_malloc (strlen (dsoname) + strlen (libprefix) + 1);
  strcpy (libname, libprefix);
  strcat (libname, dsoname);
  libhandle = lt_dlopenext (libname);
  if (libhandle == NULL)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_ADMIN |
                     GNUNET_GE_IMMEDIATE,
                     _("`%s' failed for library `%s' with error: %s\n"),
                     "lt_dlopenext", libname, lt_dlerror ());
      GNUNET_free (libname);
      return NULL;
    }
  GNUNET_free (libname);
  plug = GNUNET_malloc (sizeof (Plugin));
  plug->handle = libhandle;
  plug->libprefix = GNUNET_strdup (libprefix);
  plug->dsoname = GNUNET_strdup (dsoname);
  plug->ectx = ectx;
  return plug;
}

void
GNUNET_plugin_unload (struct GNUNET_PluginHandle *plugin)
{
  // lt_dlclose(plugin->handle);
  GNUNET_free (plugin->libprefix);
  GNUNET_free (plugin->dsoname);
  GNUNET_free (plugin);
}

void *
GNUNET_plugin_resolve_function (struct GNUNET_PluginHandle *plug,
                                const char *methodprefix, int logError)
{
  char *initName;
  void *mptr;

  initName =
    GNUNET_malloc (strlen (plug->dsoname) + strlen (methodprefix) + 2);
  strcpy (initName, "_");
  strcat (initName, methodprefix);
  strcat (initName, plug->dsoname);
  mptr = lt_dlsym (plug->handle, &initName[1]);
  if (mptr == NULL)
    mptr = lt_dlsym (plug->handle, initName);
  if ((mptr == NULL) && (logError))
    GNUNET_GE_LOG (plug->ectx,
                   GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_DEVELOPER |
                   GNUNET_GE_IMMEDIATE,
                   _("`%s' failed to resolve method '%s' with error: %s\n"),
                   "lt_dlsym", &initName[1], lt_dlerror ());
  GNUNET_free (initName);
  return mptr;
}

/* end of dso.c */
