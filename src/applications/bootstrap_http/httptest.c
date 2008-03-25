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
 * @file bootstrap_http/httptest.c
 * @brief Tests http.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_core.h"
#include "gnunet_protocols.h"
#include "gnunet_bootstrap_service.h"
#include "gnunet_stats_service.h"

void release_module_bootstrap ();

GNUNET_Bootstrap_ServiceAPI
  * provide_module_bootstrap (GNUNET_CoreAPIForPlugins * capi);

static void *
rs (const char *name)
{
  return NULL;
}

static int
rsx (void *s)
{
  return GNUNET_OK;
}

static unsigned int count;


static void
hello (const GNUNET_MessageHello * m, void *arg)
{
  count++;
}

static int
terminate (void *arg)
{
  if (GNUNET_shutdown_test () == GNUNET_YES)
    return GNUNET_NO;
  return GNUNET_YES;            /* todo: add timeout? */
}

static void *
pt (void *b)
{
  GNUNET_Bootstrap_ServiceAPI *boot = b;

  boot->bootstrap (&hello, NULL, &terminate, NULL);
  return NULL;
}

int
main (int argc, char **argv)
{
  static GNUNET_CoreAPIForPlugins capi;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_PluginHandle *plugin;
  GNUNET_Bootstrap_ServiceAPI *boot;
  struct GNUNET_ThreadHandle *p;
  void *unused;
  GNUNET_ServicePluginInitializationMethod init;
  GNUNET_ServicePluginShutdownMethod done;

  count = 0;
  cfg = GNUNET_GC_create ();
  GNUNET_GC_set_configuration_value_string (cfg,
                                            NULL,
                                            "GNUNETD",
                                            "HOSTLISTURL",
                                            "http://gnunet.org/hostlist.php");
  memset (&capi, 0, sizeof (GNUNET_CoreAPIForPlugins));
  capi.cfg = cfg;
  capi.service_request = &rs;
  capi.service_release = &rsx;
  plugin = GNUNET_plugin_load (NULL, "libgnunetmodule_", "bootstrap");
  init =
    GNUNET_plugin_resolve_function (plugin, "provide_module_", GNUNET_YES);
  boot = init (&capi);
  if (boot != NULL)
    {
      p = GNUNET_thread_create (&pt, boot, 1024 * 64);
      GNUNET_thread_join (p, &unused);
      done =
        GNUNET_plugin_resolve_function (plugin, "release_module_",
                                        GNUNET_YES);
      if (done != NULL)
        done ();
    }
  GNUNET_plugin_unload (plugin);
  GNUNET_GC_free (cfg);
  if (count == 0)
    return 1;
  return 0;
}
