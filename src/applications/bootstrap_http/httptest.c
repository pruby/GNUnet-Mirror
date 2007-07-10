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
#include "gnunet_util_crypto.h"
#include "gnunet_core.h"
#include "gnunet_protocols.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_bootstrap_service.h"
#include "gnunet_stats_service.h"

void release_module_bootstrap ();

Bootstrap_ServiceAPI *provide_module_bootstrap (CoreAPIForApplication * capi);

static void *
rs (const char *name)
{
  return NULL;
}

static int
rsx (void *s)
{
  return OK;
}

static unsigned int count;


static void
hello (const P2P_hello_MESSAGE * m, void *arg)
{
  count++;
}

static int
terminate (void *arg)
{
  if (GNUNET_SHUTDOWN_TEST () == YES)
    return NO;
  return YES;                   /* todo: add timeout? */
}

static void *
pt (void *b)
{
  Bootstrap_ServiceAPI *boot = b;

  boot->bootstrap (&hello, NULL, &terminate, NULL);
  return NULL;
}

int
main (int argc, char **argv)
{
  static CoreAPIForApplication capi;
  struct GC_Configuration *cfg;
  struct PluginHandle *plugin;
  Bootstrap_ServiceAPI *boot;
  struct PTHREAD *p;
  void *unused;
  ServiceInitMethod init;
  ServiceDoneMethod done;

  count = 0;
  cfg = GC_create_C_impl ();
  GC_set_configuration_value_string (cfg,
                                     NULL,
                                     "GNUNETD",
                                     "HOSTLISTURL",
                                     "http://gnunet.org/hostlist");
  memset (&capi, 0, sizeof (CoreAPIForApplication));
  capi.cfg = cfg;
  capi.requestService = &rs;
  capi.releaseService = &rsx;
  plugin = os_plugin_load (NULL, "libgnunetmodule_", "bootstrap");
  init = os_plugin_resolve_function (plugin, "provide_module_", YES);
  boot = init (&capi);
  p = PTHREAD_CREATE (&pt, boot, 1024 * 64);
  PTHREAD_JOIN (p, &unused);
  done = os_plugin_resolve_function (plugin, "release_module_", YES);
  done ();
  os_plugin_unload (plugin);
  GC_free (cfg);
  if (count == 0)
    return 1;
  return 0;
}
