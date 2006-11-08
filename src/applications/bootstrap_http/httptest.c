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

void release_module_bootstrap();

Bootstrap_ServiceAPI *
provide_module_bootstrap(CoreAPIForApplication * capi);
 
static void * rs(const char * name) { return NULL; }

static int rsx(void * s) { return OK; }

static void hello(const P2P_hello_MESSAGE * m,
		  void * arg) {
  int * cls = arg;
  (*cls)++;
}

static int terminate(void * arg) {
  if (GNUNET_SHUTDOWN_TEST() == YES)
    return NO;
  return YES; /* todo: add timeout? */
}

int main(int argc,
	 char ** argv) {
  static CoreAPIForApplication capi;
  struct GC_Configuration * cfg;
  Bootstrap_ServiceAPI * boot;
  unsigned int count;

  count = 0;
  cfg = GC_create_C_impl();
  GC_set_configuration_value_string(cfg,
				    NULL,
				    "GNUNETD",
				    "HOSTLISTURL",
				    "http://gnunet.org/hostlist");
  memset(&capi,
	 0,
	 sizeof(CoreAPIForApplication));
  capi.cfg = cfg;
  capi.requestService = &rs;
  capi.releaseService = &rsx;
  boot = provide_module_bootstrap(&capi);
  boot->bootstrap(&hello,
		  &count,
		  &terminate,
		  NULL);
  release_module_bootstrap();
  GC_free(cfg);
  if (count == 0)
    return 1;
  return 0;
}
