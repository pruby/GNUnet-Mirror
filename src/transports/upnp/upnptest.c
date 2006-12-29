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
 * @file src/transports/upnp/upnptest.c
 * @brief Testcase for UPnP
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_transport_upnp.h"
#include "gnunet_util_error_loggers.h"
#include "platform.h"

int main(int argc,
	 const char *argv[]) {
  struct GE_Context * ectx;
  struct GC_Configuration * cfg;
  IPaddr addr;
  int i;

  ectx = GE_create_context_stderr(NO,
				  GE_WARNING | GE_ERROR | GE_FATAL |
				  GE_USER | GE_ADMIN | GE_DEVELOPER |
				  GE_IMMEDIATE | GE_BULK);
  GE_setDefaultContext(ectx);
  cfg = GC_create_C_impl();
  GE_ASSERT(ectx, cfg != NULL);
  os_init(ectx);
  gnunet_upnp_init(cfg, ectx);

  for (i=0;i<10;i++) {
    if (GNUNET_SHUTDOWN_TEST() != NO) 
      break;
    if (OK == gnunet_upnp_get_ip(2086,
				 "TCP",
				 &addr)) {
      printf("UPnP returned external IP %u.%u.%u.%u\n",
	     PRIP(ntohl(*(int*)&addr)));
    } else {
      /* we cannot be sure that there is a UPnP-capable
	 NAT-box out there, so test should not fail
	 just because of this! */
      printf("No UPnP response (yet).\n");
    }
    PTHREAD_SLEEP(2 * cronSECONDS);
  }
  gnunet_upnp_done();
  GC_free(cfg);
  GE_free_context(ectx);
  return 0;
}

/* end of upnptest.c */
