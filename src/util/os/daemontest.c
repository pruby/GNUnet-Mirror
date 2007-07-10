/*
     This file is part of GNUnet.
     (C) 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file src/util/os/daemontest.c
 * @brief Testcase for the daemon functions
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"
#include "gnunet_util_error_loggers.h"
#include "platform.h"

int
main (int argc, const char *argv[])
{
  int daemon;
  struct GE_Context *ectx;
  struct GC_Configuration *cfg;

  ectx = GE_create_context_stderr (NO,
                                   GE_WARNING | GE_ERROR | GE_FATAL |
                                   GE_USER | GE_ADMIN | GE_DEVELOPER |
                                   GE_IMMEDIATE | GE_BULK);
  GE_setDefaultContext (ectx);
  cfg = GC_create_C_impl ();
  GE_ASSERT (ectx, cfg != NULL);
  os_init (ectx);
  daemon = os_daemon_start (ectx, cfg, "check.conf", NO);
  if (daemon <= 0)
    {
      fprintf (stderr, "Failed to start daemon.\n");
      GC_free (cfg);
      GE_free_context (ectx);
      return 1;
    }
  if (OK != connection_wait_for_running (ectx, cfg, 30 * cronSECONDS))
    {
      fprintf (stderr, "Failed to confirm daemon running (after 30s).\n");
      /* try killing anyway, just to be sure */
      os_daemon_stop (ectx, daemon);
      GC_free (cfg);
      GE_free_context (ectx);
      return 1;
    }
  if (OK != os_daemon_stop (ectx, daemon))
    {
      fprintf (stderr, "Failed to stop daemon.\n");
      GC_free (cfg);
      GE_free_context (ectx);
      return 1;
    }

  GC_free (cfg);
  GE_free_context (ectx);
  return 0;
}

/* end of deamontest.c */
