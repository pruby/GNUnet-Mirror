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
#include "platform.h"

int
main (int argc, const char *argv[])
{
  int daemon;
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GC_Configuration *cfg;

  ectx = GNUNET_GE_create_context_stderr (GNUNET_NO,
                                          GNUNET_GE_ERROR | GNUNET_GE_FATAL |
                                          GNUNET_GE_USER | GNUNET_GE_ADMIN |
                                          GNUNET_GE_DEVELOPER |
                                          GNUNET_GE_IMMEDIATE |
                                          GNUNET_GE_BULK);
  GNUNET_GE_setDefaultContext (ectx);
  cfg = GNUNET_GC_create ();
  GNUNET_GE_ASSERT (ectx, cfg != NULL);
  GNUNET_os_init (ectx);
  daemon = GNUNET_daemon_start (ectx, cfg, "check.conf", GNUNET_NO);
  if (daemon <= 0)
    {
      fprintf (stderr, "Failed to start daemon.\n");
      GNUNET_GC_free (cfg);
      GNUNET_GE_free_context (ectx);
      return 1;
    }
  if (GNUNET_OK !=
      GNUNET_wait_for_daemon_running (ectx, cfg, 30 * GNUNET_CRON_SECONDS))
    {
      fprintf (stderr, "Failed to confirm daemon running (after 30s).\n");
      /* try killing anyway, just to be sure */
      GNUNET_daemon_stop (ectx, daemon);
      GNUNET_GC_free (cfg);
      GNUNET_GE_free_context (ectx);
      return 1;
    }
  if (GNUNET_OK != GNUNET_daemon_stop (ectx, daemon))
    {
      fprintf (stderr, "Failed to stop daemon.\n");
      GNUNET_GC_free (cfg);
      GNUNET_GE_free_context (ectx);
      return 1;
    }

  GNUNET_GC_free (cfg);
  GNUNET_GE_free_context (ectx);
  return 0;
}

/* end of deamontest.c */
