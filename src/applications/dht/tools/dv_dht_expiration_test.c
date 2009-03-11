/*
     This file is part of GNUnet.
     (C) 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/dht/tools/dht_expiration_test.c
 * @brief DV_DHT testcase using only a single peer
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_dht_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_stats_lib.h"
#include "gnunet_util.h"


#define START_PEERS 1

static int err;

static int
result_callback (const GNUNET_HashCode * key,
                 unsigned int type,
                 unsigned int size, const char *data, void *cls)
{
  fprintf (stderr, "Got %u %u `%.*s'\n", type, size, size, data);
  err = 1;
  return GNUNET_SYSERR;
}

#define CHECK(a) do { if (!(a)) { ret = 1; GNUNET_GE_BREAK(ectx, 0); goto FAILURE; } } while(0)

/**
 * Testcase to test DV_DHT routing (2 peers only).
 * @return 0: ok, -1: error
 */
int
main (int argc, const char **argv)
{
#if START_PEERS
  struct GNUNET_TESTING_DaemonContext *peers;
#endif
  int ret = 0;
  GNUNET_HashCode key;
  char *value;
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_DV_DHT_Context *ctx;
  void *unused_cls = NULL;


  ectx = NULL;
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
#if START_PEERS
  peers = GNUNET_TESTING_start_daemons ("nat",
                                        "advertising dv dv_dht stats",
                                        "/tmp/gnunet-dv-dht-loopback-test",
                                        2087, 10000, 1);
  if (peers == NULL)
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
#endif
  GNUNET_GC_set_configuration_value_string (cfg,
                                            ectx,
                                            "NETWORK", "HOST",
                                            "localhost:2087");
  ctx = GNUNET_DV_DHT_context_create (cfg, ectx, &result_callback, unused_cls);
  CHECK (ctx != NULL);
  /* actual test code */
  GNUNET_hash ("expired_key", 4, &key);
  value = GNUNET_malloc (8);
  memset (value, 'A', 8);
  CHECK (GNUNET_OK == GNUNET_DV_DHT_put (cfg,
                                      ectx,
                                      &key,
                                      GNUNET_ECRS_BLOCKTYP_DV_DHT_STRING2STRING,
                                      8, value));
  /* FIXME: this value has to be >> than the expiration
     time (which is currently fixed to 12h, so we can not
     really do this test in practice... */
  GNUNET_thread_sleep (60 * GNUNET_CRON_SECONDS);
  CHECK (1 == GNUNET_DV_DHT_get_start (ctx,
                                    GNUNET_ECRS_BLOCKTYP_DV_DHT_STRING2STRING,
                                    &key));
  GNUNET_thread_sleep (15 * GNUNET_CRON_SECONDS);
  GNUNET_DV_DHT_context_destroy (ctx);

FAILURE:
#if START_PEERS
  GNUNET_TESTING_stop_daemons (peers);
#endif
  GNUNET_GC_free (cfg);
  return err;
}

/* end of dv_dht_expiration_test.c */
