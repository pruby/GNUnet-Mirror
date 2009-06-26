/*
     This file is part of GNUnet.
     (C) 2007, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/dv_dht/tools/dv_dht_driver.c
 * @brief DV_DHT Driver for testing DHT
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_dv_dht_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_stats_lib.h"
#include "gnunet_util.h"
#include "gnunet_remote_lib.h"
#include "gnunet_dhtlog_service.h"



static char *configFile = "dv_test.conf";
static GNUNET_CoreAPIForPlugins capi;
static struct GNUNET_GE_Context *ectx;
static struct GNUNET_GC_Configuration *cfg;
static GNUNET_ServicePluginInitializationMethod init;
static GNUNET_ServicePluginShutdownMethod done;
static GNUNET_dhtlog_ServiceAPI *sqlapi;

static unsigned long long topology;
static unsigned long long num_peers;
static unsigned long long num_repeat;
static unsigned long long num_rounds;
static char *dotOutFileName = NULL;

static struct GNUNET_CommandLineOption gnunetDHTDriverOptions[] = {
  GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&configFile),    /* -c */
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Run tests on DHT")),  /* -h */
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION), /* -v */
  {'O', "output", "DOT_OUTPUT",
   gettext_noop
   ("set output file for a dot input file which represents the graph of the connected nodes"),
   1, &GNUNET_getopt_configure_set_string, &dotOutFileName},
  GNUNET_COMMAND_LINE_OPTION_VERBOSE,
  GNUNET_COMMAND_LINE_OPTION_END,
};

/**
 * How many peers should the testcase run (default)?
 */
#define DEFAULT_NUM_PEERS 15

/**
 * How many times will we try the DV_DHT-GET operation before
 * giving up for good (default)?
 */
#define DEFAULT_NUM_ROUNDS 20

/**
 * How often do we iterate the put-get loop (default)?
 */
#define DEFAULT_NUM_REPEAT 5

static int ok;
static int found;

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

static int
result_callback (const GNUNET_HashCode * key,
                 unsigned int type,
                 unsigned int size, const char *data, void *cls)
{
  int *i = cls;
  char expect[8];

  memset (expect, (*i), sizeof (expect));
#if 0
  fprintf (stderr, "Got %u %u `%.*s' (want `%.*s')\n", type, size, size, data,
           sizeof (expect), expect);
#endif
  if ((8 != size) ||
      (0 != memcmp (expect, data, size)) ||
      (type != GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING))
    return GNUNET_SYSERR;
  found++;
  return GNUNET_OK;
}


static int
waitForConnect (const char *name, unsigned long long value, void *cls)
{
  if ((value > 0) && (0 == strcmp (_("# dv_dht connections"), name)))
    {
      ok = 1;
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

static int
getPeers (const char *name, unsigned long long value, void *cls)
{
  if ((value > 0) && (strstr (name, _("# dv")) != NULL))
    {
      fprintf (stderr, "%s : %llu\n", name, value);
    }

  if ((value > 0) && (0 == strcmp (_("# dv_dht connections"), name)))
    {
      ok = 1;
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

#define CHECK(a) do { if (!(a)) { ret = 1; GNUNET_GE_BREAK(ectx, 0); goto FAILURE; } } while(0)


int
do_testing (int argc, char *const *argv)
{
  struct GNUNET_REMOTE_TESTING_DaemonContext *peers;
  struct GNUNET_REMOTE_TESTING_DaemonContext *peer_array[num_peers];
  struct GNUNET_REMOTE_TESTING_DaemonContext *pos;
  int ret = 0;
  GNUNET_HashCode key;
  char value[8];
  struct GNUNET_ClientServerConnection *sock;
  struct GNUNET_DV_DHT_Context *dctx;
  struct GNUNET_DV_DHT_GetRequest *get1;
  int left;
  int i;
  int j;
  int k;
  int c;
  int r;
  int last;
  char buf[128];
  unsigned long long trialuid;

  if (sqlapi == NULL)
    {
      return GNUNET_SYSERR;
    }
  else
    {
      ret = sqlapi->insert_trial (&trialuid, num_peers, topology);
    }

  if (ret != GNUNET_OK)
    return GNUNET_SYSERR;
  printf ("Starting %u peers...\n", (unsigned int) num_peers);
  peers = GNUNET_REMOTE_start_daemons (cfg, num_peers);
  if (peers == NULL)
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  pos = peers;
  for (i = 0; i < num_peers; i++)
    {
      peer_array[i] = pos;
      pos = pos->next;
    }
  sleep (30);
  found = 0;
  for (r = 0; r < num_repeat; r++)
    {
      fprintf (stderr, "After %d minutes\n", r);
      for (i = 0; i < num_peers; i++)
        {
          if (GNUNET_shutdown_test () == GNUNET_YES)
            break;
          fprintf (stderr, "Peer %d: ", i);
          sock =
            GNUNET_client_connection_create (NULL, peer_array[i]->config);
          GNUNET_STATS_get_statistics (NULL, sock, &getPeers, NULL);
          GNUNET_thread_sleep (2 * GNUNET_CRON_SECONDS);
          GNUNET_client_connection_destroy (sock);

        }
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
      sleep (60);
    }

  for (r = 0; r < num_repeat; r++)
    {
      if (r > 0)
        {
          printf ("Found %u out of %llu attempts.\n", found,
                  num_peers * num_peers * r);
          if (found >= num_peers * num_peers * r / 2)
            break;              /* good enough */
        }
      for (i = 0; i < num_peers; i++)
        {
          if (GNUNET_shutdown_test () == GNUNET_YES)
            break;
          fprintf (stderr, "Peer %d: ", i);
          sock =
            GNUNET_client_connection_create (NULL, peer_array[i]->config);
          GNUNET_STATS_get_statistics (NULL, sock, &getPeers, NULL);
          GNUNET_thread_sleep (2 * GNUNET_CRON_SECONDS);
          GNUNET_client_connection_destroy (sock);
        }
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
      /* put loop */
      printf ("Waiting for DV_DHT connections of peer");
      for (i = 0; i < num_peers; i++)
        {
          if (GNUNET_shutdown_test () == GNUNET_YES)
            break;
          ok = 0;
          printf (" %d", i);
          fflush (stdout);
          GNUNET_snprintf (buf, sizeof (buf), "localhost:%u", 2087 + i * 10);
          /* wait for some DV_DHT's to find each other! */
          sock =
            GNUNET_client_connection_create (NULL, peer_array[i]->config);
          left = 30;            /* how many iterations should we wait? */
          while (GNUNET_OK ==
                 GNUNET_STATS_get_statistics (NULL, sock, &waitForConnect,
                                              NULL))
            {
              if (GNUNET_shutdown_test () == GNUNET_YES)
                break;
              if (9 == left % 10)
                printf (".");
              fflush (stdout);
              GNUNET_thread_sleep (2 * GNUNET_CRON_SECONDS);
              left--;
              if (left == 0)
                break;
            }
          GNUNET_client_connection_destroy (sock);
          if (ok == 0)
            {
              printf ("ERROR!\n");
              fflush (stdout);
              pos = peers;
              while (pos != NULL)
                {
                  GNUNET_REMOTE_kill_daemon (pos);
                  pos = pos->next;
                }
              fprintf (stderr, "Peers' DV_DHTs failed to DV_DHT-connect!\n");
              GNUNET_GC_free (cfg);
              return -1;
            }
          GNUNET_hash (buf, strlen (buf), &key);
          memset (value, 'A' + i, sizeof (value));
          CHECK (GNUNET_OK == GNUNET_DV_DHT_put (peer_array[i]->config,
                                                 ectx,
                                                 &key,
                                                 GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING,
                                                 sizeof (value), value));
        }
      printf ("\n");
      /* get loop */
      for (i = 0; i < num_peers; i++)
        {
          if (GNUNET_shutdown_test () == GNUNET_YES)
            break;
          GNUNET_snprintf (buf, sizeof (buf), "localhost:%u", 2087 + i * 10);

          dctx =
            GNUNET_DV_DHT_context_create (peer_array[i]->config, ectx,
                                          &result_callback, &c);
          printf ("Peer %d gets key", i);
          fflush (stdout);
          for (j = 0; j < num_peers; j++)
            {
              if (GNUNET_shutdown_test () == GNUNET_YES)
                break;
              c = 'A' + j;
              GNUNET_snprintf (buf, sizeof (buf), "localhost:%u",
                               2087 + j * 10);
              GNUNET_hash (buf, strlen (buf), &key);
              printf (" %d", j);
              fflush (stdout);
              last = found;
              get1 = GNUNET_DV_DHT_get_start (dctx,
                                              GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING,
                                              &key);
              GNUNET_GE_ASSERT (NULL, get1 != NULL);
              for (k = 0; k < num_rounds; k++)
                {
                  if (GNUNET_shutdown_test () == GNUNET_YES)
                    break;
                  if (9 == (k % 10))
                    {
                      printf (".");
                      fflush (stdout);
                    }
                  fflush (stdout);
                  GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
                  if (last < found)
                    break;
                }
              GNUNET_DV_DHT_get_stop (dctx, get1);
              if (k == num_rounds)
                {
                  printf ("?");
                  fflush (stdout);
                }
            }
          GNUNET_DV_DHT_context_destroy (dctx);
          printf ("\n");
        }
    }
  /* end of actual test code */
  if (r == num_repeat)
    printf ("Found %u out of %llu attempts.\n", found,
            num_peers * num_peers * r);
  if (found < num_peers * num_peers * r / 2)
    {
      printf
        ("Not enough results (not even 50%%), marking test as failed!\n");
      ret = 1;
    }
FAILURE:
  pos = peers;
  while (pos != NULL)
    {
      GNUNET_REMOTE_kill_daemon (pos);
      pos = pos->next;
    }
  ret = sqlapi->update_trial (trialuid);
  return ret;
}

/**
 * Driver for testing DV_DHT routing (many peers).
 * @return 0: ok, -1: error
 */
int
main (int argc, char *const *argv)
{
  int ret = 0;
  struct GNUNET_PluginHandle *plugin;
  struct GNUNET_GC_Configuration *driverConfig;
  ectx = NULL;
  cfg = GNUNET_GC_create ();

  ret =
    GNUNET_init (argc, argv, "dvdhtdriver", &configFile,
                 gnunetDHTDriverOptions, &ectx, &driverConfig);

  if (ret == -1)
    {
      GNUNET_fini (ectx, cfg);
      return -1;
    }

  if (-1 == GNUNET_GC_parse_configuration (cfg, configFile))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  if (dotOutFileName != NULL)
    {
      GNUNET_GC_set_configuration_value_string (cfg, NULL,
                                                "MULTIPLE_SERVER_TESTING",
                                                "DOT_OUTPUT", dotOutFileName);
    }

  GNUNET_GC_get_configuration_value_number (cfg,
                                            "MULTIPLE_SERVER_TESTING",
                                            "TOPOLOGY", 0, -1, 0, &topology);

  GNUNET_GC_get_configuration_value_number (cfg,
                                            "MULTIPLE_SERVER_TESTING",
                                            "NUM_PEERS",
                                            1,
                                            -1,
                                            DEFAULT_NUM_PEERS, &num_peers);

  GNUNET_GC_get_configuration_value_number (cfg,
                                            "MULTIPLE_SERVER_TESTING",
                                            "NUM_ROUNDS",
                                            1,
                                            -1,
                                            DEFAULT_NUM_ROUNDS, &num_rounds);

  GNUNET_GC_get_configuration_value_number (cfg,
                                            "MULTIPLE_SERVER_TESTING",
                                            "NUM_REPEAT",
                                            1,
                                            -1,
                                            DEFAULT_NUM_REPEAT, &num_repeat);

  memset (&capi, 0, sizeof (GNUNET_CoreAPIForPlugins));
  capi.cfg = cfg;
  capi.service_request = &rs;
  capi.service_release = &rsx;

  plugin = GNUNET_plugin_load (NULL, "libgnunetmodule_", "dhtlog_mysql");
  init =
    GNUNET_plugin_resolve_function (plugin, "provide_module_", GNUNET_YES);
  sqlapi = init (&capi);
  if (sqlapi == NULL)
    {
      ret = GNUNET_SYSERR;
    }
  else
    {
      ret = do_testing (argc, argv);
    }
  done =
    GNUNET_plugin_resolve_function (plugin, "release_module_", GNUNET_YES);
  if (done != NULL)
    done ();

  GNUNET_plugin_unload (plugin);

  GNUNET_GC_free (cfg);
  return ret;
}

/* end of dv_dht_driver.c */
