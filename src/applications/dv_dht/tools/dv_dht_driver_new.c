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


struct GNUNET_DV_DHT_keys
{
  char data[8];
  GNUNET_HashCode key;
};

static char *configFile = "dv_test.conf";
static GNUNET_CoreAPIForPlugins capi;
static struct GNUNET_GE_Context *ectx;
static struct GNUNET_GC_Configuration *cfg;
static GNUNET_ServicePluginInitializationMethod init;
static GNUNET_ServicePluginShutdownMethod done;
static GNUNET_dhtlog_ServiceAPI *sqlapi;
static struct GNUNET_Mutex *lock;

static unsigned long long topology;
static unsigned long long num_peers;
static unsigned long long num_repeat;
static unsigned long long num_rounds;
static unsigned long long settle_time;
static unsigned long long put_items;
static unsigned long long get_requests;
static unsigned long long concurrent_requests;
static unsigned long long requests_per_second;
static unsigned long long requests_wait_time;

static char *dotOutFileName = NULL;
static char *trialmessage = NULL;

static struct GNUNET_CommandLineOption gnunetDHTDriverOptions[] = {
  GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&configFile),    /* -c */
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Run tests on DHT")),  /* -h */
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION), /* -v */
  {'O', "output", "DOT_OUTPUT",
   gettext_noop
   ("set output file for a dot input file which represents the graph of the connected nodes"),
   1, &GNUNET_getopt_configure_set_string, &dotOutFileName},
  {'m', "mesage", "LOG_MESSAGE",
   gettext_noop ("log a message along with this trial in the database"),
   1, &GNUNET_getopt_configure_set_string, &trialmessage},
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
#define DEFAULT_NUM_ROUNDS 200

/**
 * How often do we iterate the put-get loop (default)?
 */
#define DEFAULT_NUM_REPEAT 5

static int ok;
static int found;
static int new_found;

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
  struct GNUNET_DV_DHT_keys *key_data = cls;
#if 0
  fprintf (stderr, "Got %u %u `%.*s' (want `%.*s')\n", type, size, size, data,
           sizeof (expect), expect);

  if ((8 != size) ||
      (0 != memcmp (key_data->data, data, size)) ||
      (type != GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING))
    return GNUNET_SYSERR;
#endif
  if ((8 != size) ||
      (0 != memcmp (key_data->data, data, size)) ||
      (type != GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING))
    return GNUNET_SYSERR;
  else
    {
      GNUNET_mutex_lock (lock);
      found++;
      new_found++;
      GNUNET_mutex_unlock (lock);
      return GNUNET_OK;
    }
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
      return GNUNET_OK;
    }
  return GNUNET_OK;
}

#define CHECK(a) do { if (!(a)) { ret = 1; GNUNET_GE_BREAK(ectx, 0); goto FAILURE; } } while(0)

int
new_do_testing (int argc, char *const *argv)
{
  struct GNUNET_REMOTE_TESTING_DaemonContext *peers;
  struct GNUNET_REMOTE_TESTING_DaemonContext *peer_array[num_peers];
  struct GNUNET_DV_DHT_Context *dctx[concurrent_requests];
  struct GNUNET_DV_DHT_GetRequest *gets[concurrent_requests];
  struct GNUNET_DV_DHT_keys keys[put_items];
  struct GNUNET_REMOTE_TESTING_DaemonContext *pos;
  int ret = 0;

  struct GNUNET_ClientServerConnection *sock;

  int i;
  int k;
  int r;
  int l;
  int j;

  int key_count;

  int random_peers[concurrent_requests];
  int random_peer;
  int random_key;
  int totalConnections;
  unsigned int failed_inserts;
  unsigned long long trialuid;

  key_count = 0;


  printf ("Starting %u peers\n", (unsigned int) num_peers);
  if (trialmessage != NULL)
    {
      printf ("Trial message is %s, strlen is %d\n", trialmessage,
              (int)strlen (trialmessage));
    }

  if (sqlapi == NULL)
    {
      return GNUNET_SYSERR;
    }
  else
    {
      if (trialmessage != NULL)
        {
          ret =
            sqlapi->insert_trial (&trialuid, num_peers, topology, put_items,
                                  get_requests, concurrent_requests,
                                  settle_time, trialmessage);
        }
      else
        {
          ret =
            sqlapi->insert_trial (&trialuid, num_peers, topology, put_items,
                                  get_requests, concurrent_requests,
                                  settle_time, "");
        }
    }
  if (ret != GNUNET_OK)
    return GNUNET_SYSERR;

  ret = GNUNET_REMOTE_start_daemons (&peers, cfg, num_peers);
  if (ret != GNUNET_SYSERR)
    totalConnections = ret;
  else
    return ret;

  sqlapi->update_connections (trialuid, totalConnections);
  printf ("Topology created, %d total connections, Trial uid %llu\n",
          totalConnections, trialuid);
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

  for (i = 0; i < put_items; i++)
    {
      for (l = 0; l < 8; l++)
        {
          keys[i].data[l] = rand ();
        }
      GNUNET_hash (keys[i].data, 8, &keys[i].key);
    }
  sleep (30);
  found = 0;

  for (r = 0; r < settle_time; r++)
    {
      fprintf (stderr, "After %d minutes\n", r);
      for (i = 0; i < num_peers; i++)
        {
          if (GNUNET_shutdown_test () == GNUNET_YES)
            break;
          fprintf (stderr, "Peer %d (%s:%d, pid %s):\n", i, peer_array[i]->hostname, peer_array[i]->port, peer_array[i]->pid);
          sock =
            GNUNET_client_connection_create (NULL, peer_array[i]->config);

          if (GNUNET_SYSERR == GNUNET_STATS_get_statistics (NULL, sock, &getPeers, NULL))
          {
            fprintf(stderr, "Problem connecting to peer %d!\n", i);
          }
          GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
          GNUNET_client_connection_destroy (sock);
        }
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
      sleep (60);
    }

  if (GNUNET_shutdown_test () == GNUNET_YES)
    return GNUNET_SYSERR;

  for (i = 0; i < put_items; i++)
    {
      random_peer = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, num_peers);
      random_key = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, put_items);
      fprintf (stdout, "Inserting key %d at peer %d\n", random_key, random_peer);
      if (GNUNET_OK != GNUNET_DV_DHT_put (peer_array[random_peer]->config,
                                             ectx,
                                             &keys[random_key].key,
                                             GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING,
                                             sizeof (keys[random_key].data),
                                             keys[random_key].data))
        {
          fprintf (stdout, "Insert FAILED at peer %d\n", random_peer);
          failed_inserts++;
        }
      GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
    }
  fprintf (stdout, "Inserted %llu items\n", put_items - failed_inserts);

  for (i = 0; i < get_requests / concurrent_requests; i++)
    {
      new_found = 0;
      for (j = 0; j < concurrent_requests; j++)
        {
          random_peers[j] =
            GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, num_peers);
          random_key =
            GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, put_items);
          /*random_key = (i + 1) * (j + 1) - 1; */
          dctx[j] =
            GNUNET_DV_DHT_context_create (peer_array[random_peers[j]]->config,
                                          ectx, &result_callback,
                                          &keys[random_key]);
          fprintf (stdout, "Searching for key %d from peer %d\n", random_key,
                   random_peers[j]);
          gets[j] =
            GNUNET_DV_DHT_get_start (dctx[j],
                                     GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING,
                                     &keys[random_key].key);
          GNUNET_GE_ASSERT (NULL, gets[j] != NULL);
        }

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
        }

      for (j = 0; j < concurrent_requests; j++)
        {
          GNUNET_DV_DHT_get_stop (dctx[j], gets[j]);
          GNUNET_DV_DHT_context_destroy (dctx[j]);
        }
      printf ("Found %u out of %llu attempts.\n", new_found,
              concurrent_requests);

    }
  printf ("Found %u out of %llu attempts.\n", found, get_requests);

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
  lock = GNUNET_mutex_create (GNUNET_YES);
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
                                            "SETTLE_TIME",
                                            0, -1, 0, &settle_time);

  GNUNET_GC_get_configuration_value_number (cfg,
                                            "MULTIPLE_SERVER_TESTING",
                                            "CONCURRENT_REQUESTS",
                                            1, -1, 5, &concurrent_requests);

  GNUNET_GC_get_configuration_value_number (cfg,
                                            "MULTIPLE_SERVER_TESTING",
                                            "PUT_ITEMS",
                                            1, -1, 100, &put_items);

  GNUNET_GC_get_configuration_value_number (cfg,
                                            "MULTIPLE_SERVER_TESTING",
                                            "GET_REQUESTS",
                                            1, -1, 100, &get_requests);

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
      ret = new_do_testing (argc, argv);
    }
  done =
    GNUNET_plugin_resolve_function (plugin, "release_module_", GNUNET_YES);
  if (done != NULL)
    done ();

  fprintf (stdout,
           "# Inserts: %llu\n# Gets: %llu\nSettle time: %llu\n# Nodes: %llu\n# Concurrent: %llu\n# Wait time: %llu\n# Successful: %d\n",
           put_items, get_requests, settle_time, num_peers,
           concurrent_requests, num_rounds, found);
  GNUNET_plugin_unload (plugin);
  GNUNET_mutex_destroy (lock);
  return ret;
}

/* end of dv_dht_driver.c */
