/*
     This file is part of GNUnet.
     (C) 2007 Christian Grothoff (and other contributing authors)

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
 * @file transports/test_repeat.c
 * @brief Test for the transports.
 * @author Christian Grothoff
 *
 * This utility can be used to test if a transport mechanism for
 * GNUnet is properly configured.
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_directories.h"
#include "gnunet_protocols.h"
#include "gnunet_transport.h"
#include "common.h"

#define ROUNDS 10

#define XROUNDS 10

#define OFFSET 10

/**
 * Name of the configuration file.
 */
static char *cfgFilename = "test.conf";

/**
 * Transport being tested.
 */
static GNUNET_TransportAPI *transport;

/**
 * What response do we currently expect to receive?
 */
static char *expectedValue;

/**
 * What is the size of the expected response?
 * (pick a value smaller than the minimum expected MTU)
 */
static unsigned long long expectedSize = 1200;

/**
 * Am I client (!= 0) or server (== 0)?
 */
static pid_t pid;

/**
 * How often did we fail so far?
 */
static unsigned int error_count;

/**
 * How many messages did we process?
 */
static unsigned int msg_count;

/**
 * No options.
 */
static struct GNUNET_CommandLineOption testOptions[] = {
  GNUNET_COMMAND_LINE_OPTION_END,
};

static void *
request_service (const char *name)
{
  /* we expect only "stats" to be requested... */
  if (0 != strcmp (name, "stats"))
    fprintf (stderr, "Rejecting request for service `%s'\n", name);
  return NULL;
}

static int
connection_assert_tsession_unused (GNUNET_TSession * tsession)
{
  return GNUNET_OK;
}

/**
 * We received a message.  The "client" should try to echo it back,
 * the "server" should validate that it got the right reply.
 */
static void
receive (GNUNET_TransportPacket * mp)
{
  unsigned int retries;
  GNUNET_TSession *tsession;
  GNUNET_MessageHello *hello;

  if (pid == 0)
    {
      /* server; do echo back */
      retries = 0;
      tsession = mp->tsession;
      if (tsession == NULL)
        {
          hello = transport->hello_create ();
          /* HACK hello -- change port! */
          ((HostAddress *) & hello[1])->port =
            htons (ntohs (((HostAddress *) & hello[1])->port) - OFFSET);
          if (GNUNET_OK != transport->connect (hello, &tsession, GNUNET_NO))
            {
              GNUNET_free (hello);
              GNUNET_free (mp->msg);
              GNUNET_free (mp);
              error_count++;
              return;
            }
          GNUNET_free (hello);
        }
      while (GNUNET_NO == transport->send (tsession,
                                           mp->msg,
                                           mp->size,
                                           retries >
                                           6 ? GNUNET_YES : GNUNET_NO))
        {
          if (retries > 10)
            {
              fprintf (stderr, "Failed to send reply!\n");
              error_count++;
              break;
            }
          retries++;
        }
      if (mp->tsession == NULL)
        transport->disconnect (tsession);
    }
  else
    {
      /* validate echo */
      if ((mp->size != expectedSize) ||
          (0 != memcmp (mp->msg, expectedValue, mp->size)))
        {
          fprintf (stderr, "Received invalid response\n");
          error_count++;
        }
      else
        msg_count++;
    }
  GNUNET_free (mp->msg);
  GNUNET_free (mp);
}

int
main (int argc, char *const *argv)
{
  GNUNET_CoreAPIForTransport api;
  struct GNUNET_PluginHandle *plugin;
  GNUNET_TransportMainMethod init;
  void (*done) ();
  GNUNET_PeerIdentity me;
  char *trans;
  int res;
  int pos;
  GNUNET_TSession *tsession;
  GNUNET_MessageHello *hello;
  int xround;

  memset (&api, 0, sizeof (GNUNET_CoreAPIForTransport));
  pid = fork ();
  res = GNUNET_init (argc,
                     argv,
                     "transport-test",
                     &cfgFilename, testOptions, &api.ectx, &api.cfg);
  if (res == -1)
    goto cleanup;

  expectedValue = GNUNET_malloc (expectedSize);
  pos = expectedSize;
  expectedValue[--pos] = '\0';
  while (pos-- > 0)
    expectedValue[pos] = 'A' + (pos % 26);
  trans = strstr (argv[0], "_");
  if (trans == NULL)
    goto cleanup;
  trans++;
  trans = strdup (trans);
  if (NULL != strstr (trans, "."))
    strstr (trans, ".")[0] = '\0';
  if (NULL != strstr (trans, "-"))
    strstr (trans, ".")[0] = '\0';
  /* disable blacklists (loopback is often blacklisted)... */
  GNUNET_GC_set_configuration_value_string (api.cfg, api.ectx, "TCP",
                                            "BLACKLIST", "");
  GNUNET_GC_set_configuration_value_string (api.cfg, api.ectx, "TCP", "UPNP",
                                            "NO");
  GNUNET_GC_set_configuration_value_string (api.cfg, api.ectx, "TCP6",
                                            "BLACKLIST", "");
  GNUNET_GC_set_configuration_value_string (api.cfg, api.ectx, "UDP",
                                            "BLACKLIST", "");
  GNUNET_GC_set_configuration_value_string (api.cfg, api.ectx, "UDP", "UPNP",
                                            "NO");
  GNUNET_GC_set_configuration_value_string (api.cfg, api.ectx, "UDP6",
                                            "BLACKLIST", "");
  GNUNET_GC_set_configuration_value_string (api.cfg, api.ectx, "HTTP",
                                            "BLACKLIST", "");
  GNUNET_GC_set_configuration_value_string (api.cfg, api.ectx, "HTTP", "UPNP",
                                            "NO");

  if (pid == 0)
    pos = OFFSET;
  else
    pos = 0;
  GNUNET_GC_set_configuration_value_number (api.cfg, api.ectx, "TCP", "PORT",
                                            4444 + pos);
  GNUNET_GC_set_configuration_value_number (api.cfg, api.ectx, "TCP6", "PORT",
                                            4445 + pos);
  GNUNET_GC_set_configuration_value_number (api.cfg, api.ectx, "UDP", "PORT",
                                            4446 + pos);
  GNUNET_GC_set_configuration_value_number (api.cfg, api.ectx, "UDP6", "PORT",
                                            4447 + pos);
  GNUNET_GC_set_configuration_value_number (api.cfg, api.ectx, "HTTP", "PORT",
                                            4448 + pos);
  GNUNET_create_random_hash (&me.hashPubKey);
  plugin = GNUNET_plugin_load (api.ectx, "libgnunettransport_", trans);
  GNUNET_free (trans);
  if (plugin == NULL)
    {
      fprintf (stderr, "Error loading plugin...\n");
      goto cleanup;
    }
  init =
    GNUNET_plugin_resolve_function (plugin, "inittransport_", GNUNET_YES);
  if (init == NULL)
    {
      fprintf (stderr, "Error resolving init method...\n");
      GNUNET_plugin_unload (plugin);
      goto cleanup;
    }
  api.cron = GNUNET_cron_create (api.ectx);
  api.my_identity = &me;
  api.receive = &receive;
  api.service_request = &request_service;
  api.service_release = NULL;   /* not needed */
  api.tsession_assert_unused = &connection_assert_tsession_unused;
  GNUNET_cron_start (api.cron);
  res = GNUNET_OK;
  transport = init (&api);
  if (transport == NULL)
    {
      fprintf (stderr, "Error initializing plugin...\n");
      GNUNET_plugin_unload (plugin);
      goto cleanup;
    }
  transport->server_start ();
  GNUNET_GE_ASSERT (NULL, (transport->mtu >= expectedSize)
                    || (transport->mtu == 0));
  GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);  /* give other process time to start */
  if (pid == 0)
    {
      /* server - wait for requests */
      GNUNET_shutdown_wait_for ();
    }
  else
    {
      for (xround = 0; xround < XROUNDS; xround++)
        {
          fprintf (stderr, ".");
          /* client - initiate requests */
          hello = transport->hello_create ();
          /* HACK hello -- change port! */
          ((HostAddress *) & hello[1])->port =
            htons (ntohs (((HostAddress *) & hello[1])->port) + OFFSET);
          if (GNUNET_OK != transport->connect (hello, &tsession, GNUNET_NO))
            {
              GNUNET_free (hello);
              transport->server_stop ();
              GNUNET_plugin_unload (plugin);
              goto cleanup;
            }
          GNUNET_free (hello);
          pos = 0;
          while (pos < ROUNDS)
            {
              if (GNUNET_OK == transport->send (tsession,
                                                expectedValue,
                                                expectedSize,
                                                pos >
                                                ROUNDS /
                                                2 ? GNUNET_YES : GNUNET_NO))
                pos++;
            }
          pos = 0;
          while ((pos++ < 100) && (msg_count < ROUNDS * (xround + 1)))
            GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
          if (msg_count < ROUNDS * (xround + 1))
            {
              if (NULL == strstr (argv[0], "udp"))
                res = GNUNET_SYSERR;
              else
                fprintf (stderr,
                         "WARNING: only %u/%u messages received (maybe ok, try again?)\n",
                         msg_count, ROUNDS);
            }
          transport->disconnect (tsession);
          if ((xround % 3) == 0)
            {
              transport->server_stop ();
              transport->server_start ();
            }
        }
      fprintf (stderr, "\n");
    }

  transport->server_stop ();
  done = GNUNET_plugin_resolve_function (plugin, "donetransport_", GNUNET_NO);
  if (done != NULL)
    done ();
  if (pid != 0)
    {
      PLIBC_KILL (pid, SIGTERM);
      waitpid (pid, &pos, 0);
      if (WEXITSTATUS (pos) != 0)
        res = GNUNET_SYSERR;
    }
  GNUNET_plugin_unload (plugin);
  GNUNET_cron_stop (api.cron);
  GNUNET_cron_destroy (api.cron);
  GNUNET_fini (api.ectx, api.cfg);
  GNUNET_free (expectedValue);
  if (error_count > 0)
    res = GNUNET_SYSERR;
  if (res != GNUNET_OK)
    {
      fprintf (stderr,
               "Test failed (%u/%u %s)!\n",
               msg_count, ROUNDS * XROUNDS,
               pid == 0 ? "messages" : "replies");
      return 2;
    }
  return 0;

cleanup:
  GNUNET_fini (api.ectx, api.cfg);
  if (pid != 0)
    {
      PLIBC_KILL (pid, SIGTERM);
      waitpid (pid, &res, 0);
    }
  GNUNET_free (expectedValue);
  return 1;
}


/* end of test_repeat.c */
