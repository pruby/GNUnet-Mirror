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
 * @file transports/test.c
 * @brief Test for the transports.
 * @author Christian Grothoff
 *
 * This utility can be used to test if a transport mechanism for
 * GNUnet is properly configured.
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_util_boot.h"
#include "gnunet_directories.h"
#include "gnunet_protocols.h"
#include "gnunet_transport.h"

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
static TransportAPI *transport;

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
static struct CommandLineOption testOptions[] = {
  COMMAND_LINE_OPTION_END,
};

static void *
requestService (const char *name)
{
  /* we expect only "stats" to be requested... */
  if (0 != strcmp (name, "stats"))
    fprintf (stderr, "Rejecting request for service `%s'\n", name);
  return NULL;
}

static int
assertUnused (TSession * tsession)
{
  return OK;
}

/**
 * We received a message.  The "client" should try to echo it back,
 * the "server" should validate that it got the right reply.
 */
static void
receive (P2P_PACKET * mp)
{
  unsigned int retries;
  TSession *tsession;
  P2P_hello_MESSAGE *hello;

  if (pid == 0)
    {
      /* server; do echo back */
      retries = 0;
      tsession = mp->tsession;
      if (tsession == NULL)
        {
          hello = transport->createhello ();
          /* HACK hello -- change port! */
          ((unsigned short *) &hello[1])[2] =
            htons (ntohs (((unsigned short *) &hello[1])[2]) - OFFSET);
          if (OK != transport->connect (hello, &tsession, NO))
            {
              FREE (hello);
              FREE (mp->msg);
              FREE (mp);
              error_count++;
              return;
            }
          FREE (hello);
        }
      while (NO == transport->send (tsession,
                                    mp->msg,
                                    mp->size, retries > 6 ? YES : NO))
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
  FREE (mp->msg);
  FREE (mp);
}

int
main (int argc, char *const *argv)
{
  CoreAPIForTransport api;
  struct PluginHandle *plugin;
  TransportMainMethod init;
  void (*done) ();
  PeerIdentity me;
  char *trans;
  int res;
  int pos;
  TSession *tsession;
  P2P_hello_MESSAGE *hello;
  int xround;

  memset (&api, 0, sizeof (CoreAPIForTransport));
  pid = fork ();
  res = GNUNET_init (argc,
                     argv,
                     "transport-test",
                     &cfgFilename, testOptions, &api.ectx, &api.cfg);
  if (res == -1)
    goto cleanup;

  expectedValue = MALLOC (expectedSize);
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
  GC_set_configuration_value_string (api.cfg, api.ectx, "TCP", "BLACKLIST",
                                     "");
  GC_set_configuration_value_string (api.cfg, api.ectx, "TCP", "UPNP", "NO");
  GC_set_configuration_value_string (api.cfg, api.ectx, "TCP6", "BLACKLIST",
                                     "");
  GC_set_configuration_value_string (api.cfg, api.ectx, "UDP", "BLACKLIST",
                                     "");
  GC_set_configuration_value_string (api.cfg, api.ectx, "UDP", "UPNP", "NO");
  GC_set_configuration_value_string (api.cfg, api.ectx, "UDP6", "BLACKLIST",
                                     "");
  GC_set_configuration_value_string (api.cfg, api.ectx, "HTTP", "BLACKLIST",
                                     "");
  GC_set_configuration_value_string (api.cfg, api.ectx, "HTTP", "UPNP", "NO");

  if (pid == 0)
    pos = OFFSET;
  else
    pos = 0;
  GC_set_configuration_value_number (api.cfg, api.ectx, "TCP", "PORT",
                                     4444 + pos);
  GC_set_configuration_value_number (api.cfg, api.ectx, "TCP6", "PORT",
                                     4445 + pos);
  GC_set_configuration_value_number (api.cfg, api.ectx, "UDP", "PORT",
                                     4446 + pos);
  GC_set_configuration_value_number (api.cfg, api.ectx, "UDP6", "PORT",
                                     4447 + pos);
  GC_set_configuration_value_number (api.cfg, api.ectx, "HTTP", "PORT",
                                     4448 + pos);
  makeRandomId (&me.hashPubKey);
  plugin = os_plugin_load (api.ectx, "libgnunettransport_", trans);
  FREE (trans);
  if (plugin == NULL)
    {
      fprintf (stderr, "Error loading plugin...\n");
      goto cleanup;
    }
  init = os_plugin_resolve_function (plugin, "inittransport_", YES);
  if (init == NULL)
    {
      fprintf (stderr, "Error resolving init method...\n");
      os_plugin_unload (plugin);
      goto cleanup;
    }
  api.cron = cron_create (api.ectx);
  api.myIdentity = &me;
  api.receive = &receive;
  api.requestService = &requestService;
  api.releaseService = NULL;    /* not needed */
  api.assertUnused = &assertUnused;
  cron_start (api.cron);
  res = OK;
  transport = init (&api);
  if (transport == NULL)
    {
      fprintf (stderr, "Error initializing plugin...\n");
      os_plugin_unload (plugin);
      goto cleanup;
    }
  transport->startTransportServer ();
  GE_ASSERT (NULL, (transport->mtu >= expectedSize) || (transport->mtu == 0));
  PTHREAD_SLEEP (50 * cronMILLIS);      /* give other process time to start */
  if (pid == 0)
    {
      /* server - wait for requests */
      GNUNET_SHUTDOWN_WAITFOR ();
    }
  else
    {
      for (xround = 0; xround < XROUNDS; xround++)
        {
          fprintf (stderr, ".");
          /* client - initiate requests */
          hello = transport->createhello ();
          /* HACK hello -- change port! */
          ((unsigned short *) &hello[1])[2] =
            htons (ntohs (((unsigned short *) &hello[1])[2]) + OFFSET);
          if (OK != transport->connect (hello, &tsession, NO))
            {
              FREE (hello);
              transport->stopTransportServer ();
              os_plugin_unload (plugin);
              goto cleanup;
            }
          FREE (hello);
          pos = 0;
          while (pos < ROUNDS)
            {
              if (OK == transport->send (tsession,
                                         expectedValue,
                                         expectedSize,
                                         pos > ROUNDS / 2 ? YES : NO))
                pos++;
            }
          pos = 0;
          while ((pos++ < 100) && (msg_count < ROUNDS * (xround + 1)))
            PTHREAD_SLEEP (50 * cronMILLIS);
          if (msg_count < ROUNDS * (xround + 1))
            {
              if (NULL == strstr (argv[0], "udp"))
                res = SYSERR;
              else
                fprintf (stderr,
                         "WARNING: only %u/%u messages received (maybe ok, try again?)\n",
                         msg_count, ROUNDS);
            }
          transport->disconnect (tsession);
          if ((xround % 3) == 0)
            {
              transport->stopTransportServer ();
              transport->startTransportServer ();
            }
        }
      fprintf (stderr, "\n");
    }

  transport->stopTransportServer ();
  done = os_plugin_resolve_function (plugin, "donetransport_", NO);
  if (done != NULL)
    done ();
  if (pid != 0)
    {
      kill (pid, SIGTERM);
      waitpid (pid, &pos, 0);
      if (WEXITSTATUS (pos) != 0)
        res = SYSERR;
    }
  os_plugin_unload (plugin);
  cron_stop (api.cron);
  cron_destroy (api.cron);
  GNUNET_fini (api.ectx, api.cfg);
  FREE (expectedValue);
  if (error_count > 0)
    res = SYSERR;
  if (res != OK)
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
      kill (pid, SIGTERM);
      waitpid (pid, &res, 0);
    }
  FREE (expectedValue);
  return 1;
}


/* end of gnunet-transport-check */
