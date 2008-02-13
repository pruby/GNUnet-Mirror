/*
     This file is part of GNUnet.
     (C) 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/testing/testingtest.c
 * @brief testcase for testing library
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_identity_lib.h"
#include "gnunet_util.h"
#include "gnunet_testing_lib.h"

#define VERBOSE GNUNET_NO

static void
updatePort (struct GNUNET_GC_Configuration *cfg,
            const char *section, unsigned short offset)
{
  unsigned long long old;

  if ((GNUNET_YES == GNUNET_GC_have_configuration_value (cfg,
                                                         section,
                                                         "PORT")) &&
      (0 == GNUNET_GC_get_configuration_value_number (cfg,
                                                      section,
                                                      "PORT",
                                                      0, 65535, 65535, &old)))
    {
      old += offset;
      GNUNET_GE_ASSERT (NULL,
                        0 == GNUNET_GC_set_configuration_value_number (cfg,
                                                                       NULL,
                                                                       section,
                                                                       "PORT",
                                                                       old));
    }
}

/**
 * Starts a gnunet daemon.
 *
 * @param app_port port to listen on for local clients
 * @param tra_offset offset to add to transport ports
 * @param gnunetd_home directory to use for the home directory
 * @param transports transport services that should be loaded
 * @param applications application services that should be loaded
 * @param pid of the process (set)
 * @param peer identity of the peer (set)
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_TESTING_start_daemon (unsigned short app_port,
                             unsigned short tra_offset,
                             const char *gnunetd_home,
                             const char *transports,
                             const char *applications,
                             pid_t * pid,
                             GNUNET_PeerIdentity * peer, char **configFile)
{
  int ret;
  char *ipath;
  char *dpath;
  struct GNUNET_GC_Configuration *cfg;
  char host[128];
  struct GNUNET_ClientServerConnection *sock;
  GNUNET_MessageHello *hello;
  int round;

  fprintf (stderr, "Starting peer on port %u\n", app_port);
#if 0
  /* do not usually do this -- may easily
     exhaust entropy pool for hostkey generation... */
  GNUNET_disk_directory_remove (NULL, gnunetd_home);
#endif
  ipath = GNUNET_get_installation_path (GNUNET_IPK_DATADIR);
  if (ipath == NULL)
    return GNUNET_SYSERR;
  dpath = GNUNET_malloc (strlen (ipath) + 128);
  strcpy (dpath, ipath);
  GNUNET_free (ipath);
  strcat (dpath, DIR_SEPARATOR_STR "gnunet-testing.conf");
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, dpath))
    {
      fprintf (stderr,
               "Failed to read default configuration file `%s'\n", dpath);
      GNUNET_GC_free (cfg);
      GNUNET_free (dpath);
      return GNUNET_SYSERR;
    }
  GNUNET_free (dpath);
  updatePort (cfg, "TCP", tra_offset);
  updatePort (cfg, "TCP6", tra_offset);
  updatePort (cfg, "UDP", tra_offset);
  updatePort (cfg, "UDP6", tra_offset);
  updatePort (cfg, "HTTP", tra_offset);
  updatePort (cfg, "SMTP", tra_offset);
  GNUNET_GC_set_configuration_value_string (cfg,
                                            NULL,
                                            "PATHS", "GNUNETD_HOME",
                                            gnunetd_home);
  if (transports != NULL)
    GNUNET_GC_set_configuration_value_string (cfg,
                                              NULL,
                                              "GNUNETD", "TRANSPORTS",
                                              transports);
  if (applications != NULL)
    GNUNET_GC_set_configuration_value_string (cfg,
                                              NULL,
                                              "GNUNETD",
                                              "APPLICATIONS", applications);
  GNUNET_GC_set_configuration_value_number (cfg, NULL, "NETWORK", "PORT",
                                            app_port);
  dpath = GNUNET_strdup ("/tmp/gnunet-config.XXXXXX");
  ret = mkstemp (dpath);
  if (ret == -1)
    {
      GNUNET_GE_LOG_STRERROR_FILE (NULL,
                                   GNUNET_GE_ERROR | GNUNET_GE_USER |
                                   GNUNET_GE_BULK, "mkstemp", dpath);
      GNUNET_free (dpath);
      GNUNET_GC_free (cfg);
      return GNUNET_SYSERR;
    }
  CLOSE (ret);
  if (0 != GNUNET_GC_write_configuration (cfg, dpath))
    {
      fprintf (stderr,
               "Failed to write peer configuration file `%s'\n", dpath);
      GNUNET_free (dpath);
      GNUNET_GC_free (cfg);
      return GNUNET_SYSERR;
    }
  GNUNET_GC_free (cfg);

  cfg = GNUNET_GC_create ();
  /* cfg is now client CFG for GNUNET_daemon_start */
  GNUNET_snprintf (host, 128, "localhost:%u", app_port);
  GNUNET_GC_set_configuration_value_string (cfg, NULL, "NETWORK", "HOST",
                                            host);

  ret = GNUNET_daemon_start (NULL, cfg, dpath, GNUNET_NO);
  if (ret == -1)
    {
      fprintf (stderr, "Failed to start daemon!\n");
      GNUNET_GC_free (cfg);
      return GNUNET_SYSERR;
    }
  *pid = ret;

  /* now get peer ID */
  /* we need to wait quite a while since the peers
     maybe creating public keys and waiting for
     entropy! */
  if (GNUNET_OK !=
      GNUNET_wait_for_daemon_running (NULL, cfg, 15 * GNUNET_CRON_MINUTES))
    {
      fprintf (stderr, "Failed to confirm daemon running!\n");
      GNUNET_GC_free (cfg);
      UNLINK (dpath);
      GNUNET_free (dpath);
      return GNUNET_SYSERR;
    }
  *configFile = dpath;
  dpath = NULL;
  round = 0;
  ret = GNUNET_SYSERR;
  while ((round++ < 10) && (ret == GNUNET_SYSERR))
    {
      sock = GNUNET_client_connection_create (NULL, cfg);
      ret = GNUNET_IDENTITY_get_self (sock, &hello);
      if (ret == GNUNET_OK)
        {
          GNUNET_hash (&hello->publicKey, sizeof (GNUNET_RSA_PublicKey),
                       &peer->hashPubKey);
          GNUNET_free (hello);
        }
      else
        {
          GNUNET_thread_sleep (2 * GNUNET_CRON_SECONDS);
        }
      GNUNET_client_connection_destroy (sock);
    }
  GNUNET_GC_free (cfg);
  if (ret == GNUNET_SYSERR)
    fprintf (stderr,
             "Failed to obtain daemon's identity (is a transport loaded?)!\n");


  return ret;
}

#if VERBOSE
static int
printInfo (void *data,
           const GNUNET_PeerIdentity *
           identity,
           const void *address,
           unsigned int addr_len,
           GNUNET_CronTime last_message,
           unsigned int trust, unsigned int bpmFromPeer)
{
  GNUNET_EncName oth;
  GNUNET_hash_to_enc (&identity->hashPubKey, &oth);
  fprintf (stderr,
           "%s: %llu - %u\n", (const char *) &oth, last_message, bpmFromPeer);
  return GNUNET_OK;
}
#endif

/**
 * Establish a connection between two GNUnet daemons
 * (both must run on this machine).
 *
 * @param port1 client port of the first daemon
 * @param port2 client port of the second daemon
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_TESTING_connect_daemons (unsigned short port1, unsigned short port2)
{
  char host[128];
  struct GNUNET_GC_Configuration *cfg1 = GNUNET_GC_create ();
  struct GNUNET_GC_Configuration *cfg2 = GNUNET_GC_create ();
  struct GNUNET_ClientServerConnection *sock1;
  struct GNUNET_ClientServerConnection *sock2;
  int ret;
  GNUNET_MessageHello *h1;
  GNUNET_MessageHello *h2;

  ret = GNUNET_SYSERR;
  GNUNET_snprintf (host, 128, "localhost:%u", port1);
  GNUNET_GC_set_configuration_value_string (cfg1, NULL, "NETWORK", "HOST",
                                            host);
  GNUNET_snprintf (host, 128, "localhost:%u", port2);
  GNUNET_GC_set_configuration_value_string (cfg2, NULL, "NETWORK", "HOST",
                                            host);
  if ((GNUNET_OK ==
       GNUNET_wait_for_daemon_running (NULL, cfg1, 300 * GNUNET_CRON_SECONDS))
      && (GNUNET_OK ==
          GNUNET_wait_for_daemon_running (NULL, cfg2,
                                          300 * GNUNET_CRON_SECONDS)))
    {
      sock1 = GNUNET_client_connection_create (NULL, cfg1);
      sock2 = GNUNET_client_connection_create (NULL, cfg2);
      ret = -20;
      fprintf (stderr, _("Waiting for peers to connect"));
      while ((ret++ < -1) && (GNUNET_shutdown_test () == GNUNET_NO))
        {
          h1 = NULL;
          h2 = NULL;
          if ((GNUNET_OK == GNUNET_IDENTITY_get_self (sock1,
                                                      &h1)) &&
              (GNUNET_OK == GNUNET_IDENTITY_get_self (sock2,
                                                      &h2)) &&
              (GNUNET_OK == GNUNET_IDENTITY_peer_add (sock1,
                                                      h2)) &&
              (GNUNET_OK == GNUNET_IDENTITY_peer_add (sock2, h1)))
            {
              fprintf (stderr, ".");
              if (GNUNET_YES == GNUNET_IDENTITY_request_connect (sock1,
                                                                 &h2->
                                                                 senderIdentity))
                {
                  ret = GNUNET_OK;
                  GNUNET_free_non_null (h1);
                  GNUNET_free_non_null (h2);
                  break;
                }
              if (GNUNET_YES == GNUNET_IDENTITY_request_connect (sock2,
                                                                 &h1->
                                                                 senderIdentity))
                {
                  ret = GNUNET_OK;
                  GNUNET_free_non_null (h1);
                  GNUNET_free_non_null (h2);
                  break;
                }
              GNUNET_thread_sleep (100 * GNUNET_CRON_MILLISECONDS);
            }
          GNUNET_free_non_null (h1);
          GNUNET_free_non_null (h2);
        }
      if (ret != GNUNET_OK)
        {
#if VERBOSE
          GNUNET_EncName e1;
          GNUNET_EncName e2;
          GNUNET_hash_to_enc (&h1->senderIdentity.hashPubKey, &e1);
          GNUNET_hash_to_enc (&h2->senderIdentity.hashPubKey, &e2);
          fprintf (stderr,
                   "\nFailed to connect `%s' and `%s'\n",
                   (const char *) &e1, (const char *) &e2);
          fprintf (stderr, "Connections of `%s':\n", (const char *) &e1);
          GNUNET_IDENTITY_request_peer_infos (sock1, &printInfo, NULL);
          fprintf (stderr, "Connections of `%s':\n", (const char *) &e2);
          GNUNET_IDENTITY_request_peer_infos (sock2, &printInfo, NULL);
#endif
        }
      fprintf (stderr, "%s\n", ret == GNUNET_OK ? "!" : "?");
      GNUNET_client_connection_destroy (sock1);
      GNUNET_client_connection_destroy (sock2);
    }
  else
    {
      fprintf (stderr, "Failed to establish connection with peers.\n");
    }
  GNUNET_GC_free (cfg1);
  GNUNET_GC_free (cfg2);
  return ret;
}


/**
 * Shutdown the GNUnet daemon waiting on the given port
 * and running under the given pid.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_TESTING_stop_daemon (unsigned short port, pid_t pid)
{
  if (GNUNET_daemon_stop (NULL, pid) != GNUNET_YES)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

/**
 * Start count gnunetd processes with the same set of
 * transports and applications.  The port numbers will
 * be computed by adding "delta" each time (zero
 * times for the first peer).
 *
 * @return handle used to stop the daemons, NULL on error
 */
struct GNUNET_TESTING_DaemonContext *
GNUNET_TESTING_start_daemons (const char *transports,
                              const char *applications,
                              const char *gnunetd_home_prefix,
                              unsigned short app_baseport,
                              unsigned short delta, unsigned int count)
{
  struct GNUNET_TESTING_DaemonContext *ret;
  struct GNUNET_TESTING_DaemonContext *nxt;
  unsigned int pos;
  char *home;
  size_t max;
  pid_t pid;
  GNUNET_PeerIdentity peer;
  char *cf;

  ret = NULL;
  max = strlen (gnunetd_home_prefix) + 14;
  home = GNUNET_malloc (max);
  for (pos = 0; pos < count; pos++)
    {
      GNUNET_snprintf (home, max, "%s.%u", gnunetd_home_prefix, pos);
      if (GNUNET_OK !=
          GNUNET_TESTING_start_daemon (app_baseport + pos * delta,
                                       delta * pos, home, transports,
                                       applications, &pid, &peer, &cf))
        {
          GNUNET_TESTING_stop_daemons (ret);
          ret = NULL;
          break;
        }
      nxt = GNUNET_malloc (sizeof (struct GNUNET_TESTING_DaemonContext));
      nxt->next = ret;
      nxt->pid = pid;
      nxt->peer = peer;
      nxt->configFile = cf;
      nxt->port = app_baseport + pos * delta;
      ret = nxt;
    }
  GNUNET_free (home);
  return ret;
}

int
GNUNET_TESTING_stop_daemons (struct GNUNET_TESTING_DaemonContext *peers)
{
  struct GNUNET_TESTING_DaemonContext *next;
  int ret;

  ret = GNUNET_OK;
  while (peers != NULL)
    {
      next = peers->next;
      if (GNUNET_OK != GNUNET_TESTING_stop_daemon (peers->port, peers->pid))
        ret = GNUNET_SYSERR;
      UNLINK (peers->configFile);
      GNUNET_free (peers->configFile);
      GNUNET_free (peers);
      peers = next;
    }
  return ret;
}



/* end of testing.c */
