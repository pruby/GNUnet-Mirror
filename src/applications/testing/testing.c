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
 * @file applications/testing/testingtest.c
 * @brief testcase for testing library
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_identity_lib.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_testing_lib.h"

static void
updatePort (struct GC_Configuration *cfg,
            const char *section, unsigned short offset)
{
  unsigned long long old;

  if ((YES == GC_have_configuration_value (cfg,
                                           section,
                                           "PORT")) &&
      (0 == GC_get_configuration_value_number (cfg,
                                               section,
                                               "PORT",
                                               0, 65535, 65535, &old)))
    {
      old += offset;
      GE_ASSERT (NULL,
                 0 == GC_set_configuration_value_number (cfg,
                                                         NULL,
                                                         section,
                                                         "PORT", old));
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
 * @return OK on success, SYSERR on error
 */
int
gnunet_testing_start_daemon (unsigned short app_port,
                             unsigned short tra_offset,
                             const char *gnunetd_home,
                             const char *transports,
                             const char *applications,
                             pid_t * pid,
                             PeerIdentity * peer, char **configFile)
{
  int ret;
  char *ipath;
  char *dpath;
  struct GC_Configuration *cfg;
  char host[128];
  struct ClientServerConnection *sock;
  P2P_hello_MESSAGE *hello;
  int round;

  fprintf (stderr, "Starting peer on port %u\n", app_port);
#if 0
  /* do not usually do this -- may easily
     exhaust entropy pool for hostkey generation... */
  disk_directory_remove (NULL, gnunetd_home);
#endif
  ipath = os_get_installation_path (IPK_DATADIR);
  if (ipath == NULL)
    return SYSERR;
  dpath = MALLOC (strlen (ipath) + 128);
  strcpy (dpath, ipath);
  FREE (ipath);
  strcat (dpath, DIR_SEPARATOR_STR "gnunet-testing.conf");
  cfg = GC_create_C_impl ();
  if (-1 == GC_parse_configuration (cfg, dpath))
    {
      fprintf (stderr,
               "Failed to read default configuration file `%s'\n", dpath);
      GC_free (cfg);
      FREE (dpath);
      return SYSERR;
    }
  FREE (dpath);
  updatePort (cfg, "TCP", tra_offset);
  updatePort (cfg, "TCP6", tra_offset);
  updatePort (cfg, "UDP", tra_offset);
  updatePort (cfg, "UDP6", tra_offset);
  updatePort (cfg, "HTTP", tra_offset);
  updatePort (cfg, "SMTP", tra_offset);
  GC_set_configuration_value_string (cfg,
                                     NULL,
                                     "PATHS", "GNUNETD_HOME", gnunetd_home);
  if (transports != NULL)
    GC_set_configuration_value_string (cfg,
                                       NULL,
                                       "GNUNETD", "TRANSPORTS", transports);
  if (applications != NULL)
    GC_set_configuration_value_string (cfg,
                                       NULL,
                                       "GNUNETD",
                                       "APPLICATIONS", applications);
  GC_set_configuration_value_number (cfg, NULL, "NETWORK", "PORT", app_port);
  dpath = STRDUP ("/tmp/gnunet-config.XXXXXX");
  ret = mkstemp (dpath);
  if (ret == -1)
    {
      GE_LOG_STRERROR_FILE (NULL,
                            GE_ERROR | GE_USER | GE_BULK, "mkstemp", dpath);
      FREE (dpath);
      GC_free (cfg);
      return SYSERR;
    }
  CLOSE (ret);
  if (0 != GC_write_configuration (cfg, dpath))
    {
      fprintf (stderr,
               "Failed to write peer configuration file `%s'\n", dpath);
      FREE (dpath);
      GC_free (cfg);
      return SYSERR;
    }
  GC_free (cfg);

  cfg = GC_create_C_impl ();
  /* cfg is now client CFG for os_daemon_start */
  SNPRINTF (host, 128, "localhost:%u", app_port);
  GC_set_configuration_value_string (cfg, NULL, "NETWORK", "HOST", host);

  ret = os_daemon_start (NULL, cfg, dpath, NO);
  if (ret == -1)
    {
      fprintf (stderr, "Failed to start daemon!\n");
      GC_free (cfg);
      return SYSERR;
    }
  *pid = ret;

  /* now get peer ID */
  /* we need to wait quite a while since the peers
     maybe creating public keys and waiting for
     entropy! */
  if (OK != connection_wait_for_running (NULL, cfg, 15 * cronMINUTES))
    {
      fprintf (stderr, "Failed to confirm daemon running!\n");
      GC_free (cfg);
      UNLINK (dpath);
      FREE (dpath);
      return SYSERR;
    }
  *configFile = dpath;
  dpath = NULL;
  round = 0;
  ret = SYSERR;
  while ((round++ < 10) && (ret == SYSERR))
    {
      sock = client_connection_create (NULL, cfg);
      ret = gnunet_identity_get_self (sock, &hello);
      if (ret == OK)
        {
          hash (&hello->publicKey, sizeof (PublicKey), &peer->hashPubKey);
          FREE (hello);
        }
      else
        {
          PTHREAD_SLEEP (2 * cronSECONDS);
        }
      connection_destroy (sock);
    }
  GC_free (cfg);
  if (ret == SYSERR)
    fprintf (stderr,
             "Failed to obtain daemon's identity (is a transport loaded?)!\n");


  return ret;
}

/**
 * Establish a connection between two GNUnet daemons
 * (both must run on this machine).
 *
 * @param port1 client port of the first daemon
 * @param port2 client port of the second daemon
 * @return OK on success, SYSERR on failure
 */
int
gnunet_testing_connect_daemons (unsigned short port1, unsigned short port2)
{
  char host[128];
  GC_Configuration *cfg1 = GC_create_C_impl ();
  GC_Configuration *cfg2 = GC_create_C_impl ();
  struct ClientServerConnection *sock1;
  struct ClientServerConnection *sock2;
  int ret;
  P2P_hello_MESSAGE *h1;
  P2P_hello_MESSAGE *h2;

  ret = SYSERR;
  SNPRINTF (host, 128, "localhost:%u", port1);
  GC_set_configuration_value_string (cfg1, NULL, "NETWORK", "HOST", host);
  SNPRINTF (host, 128, "localhost:%u", port2);
  GC_set_configuration_value_string (cfg2, NULL, "NETWORK", "HOST", host);
  if ((OK == connection_wait_for_running (NULL,
                                          cfg1,
                                          300 * cronSECONDS)) &&
      (OK == connection_wait_for_running (NULL, cfg2, 300 * cronSECONDS)))
    {
      sock1 = client_connection_create (NULL, cfg1);
      sock2 = client_connection_create (NULL, cfg2);
      ret = -10;
      fprintf (stderr, _("Waiting for peers to connect"));
      while ((ret++ < -1) && (GNUNET_SHUTDOWN_TEST () == NO))
        {
          h1 = NULL;
          h2 = NULL;
          if ((OK == gnunet_identity_get_self (sock1,
                                               &h1)) &&
              (OK == gnunet_identity_get_self (sock2,
                                               &h2)) &&
              (OK == gnunet_identity_peer_add (sock1,
                                               h2)) &&
              (OK == gnunet_identity_peer_add (sock2, h1)))
            {
              fprintf (stderr, ".");
              if (YES == gnunet_identity_request_connect (sock1,
                                                          &h2->
                                                          senderIdentity))
                {
                  ret = OK;
                  break;
                }
              if (YES == gnunet_identity_request_connect (sock2,
                                                          &h1->
                                                          senderIdentity))
                {
                  ret = OK;
                  break;
                }
              PTHREAD_SLEEP (100 * cronMILLIS);
            }
          FREENONNULL (h1);
          FREENONNULL (h2);
        }
      fprintf (stderr, "%s\n", ret == OK ? "!" : "?");
      connection_destroy (sock1);
      connection_destroy (sock2);
    }
  else
    {
      fprintf (stderr, "Failed to establish connection with peers.\n");
    }
  GC_free (cfg1);
  GC_free (cfg2);
  return ret;
}


/**
 * Shutdown the GNUnet daemon waiting on the given port
 * and running under the given pid.
 *
 * @return OK on success, SYSERR on failure
 */
int
gnunet_testing_stop_daemon (unsigned short port, pid_t pid)
{
  if (os_daemon_stop (NULL, pid) != YES)
    return SYSERR;
  return OK;
}

/**
 * Start count gnunetd processes with the same set of
 * transports and applications.  The port numbers will
 * be computed by adding "delta" each time (zero
 * times for the first peer).
 *
 * @return handle used to stop the daemons, NULL on error
 */
struct DaemonContext *
gnunet_testing_start_daemons (const char *transports,
                              const char *applications,
                              const char *gnunetd_home_prefix,
                              unsigned short app_baseport,
                              unsigned short delta, unsigned int count)
{
  struct DaemonContext *ret;
  struct DaemonContext *nxt;
  unsigned int pos;
  char *home;
  size_t max;
  pid_t pid;
  PeerIdentity peer;
  char *cf;

  ret = NULL;
  max = strlen (gnunetd_home_prefix) + 14;
  home = MALLOC (max);
  for (pos = 0; pos < count; pos++)
    {
      SNPRINTF (home, max, "%s.%u", gnunetd_home_prefix, pos);
      if (OK != gnunet_testing_start_daemon (app_baseport + pos * delta,
                                             delta * pos,
                                             home,
                                             transports,
                                             applications, &pid, &peer, &cf))
        {
          gnunet_testing_stop_daemons (ret);
          ret = NULL;
          break;
        }
      nxt = MALLOC (sizeof (struct DaemonContext));
      nxt->next = ret;
      nxt->pid = pid;
      nxt->peer = peer;
      nxt->configFile = cf;
      nxt->port = app_baseport + pos * delta;
      ret = nxt;
    }
  FREE (home);
  return ret;
}

int
gnunet_testing_stop_daemons (struct DaemonContext *peers)
{
  struct DaemonContext *next;
  int ret;

  ret = OK;
  while (peers != NULL)
    {
      next = peers->next;
      if (OK != gnunet_testing_stop_daemon (peers->port, peers->pid))
        ret = SYSERR;
      UNLINK (peers->configFile);
      FREE (peers->configFile);
      FREE (peers);
      peers = next;
    }
  return ret;
}




/* end of testing.c */
