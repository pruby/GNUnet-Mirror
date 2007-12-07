/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/tracekit/gnunet-tracekit.c
 * @brief tool that sends a trace request and prints the received network topology
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_protocols.h"
#include "gnunet_util.h"
#include "tracekit.h"

static struct GNUNET_Semaphore *doneSem;

static char *cfgFilename = GNUNET_DEFAULT_CLIENT_CONFIG_FILE;

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_GC_Configuration *cfg;

/**
 * All gnunet-tracekit command line options
 */
static struct GNUNET_CommandLineOption gnunettracekitOptions[] = {
  GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),   /* -c */
  {'D', "depth", "DEPTH",
   gettext_noop ("probe network to the given DEPTH"), 1,
   &GNUNET_getopt_configure_set_option, "GNUNET-TRACEKIT:HOPS"},
  {'F', "format", "FORMAT",
   gettext_noop
   ("specify output format; 0 for human readable output, 1 for dot, 2 for vcg"),
   1,
   &GNUNET_getopt_configure_set_option, "GNUNET-TRACEKIT:FORMAT"},
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Start GNUnet transport benchmarking tool.")), /* -h */
  GNUNET_COMMAND_LINE_OPTION_HOSTNAME,  /* -H */
  GNUNET_COMMAND_LINE_OPTION_LOGGING,   /* -L */
  {'P', "priority", "PRIO",
   gettext_noop ("use PRIO for the priority of the trace request"), 1,
   &GNUNET_getopt_configure_set_option, "GNUNET-TRACEKIT:PRIORITY"},
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION), /* -v */
  {'W', "wait", "DELAY",
   gettext_noop ("wait DELAY seconds for replies"), 1,
   &GNUNET_getopt_configure_set_option, "GNUNET-TRACEKIT:WAIT"},
  GNUNET_COMMAND_LINE_OPTION_END,
};

static unsigned int
getConfigurationInt (const char *sec, const char *opt, unsigned int max)
{
  unsigned long long val;

  GNUNET_GC_get_configuration_value_number (cfg, sec, opt, 0, max, 0, &val);
  return (unsigned int) val;
}

static void
run_shutdown (void *unused)
{
  GNUNET_shutdown_initiate ();
}

static void *
receiveThread (void *cls)
{
  struct GNUNET_ClientServerConnection *sock = cls;
  CS_tracekit_reply_MESSAGE *buffer;
  unsigned long long format;
  GNUNET_PeerIdentity *peersSeen;
  unsigned int psCount;
  unsigned int psSize;
  GNUNET_PeerIdentity *peersResponding;
  unsigned int prCount;
  unsigned int prSize;
  int i;
  int j;
  int match;

  psCount = 0;
  psSize = 1;
  peersSeen = GNUNET_malloc (psSize * sizeof (GNUNET_PeerIdentity));
  prCount = 0;
  prSize = 1;
  peersResponding = GNUNET_malloc (prSize * sizeof (GNUNET_PeerIdentity));
  buffer = GNUNET_malloc (GNUNET_MAX_BUFFER_SIZE);
  if (-1 ==
      GNUNET_GC_get_configuration_value_number (cfg,
                                                "GNUNET-TRACEKIT",
                                                "FORMAT", 0, 2, 0, &format))
    {
      printf (_("Format specification invalid. "
                "Use 0 for user-readable, 1 for dot, 2 for vcg.\n"));
      GNUNET_semaphore_up (doneSem);
      GNUNET_free (peersResponding);
      GNUNET_free (peersSeen);
      GNUNET_free (buffer);
      return NULL;
    }
  if (format == 1)
    printf ("digraph G {\n");
  if (format == 2)
    printf ("graph: {\n");
  while (GNUNET_OK ==
         GNUNET_client_connection_read (sock,
                                        (GNUNET_MessageHeader **) & buffer))
    {
      int count;
      GNUNET_EncName enc;

      count =
        ntohs (buffer->header.size) - sizeof (CS_tracekit_reply_MESSAGE);
      if (count < 0)
        {
          GNUNET_GE_BREAK (ectx, 0);
          break;                /* faulty reply */
        }
      GNUNET_hash_to_enc (&buffer->responderId.hashPubKey, &enc);
      match = GNUNET_NO;
      for (j = 0; j < prCount; j++)
        if (0 == memcmp (&buffer->responderId.hashPubKey,
                         &peersResponding[j].hashPubKey,
                         sizeof (GNUNET_HashCode)))
          match = GNUNET_YES;
      if (match == GNUNET_NO)
        {
          if (prCount == prSize)
            GNUNET_array_grow (peersResponding, prSize, prSize * 2);
          memcpy (&peersResponding[prCount++],
                  &buffer->responderId.hashPubKey,
                  sizeof (GNUNET_PeerIdentity));
        }
      count = count / sizeof (GNUNET_PeerIdentity);
      if (ntohs (buffer->header.size) !=
          sizeof (CS_tracekit_reply_MESSAGE) +
          count * sizeof (GNUNET_PeerIdentity))
        {
          GNUNET_GE_BREAK (ectx, 0);
          break;
        }
      if (count == 0)
        {
          switch (format)
            {
            case 0:
              printf (_("`%s' is not connected to any peer.\n"),
                      (char *) &enc);
              break;
            case 1:
              printf ("  %.*s;\n", 4, (char *) &enc);
              break;
            case 2:
              /* deferred -- vcg needs all node data in one line */
              break;
            }
        }
      else
        {
          GNUNET_EncName other;

          for (i = 0; i < count; i++)
            {
              match = GNUNET_NO;
              for (j = 0; j < psCount; j++)
                if (0 ==
                    memcmp (&
                            ((CS_tracekit_reply_MESSAGNUNET_GE_GENERIC *)
                             buffer)->peerList[i].hashPubKey,
                            &peersSeen[j].hashPubKey,
                            sizeof (GNUNET_HashCode)))
                  match = GNUNET_YES;
              if (match == GNUNET_NO)
                {
                  if (psCount == psSize)
                    GNUNET_array_grow (peersSeen, psSize, psSize * 2);
                  memcpy (&peersSeen[psCount++],
                          &((CS_tracekit_reply_MESSAGNUNET_GE_GENERIC *)
                            buffer)->peerList[i].hashPubKey,
                          sizeof (GNUNET_PeerIdentity));
                }

              GNUNET_hash_to_enc (&
                                  ((CS_tracekit_reply_MESSAGNUNET_GE_GENERIC
                                    *) buffer)->peerList[i].hashPubKey,
                                  &other);
              switch (format)
                {
                case 0:
                  printf (_("`%s' connected to `%s'.\n"),
                          (char *) &enc, (char *) &other);
                  break;
                case 1:        /* dot */
                  printf ("  \"%.*s\" -> \"%.*s\";\n",
                          4, (char *) &enc, 4, (char *) &other);
                  break;
                case 2:        /* vcg */
                  printf
                    ("\tedge: { sourcename: \"%s\" targetname: \"%s\" }\n",
                     (char *) &enc, (char *) &other);
                  break;
                default:       /* undef */
                  printf (_("Format specification invalid. "
                            "Use 0 for user-readable, 1 for dot\n"));
                  break;
                }
            }
        }
    }
  GNUNET_free (buffer);
  for (i = 0; i < psCount; i++)
    {
      GNUNET_EncName enc;

      match = GNUNET_NO;
      for (j = 0; j < prCount; j++)
        if (0 == memcmp (&peersResponding[j].hashPubKey,
                         &peersSeen[i].hashPubKey, sizeof (GNUNET_HashCode)))
          {
            match = GNUNET_YES;
            break;
          }
      if (match == GNUNET_NO)
        {
          GNUNET_hash_to_enc (&peersSeen[i].hashPubKey, &enc);
          switch (format)
            {
            case 0:
              printf (_("Peer `%s' did not report back.\n"), (char *) &enc);
              break;
            case 1:
              printf ("  \"%.*s\" [style=filled,color=\".7 .3 1.0\"];\n",
                      4, (char *) &enc);
              break;
            case 2:
              printf
                ("\tnode: { title: \"%s\" label: \"%.*s\" shape: \"ellipse\" }\n",
                 (char *) &enc, 4, (char *) &enc);
              break;
            default:
              break;
            }
        }
      else
        {
          switch (format)
            {
            case 2:
              GNUNET_hash_to_enc (&peersSeen[i].hashPubKey, &enc);
              printf ("\tnode: { title: \"%s\" label: \"%.*s\" }\n",
                      (char *) &enc, 4, (char *) &enc);
              break;
            default:
              break;
            }
        }
    }
  if (psCount == 0)
    {
      switch (format)
        {
        case 2:
          printf ("\tnode: { title: \"NO CONNECTIONS\" }\n");
          break;
        default:
          break;
        }
    }
  if (format == 1)
    printf ("}\n");
  if (format == 2)
    printf ("}\n");
  GNUNET_semaphore_up (doneSem);
  GNUNET_free (peersResponding);
  GNUNET_free (peersSeen);
  return NULL;
}

/**
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return value from gnunet-tracekit: 0: ok, -1: error
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_ClientServerConnection *sock;
  struct GNUNET_ThreadHandle *messageReceiveThread;
  void *unused;
  CS_tracekit_probe_MESSAGE probe;
  int sleepTime;
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_CronManager *cron;
  int res;

  res = GNUNET_init (argc,
                     argv,
                     "gnunet-tracekit",
                     &cfgFilename, gnunettracekitOptions, &ectx, &cfg);
  if (res == -1)
    {
      GNUNET_fini (ectx, cfg);
      return -1;
    }
  sock = GNUNET_client_connection_create (ectx, cfg);
  if (sock == NULL)
    {
      fprintf (stderr, _("Error establishing connection with gnunetd.\n"));
      GNUNET_fini (ectx, cfg);
      return 1;
    }

  doneSem = GNUNET_semaphore_create (0);
  messageReceiveThread =
    GNUNET_thread_create (&receiveThread, sock, 128 * 1024);
  if (messageReceiveThread == NULL)
    GNUNET_GE_DIE_STRERROR (ectx,
                            GNUNET_GE_FATAL | GNUNET_GE_IMMEDIATE |
                            GNUNET_GE_ADMIN, "pthread_create");

  probe.header.size = htons (sizeof (CS_tracekit_probe_MESSAGE));
  probe.header.type = htons (GNUNET_CS_PROTO_TRACEKIT_PROBE);
  probe.hops
    = htonl (getConfigurationInt ("GNUNET-TRACEKIT", "HOPS", 0xFFFFFFFF));
  probe.priority
    = htonl (getConfigurationInt ("GNUNET-TRACEKIT", "PRIORITY", 0xFFFFFFFF));
  if (GNUNET_SYSERR == GNUNET_client_connection_write (sock, &probe.header))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Could not send request to gnunetd.\n"));
      return -1;
    }
  cron = cron_create (ectx);
  GNUNET_cron_start (cron);
  sleepTime = getConfigurationInt ("GNUNET-TRACEKIT", "WAIT", 0xFFFFFFFF);
  if (sleepTime == 0)
    sleepTime = 5;
  GNUNET_cron_add_job (cron, &run_shutdown, GNUNET_CRON_SECONDS * sleepTime,
                       0, NULL);
  GNUNET_shutdown_wait_for ();
  GNUNET_client_connection_close_forever (sock);
  GNUNET_semaphore_down (doneSem, GNUNET_YES);
  GNUNET_semaphore_destroy (doneSem);
  GNUNET_thread_join (messageReceiveThread, &unused);
  GNUNET_client_connection_destroy (sock);
  GNUNET_cron_stop (cron);
  GNUNET_cron_destroy (cron);
  GNUNET_fini (ectx, cfg);
  return 0;
}

/* end of gnunet-tracekit.c */
