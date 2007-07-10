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
#include "gnunet_protocols.h"
#include "gnunet_util_network_client.h"
#include "gnunet_util_boot.h"
#include "gnunet_util_crypto.h"
#include "tracekit.h"

static struct SEMAPHORE *doneSem;

static char *cfgFilename;

static struct GE_Context *ectx;

static struct GC_Configuration *cfg;

/**
 * All gnunet-tracekit command line options
 */
static struct CommandLineOption gnunettracekitOptions[] = {
  COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),  /* -c */
  {'D', "depth", "DEPTH",
   gettext_noop ("probe network to the given DEPTH"), 1,
   &gnunet_getopt_configure_set_option, "GNUNET-TRACEKIT:HOPS"},
  {'F', "format", "FORMAT",
   gettext_noop
   ("specify output format; 0 for human readable output, 1 for dot, 2 for vcg"),
   1,
   &gnunet_getopt_configure_set_option, "GNUNET-TRACEKIT:FORMAT"},
  COMMAND_LINE_OPTION_HELP (gettext_noop ("Start GNUnet transport benchmarking tool.")),        /* -h */
  COMMAND_LINE_OPTION_HOSTNAME, /* -H */
  COMMAND_LINE_OPTION_LOGGING,  /* -L */
  {'P', "priority", "PRIO",
   gettext_noop ("use PRIO for the priority of the trace request"), 1,
   &gnunet_getopt_configure_set_option, "GNUNET-TRACEKIT:PRIORITY"},
  COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION),        /* -v */
  {'W', "wait", "DELAY",
   gettext_noop ("wait DELAY seconds for replies"), 1,
   &gnunet_getopt_configure_set_option, "GNUNET-TRACEKIT:WAIT"},
  COMMAND_LINE_OPTION_END,
};

static unsigned int
getConfigurationInt (const char *sec, const char *opt, unsigned int max)
{
  unsigned long long val;

  GC_get_configuration_value_number (cfg, sec, opt, 0, max, 0, &val);
  return (unsigned int) val;
}

static void
run_shutdown (void *unused)
{
  GNUNET_SHUTDOWN_INITIATE ();
}

static void *
receiveThread (void *cls)
{
  struct ClientServerConnection *sock = cls;
  CS_tracekit_reply_MESSAGE *buffer;
  unsigned long long format;
  PeerIdentity *peersSeen;
  unsigned int psCount;
  unsigned int psSize;
  PeerIdentity *peersResponding;
  unsigned int prCount;
  unsigned int prSize;
  int i;
  int j;
  int match;

  psCount = 0;
  psSize = 1;
  peersSeen = MALLOC (psSize * sizeof (PeerIdentity));
  prCount = 0;
  prSize = 1;
  peersResponding = MALLOC (prSize * sizeof (PeerIdentity));
  buffer = MALLOC (MAX_BUFFER_SIZE);
  if (-1 ==
      GC_get_configuration_value_number (cfg,
                                         "GNUNET-TRACEKIT",
                                         "FORMAT", 0, 2, 0, &format))
    {
      printf (_("Format specification invalid. "
                "Use 0 for user-readable, 1 for dot, 2 for vcg.\n"));
      SEMAPHORE_UP (doneSem);
      FREE (peersResponding);
      FREE (peersSeen);
      FREE (buffer);
      return NULL;
    }
  if (format == 1)
    printf ("digraph G {\n");
  if (format == 2)
    printf ("graph: {\n");
  while (OK == connection_read (sock, (MESSAGE_HEADER **) & buffer))
    {
      int count;
      EncName enc;

      count =
        ntohs (buffer->header.size) - sizeof (CS_tracekit_reply_MESSAGE);
      if (count < 0)
        {
          GE_BREAK (ectx, 0);
          break;                /* faulty reply */
        }
      hash2enc (&buffer->responderId.hashPubKey, &enc);
      match = NO;
      for (j = 0; j < prCount; j++)
        if (equalsHashCode512 (&buffer->responderId.hashPubKey,
                               &peersResponding[j].hashPubKey))
          match = YES;
      if (match == NO)
        {
          if (prCount == prSize)
            GROW (peersResponding, prSize, prSize * 2);
          memcpy (&peersResponding[prCount++],
                  &buffer->responderId.hashPubKey, sizeof (PeerIdentity));
        }
      count = count / sizeof (PeerIdentity);
      if (ntohs (buffer->header.size) !=
          sizeof (CS_tracekit_reply_MESSAGE) + count * sizeof (PeerIdentity))
        {
          GE_BREAK (ectx, 0);
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
          EncName other;

          for (i = 0; i < count; i++)
            {
              match = NO;
              for (j = 0; j < psCount; j++)
                if (equalsHashCode512
                    (&((CS_tracekit_reply_MESSAGE_GENERIC *) buffer)->
                     peerList[i].hashPubKey, &peersSeen[j].hashPubKey))
                  match = YES;
              if (match == NO)
                {
                  if (psCount == psSize)
                    GROW (peersSeen, psSize, psSize * 2);
                  memcpy (&peersSeen[psCount++],
                          &((CS_tracekit_reply_MESSAGE_GENERIC *) buffer)->
                          peerList[i].hashPubKey, sizeof (PeerIdentity));
                }

              hash2enc (&((CS_tracekit_reply_MESSAGE_GENERIC *) buffer)->
                        peerList[i].hashPubKey, &other);
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
  FREE (buffer);
  for (i = 0; i < psCount; i++)
    {
      EncName enc;

      match = NO;
      for (j = 0; j < prCount; j++)
        if (equalsHashCode512 (&peersResponding[j].hashPubKey,
                               &peersSeen[i].hashPubKey))
          {
            match = YES;
            break;
          }
      if (match == NO)
        {
          hash2enc (&peersSeen[i].hashPubKey, &enc);
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
              hash2enc (&peersSeen[i].hashPubKey, &enc);
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
  SEMAPHORE_UP (doneSem);
  FREE (peersResponding);
  FREE (peersSeen);
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
  struct ClientServerConnection *sock;
  struct PTHREAD *messageReceiveThread;
  void *unused;
  CS_tracekit_probe_MESSAGE probe;
  int sleepTime;
  struct GE_Context *ectx;
  struct CronManager *cron;
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
  sock = client_connection_create (ectx, cfg);
  if (sock == NULL)
    {
      fprintf (stderr, _("Error establishing connection with gnunetd.\n"));
      GNUNET_fini (ectx, cfg);
      return 1;
    }

  doneSem = SEMAPHORE_CREATE (0);
  messageReceiveThread = PTHREAD_CREATE (&receiveThread, sock, 128 * 1024);
  if (messageReceiveThread == NULL)
    GE_DIE_STRERROR (ectx,
                     GE_FATAL | GE_IMMEDIATE | GE_ADMIN, "pthread_create");

  probe.header.size = htons (sizeof (CS_tracekit_probe_MESSAGE));
  probe.header.type = htons (CS_PROTO_tracekit_PROBE);
  probe.hops
    = htonl (getConfigurationInt ("GNUNET-TRACEKIT", "HOPS", 0xFFFFFFFF));
  probe.priority
    = htonl (getConfigurationInt ("GNUNET-TRACEKIT", "PRIORITY", 0xFFFFFFFF));
  if (SYSERR == connection_write (sock, &probe.header))
    {
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("Could not send request to gnunetd.\n"));
      return -1;
    }
  cron = cron_create (ectx);
  cron_start (cron);
  sleepTime = getConfigurationInt ("GNUNET-TRACEKIT", "WAIT", 0xFFFFFFFF);
  if (sleepTime == 0)
    sleepTime = 5;
  cron_add_job (cron, &run_shutdown, cronSECONDS * sleepTime, 0, NULL);
  GNUNET_SHUTDOWN_WAITFOR ();
  connection_close_forever (sock);
  SEMAPHORE_DOWN (doneSem, YES);
  SEMAPHORE_DESTROY (doneSem);
  PTHREAD_JOIN (messageReceiveThread, &unused);
  connection_destroy (sock);
  cron_stop (cron);
  cron_destroy (cron);
  GNUNET_fini (ectx, cfg);
  return 0;
}

/* end of gnunet-tracekit.c */
