/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2006, 2007 Christian Grothoff (and other contributing authors)

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
#include "gnunet_tracekit_lib.h"
#include "tracekit.h"

struct SeenRecord
{
  GNUNET_PeerIdentity src;
  GNUNET_PeerIdentity dst;
};

static char *cfgFilename = GNUNET_DEFAULT_CLIENT_CONFIG_FILE;

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_GC_Configuration *cfg;

static unsigned int priority = 0;

static unsigned int depth = 5;

static unsigned int format = 0;

static unsigned int delay = 300;

static struct SeenRecord *seen;

static unsigned int count;

static int
check_seen (const GNUNET_PeerIdentity * src, const GNUNET_PeerIdentity * dst)
{
  static GNUNET_PeerIdentity null_peer;
  unsigned int j;

  if (dst == NULL)
    dst = &null_peer;
  for (j = 0; j < count; j++)
    if ((0 == memcmp (src,
                      &seen[j].src,
                      sizeof (GNUNET_HashCode))) &&
        (0 == memcmp (dst, &seen[j].dst, sizeof (GNUNET_HashCode))))
      return GNUNET_YES;
  GNUNET_array_grow (seen, count, count + 1);
  seen[count - 1].src = *src;
  seen[count - 1].dst = *dst;
  return GNUNET_NO;
}

/**
 * Generate a human-readable report.
 *
 * @param reporter identity of the peer reporting a connection
 * @param link identity of another peer that the reporting peer
 *             is reported to be connected to, or NULL if the
 *             peer is reporting to have no connections at all
 * @return GNUNET_OK to continue data gathering,
 *         GNUNET_SYSERR to abort
 */
static int
human_readable (void *unused,
                const GNUNET_PeerIdentity * reporter,
                const GNUNET_PeerIdentity * link)
{
  GNUNET_EncName src;
  GNUNET_EncName dst;

  if (check_seen (reporter, link))
    return GNUNET_OK;

  GNUNET_hash_to_enc (&reporter->hashPubKey, &src);
  if (link != NULL)
    {
      GNUNET_hash_to_enc (&link->hashPubKey, &dst);
      fprintf (stdout,
               _("`%s' connected to `%s'.\n"),
               (const char *) &src, (const char *) &dst);
    }
  else
    {
      fprintf (stdout,
               _("`%s' is not connected to any peer.\n"),
               (const char *) &src);
    }
  return GNUNET_OK;
}

/**
 * Generate dot-format.
 *
 * @param reporter identity of the peer reporting a connection
 * @param link identity of another peer that the reporting peer
 *             is reported to be connected to, or NULL if the
 *             peer is reporting to have no connections at all
 * @return GNUNET_OK to continue data gathering,
 *         GNUNET_SYSERR to abort
 */
static int
dot_format (void *unused,
            const GNUNET_PeerIdentity * reporter,
            const GNUNET_PeerIdentity * link)
{
  GNUNET_EncName src;
  GNUNET_EncName dst;

  if (check_seen (reporter, link))
    return GNUNET_OK;
  GNUNET_hash_to_enc (&reporter->hashPubKey, &src);
  if (link != NULL)
    {
      GNUNET_hash_to_enc (&link->hashPubKey, &dst);
      printf ("  \"%.*s\" -> \"%.*s\";\n",
              4, (char *) &src, 4, (char *) &dst);
    }
  else
    {
      printf ("  %.*s;\n", 4, (char *) &src);
    }

  return GNUNET_OK;
}

/**
 * Generate vcg-format.
 *
 * @param reporter identity of the peer reporting a connection
 * @param link identity of another peer that the reporting peer
 *             is reported to be connected to, or NULL if the
 *             peer is reporting to have no connections at all
 * @return GNUNET_OK to continue data gathering,
 *         GNUNET_SYSERR to abort
 */
static int
vcg_format (void *unused,
            const GNUNET_PeerIdentity * reporter,
            const GNUNET_PeerIdentity * link)
{
  GNUNET_EncName src;
  GNUNET_EncName dst;

  if (check_seen (reporter, link))
    return GNUNET_OK;
  GNUNET_hash_to_enc (&reporter->hashPubKey, &src);
  if (link != NULL)
    {
      GNUNET_hash_to_enc (&link->hashPubKey, &dst);
      printf
        ("\tedge: { sourcename: \"%s\" targetname: \"%s\" }\n",
         (char *) &src, (char *) &dst);
    }
  else
    {
      /* deferred -- vcg needs all node data in one line */
    }
  return GNUNET_OK;
}


static void *
process (void *cls)
{
  static GNUNET_PeerIdentity null_peer;
  GNUNET_PeerIdentity *current;
  struct GNUNET_ClientServerConnection *sock = cls;
  GNUNET_TRACEKIT_ReportCallback report;
  GNUNET_EncName enc;
  unsigned int i;
  unsigned int j;
  int is_source;
  int is_first;

  report = NULL;
  switch (format)
    {
    case 0:
      report = &human_readable;
      break;
    case 1:
      printf ("digraph G {\n");
      report = &dot_format;
      break;
    case 2:
      report = &vcg_format;
      printf ("graph: {\n");
      break;
    default:
      GNUNET_GE_BREAK (NULL, 0);
    }
  GNUNET_TRACEKIT_run (sock, depth, priority, report, NULL);
  /* final processing loop */
  for (i = 0; i < count * 2; i++)
    {
      if (0 == i % 2)
        current = &seen[i / 2].src;
      else
        current = &seen[i / 2].dst;
      if (0 == memcmp (current, &null_peer, sizeof (GNUNET_PeerIdentity)))
        continue;
      is_first = GNUNET_YES;
      for (j = 0; j < count * 2; j++)
        if (0 == memcmp (current,
                         (0 == i % 2) ? &seen[i / 2].src : &seen[i / 2].dst,
                         sizeof (GNUNET_PeerIdentity)))
          {
            is_first = GNUNET_NO;
            break;
          }
      if (is_first != GNUNET_YES)
        continue;               /* only each peer once */
      is_source = GNUNET_NO;
      for (j = 0; j < count; j++)
        {
          if (0 == memcmp (current,
                           &seen[i].src, sizeof (GNUNET_PeerIdentity)))
            {
              is_source = GNUNET_YES;
              break;
            }
        }
      switch (format)
        {
        case 0:
          break;
        case 1:
          if (is_source == GNUNET_NO)
            {
              printf ("  \"%.*s\" [style=filled,color=\".7 .3 1.0\"];\n",
                      4, (char *) &enc);
            }
          break;
        case 2:
          if (is_source == GNUNET_NO)
            {
              printf
                ("\tnode: { title: \"%s\" label: \"%.*s\" shape: \"ellipse\" }\n",
                 (char *) &enc, 4, (char *) &enc);
            }
          else
            {
              printf ("\tnode: { title: \"%s\" label: \"%.*s\" }\n",
                      (char *) &enc, 4, (char *) &enc);
            }
          break;
        }
    }
  /* close syntax */
  switch (format)
    {
    case 0:
      break;
    case 1:
      printf ("}\n");
      break;
    case 2:
      printf ("}\n");
      break;
    }
  return NULL;
}

/**
 * All gnunet-tracekit command line options
 */
static struct GNUNET_CommandLineOption gnunettracekitOptions[] = {
  GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),   /* -c */
  {'D', "depth", "DEPTH",
   gettext_noop ("probe network to the given DEPTH"), 1,
   &GNUNET_getopt_configure_set_uint, &depth},
  {'F', "format", "FORMAT",
   gettext_noop
   ("specify output format; 0 for human readable output, 1 for dot, 2 for vcg"),
   1,
   &GNUNET_getopt_configure_set_uint, &format},
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Start GNUnet transport benchmarking tool.")), /* -h */
  GNUNET_COMMAND_LINE_OPTION_HOSTNAME,  /* -H */
  GNUNET_COMMAND_LINE_OPTION_LOGGING,   /* -L */
  {'P', "priority", "PRIORITY",
   gettext_noop ("use PRIORITY for the priority of the trace request"), 1,
   &GNUNET_getopt_configure_set_uint, &priority,},
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION), /* -v */
  {'W', "wait", "DELAY",
   gettext_noop ("wait DELAY seconds for replies"), 1,
   &GNUNET_getopt_configure_set_uint, &delay},
  GNUNET_COMMAND_LINE_OPTION_END,
};

static void
run_shutdown (void *unused)
{
  GNUNET_shutdown_initiate ();
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
  struct GNUNET_ThreadHandle *myThread;
  struct GNUNET_CronManager *cron;
  void *unused;

  if (-1 == GNUNET_init (argc,
                         argv,
                         "gnunet-tracekit",
                         &cfgFilename, gnunettracekitOptions, &ectx, &cfg))
    {
      GNUNET_fini (ectx, cfg);
      return -1;
    }
  if (format > 2)
    {
      printf (_("Format specification invalid. "
                "Use 0 for user-readable, 1 for dot, 2 for vcg.\n"));
      return -1;
    }

  sock = GNUNET_client_connection_create (ectx, cfg);
  if (sock == NULL)
    {
      fprintf (stderr, _("Error establishing connection with gnunetd.\n"));
      GNUNET_fini (ectx, cfg);
      return 1;
    }
  myThread = GNUNET_thread_create (&process, sock, 128 * 1024);
  if (myThread == NULL)
    GNUNET_GE_DIE_STRERROR (ectx,
                            GNUNET_GE_FATAL | GNUNET_GE_IMMEDIATE |
                            GNUNET_GE_ADMIN, "pthread_create");
  cron = GNUNET_cron_create (ectx);
  GNUNET_cron_start (cron);
  GNUNET_cron_add_job (cron, &run_shutdown, GNUNET_CRON_SECONDS * delay,
                       0, NULL);
  GNUNET_shutdown_wait_for ();
  GNUNET_client_connection_close_forever (sock);
  GNUNET_thread_join (myThread, &unused);
  GNUNET_client_connection_destroy (sock);
  GNUNET_cron_stop (cron);
  GNUNET_cron_destroy (cron);
  GNUNET_array_grow (seen, count, 0);
  GNUNET_fini (ectx, cfg);
  return 0;
}

/* end of gnunet-tracekit.c */
