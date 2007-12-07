/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/stats/gnunet-stats.c
 * @brief tool to obtain statistics from gnunetd.
 * @author Christian Grothoff
 * @author Igor Wronsky
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_util.h"
#include "gnunet_stats_lib.h"
#include "statistics.h"

static int lastIp2p = 42;       /* not GNUNET_YES or GNUNET_NO */

static char *cfgFilename = GNUNET_DEFAULT_CLIENT_CONFIG_FILE;

/**
 * Print statistics received.
 *
 * @param stream where to print the statistics
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
printStatistics (const char *name, unsigned long long value, void *cls)
{
  FILE *stream = cls;
  FPRINTF (stream, "%-60s: %16llu\n", dgettext ("GNUnet", name), value);
  return GNUNET_OK;
}

static int
printProtocols (unsigned short type, int isP2P, void *cls)
{
  FILE *stream = cls;
  const char *name = NULL;

  if (isP2P != lastIp2p)
    {
      if (isP2P)
        fprintf (stream, _("Supported peer-to-peer messages:\n"));

      else
        fprintf (stream, _("Supported client-server messages:\n"));
      lastIp2p = isP2P;
    }
  if (isP2P)
    name = GNUNET_STATS_p2p_message_type_to_string (type);
  else
    name = GNUNET_STATS_cs_message_type_to_string (type);
  if (name == NULL)
    fprintf (stream, "\t%d\n", type);
  else
    fprintf (stream, "\t%d\t(%s)\n", type, name);
  return GNUNET_OK;
}

/**
 * All gnunet-transport-check command line options
 */
static struct GNUNET_CommandLineOption gnunetstatsOptions[] = {
  GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),   /* -c */
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Print statistics about GNUnet operations.")), /* -h */
  GNUNET_COMMAND_LINE_OPTION_HOSTNAME,  /* -H */
  GNUNET_COMMAND_LINE_OPTION_LOGGING,   /* -L */
  {'p', "protocols", NULL,
   gettext_noop ("prints supported protocol messages"),
   0, &GNUNET_getopt_configure_set_option, "STATS:PRINT-PROTOCOLS=YES"},
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION), /* -v */
  GNUNET_COMMAND_LINE_OPTION_END,
};


/**
 * The main function to obtain statistics from gnunetd.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int res;
  struct GNUNET_ClientServerConnection *sock;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_GE_Context *ectx;

  res = GNUNET_init (argc,
                     argv,
                     "gnunet-stats",
                     &cfgFilename, gnunetstatsOptions, &ectx, &cfg);
  if (res == -1)
    {
      GNUNET_fini (ectx, cfg);
      return -1;
    }
  sock = GNUNET_client_connection_create (ectx, cfg);
  if (sock == NULL)
    {
      fprintf (stderr, _("Error establishing connection with gnunetd.\n"));
      return 1;
    }
  res = GNUNET_STATS_get_statistics (ectx, sock, &printStatistics, stdout);
  if ((GNUNET_YES == GNUNET_GC_get_configuration_value_yesno (cfg,
                                                              "STATS",
                                                              "PRINT-PROTOCOLS",
                                                              GNUNET_NO))
      && (res == GNUNET_OK))
    {
      res =
        GNUNET_STATS_get_available_protocols (ectx, sock, &printProtocols,
                                              stdout);
    }
  if (res != GNUNET_OK)
    fprintf (stderr, _("Error reading information from gnunetd.\n"));
  GNUNET_client_connection_destroy (sock);
  GNUNET_fini (ectx, cfg);

  return (res == GNUNET_OK) ? 0 : 1;
}

/* end of gnunet-stats.c */
