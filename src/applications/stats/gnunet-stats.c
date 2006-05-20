/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005 Christian Grothoff (and other contributing authors)

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
#include "gnunet_util.h"
#include "gnunet_stats_lib.h"
#include "statistics.h"

static int printProtocolsSelected;

static int lastIp2p = 42; /* not YES or NO */

/**
 * Print statistics received.
 *
 * @param stream where to print the statistics
 * @return OK on success, SYSERR on error
 */
static int printStatistics(const char * name,
			   unsigned long long value,
			   FILE * stream) {
  FPRINTF(stream,
	  "%-60s: %16llu\n",
	  dgettext("GNUnet", name),
	  value);
  return OK;
}

static int printProtocols(unsigned short type,
			  int isP2P,
			  FILE * stream) {
  const char *name = NULL;

  if (isP2P != lastIp2p) {
    if (isP2P)
      fprintf(stream,
	      _("Supported peer-to-peer messages:\n"));
    else
      fprintf(stream,
	      _("Supported client-server messages:\n"));
    lastIp2p = isP2P;
  }
  if (isP2P)
    name = p2pMessageName(type);
  else
    name = csMessageName(type);
  if (name == NULL)
    fprintf(stream,
	    "\t%d\n",
	    type);
  else
    fprintf(stream,
	    "\t%d\t(%s)\n",
	    type,
	    name);
  return OK;
}

/**
 * Prints the usage information for this command if the user errs.
 * Aborts the program.
 */
static void printhelp() {
  static Help help[] = {
    HELP_CONFIG,
    HELP_HELP,
    HELP_HOSTNAME,
    HELP_LOGLEVEL,
    { 'p', "protocols", NULL,
      gettext_noop("prints supported protocol messages") },
    HELP_VERSION,
    HELP_END,
  };
  formatHelp("gnunet-stats [OPTIONS]",
	     _("Print statistics about GNUnet operations."),
	     help);
}

/**
 * Parse the options.
 *
 * @param argc the number of options
 * @param argv the option list (including keywords)
 * @return SYSERR if we should abort, OK to continue
 */
static int parseOptions(int argc,
			char ** argv) {
  int option_index;
  int c;

  while (1) {
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "protocols",          0, 0, 'p' },
      { 0,0,0,0 }
    };
    option_index = 0;
    c = GNgetopt_long(argc,
		      argv,
		      "c:dhHL:pv",
		      long_options,
		      &option_index);
    if (c == -1)
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'v':
      printf("GNUnet v%s, gnunet-stats v%s\n",
	     VERSION, STATS_VERSION);
      return SYSERR;
    case 'h':
      printhelp();
      return SYSERR;
    case 'p':
      printProtocolsSelected = YES;
      break;
    default:
      LOG(LOG_FAILURE,
	  _("Use --help to get a list of options.\n"));
      return -1;
    } /* end of parsing commandline */
  } /* while (1) */
  return OK;
}

/**
 * The main function to obtain statistics from gnunetd.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int main(int argc, char ** argv) {
  int res;
  GNUNET_TCP_SOCKET * sock;

  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return 0;
  sock = getClientSocket();
  if (sock == NULL) {
    fprintf(stderr,
	    _("Error establishing connection with gnunetd.\n"));
    return 1;
  }
  res = requestStatistics(sock,
			  (StatisticsProcessor) &printStatistics,
			  stdout);
  if ((printProtocolsSelected == YES) &&
      (res == OK)) {
    res = requestAvailableProtocols(sock,
				    (ProtocolProcessor) &printProtocols,
				    stdout);
  }
  if (res != OK)
    fprintf(stderr,
	    _("Error reading information from gnunetd.\n"));
  releaseClientSocket(sock);
  doneUtil();

  return (res == OK) ? 0 : 1;
}

/* end of gnunet-stats.c */
