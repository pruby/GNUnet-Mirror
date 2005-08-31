/*
     This file is part of GNUnet.
     (C) 2005 Christian Grothoff (and other contributing authors)

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
 * @file applications/session/sessiontest.c
 * @brief Session establishment testcase
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_stats_lib.h"

static int parseOptions(int argc,
			char ** argv) {
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  return OK;
}

/**
 * Identity of peer 2 (hardwired).
 */
static PeerIdentity peer2;

static int waitForConnect(const char * name,
			  unsigned long long value,
			  void * cls) {
  if ( (value > 0) &&
       (0 == strcmp(_("# of connected peers"),
		    name)) )
    return SYSERR;
  return OK;
}

/**
 * Testcase to test p2p session key exchange.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0: ok, -1: error
 */
int main(int argc, char ** argv) {
  pid_t daemon1;
  pid_t daemon2;
  int ret;
  GNUNET_TCP_SOCKET * sock;
  int left;

  GNUNET_ASSERT(OK ==
		enc2hash("BV3AS3KMIIBVIFCGEG907N6NTDTH26B7T6FODUSLSGK"
			 "5B2Q58IEU1VF5FTR838449CSHVBOAHLDVQAOA33O77F"
			 "OPDA8F1VIKESLSNBO",
			 &peer2.hashPubKey));
  if (OK != initUtil(argc,
		     argv,
		     &parseOptions))
    return -1;
  FREENONNULL(setConfigurationString("GNUNET",
				     "GNUNETD-CONFIG",
				     "peer1.conf"));
  daemon1 = startGNUnetDaemon(NO);
  FREENONNULL(setConfigurationString("GNUNET",
				     "GNUNETD-CONFIG",
				     "peer2.conf"));
  daemon2 = startGNUnetDaemon(NO);
  /* in case existing hellos have expired */
  gnunet_util_sleep(30 * cronSECONDS);
  system("cp peer1/data/hosts/* peer2/data/hosts/");
  system("cp peer2/data/hosts/* peer1/data/hosts/");
  if (daemon1 != -1) {
    if (! termProcess(daemon1))
      DIE_STRERROR("kill");
    GNUNET_ASSERT(OK == waitForGNUnetDaemonTermination(daemon1));
  }
  if (daemon2 != -1) {
    if (! termProcess(daemon2))
      DIE_STRERROR("kill");
    GNUNET_ASSERT(OK == waitForGNUnetDaemonTermination(daemon2));
  }

  /* re-start, this time we're sure up-to-date hellos are available */
  FREENONNULL(setConfigurationString("GNUNET",
				     "GNUNETD-CONFIG",
				     "peer1.conf"));
  daemon1 = startGNUnetDaemon(NO);
  FREENONNULL(setConfigurationString("GNUNET",
				     "GNUNETD-CONFIG",
				     "peer2.conf"));
  daemon2 = startGNUnetDaemon(NO);
  gnunet_util_sleep(5 * cronSECONDS);


  ret = 0;
  left = 5;
  /* wait for connection or abort with error */
  do {
    sock = getClientSocket();
    if (sock == NULL) {
      printf(_("Waiting for gnunetd to start (%u iterations left)...\n"),
	     left);
      sleep(1);
      left--;
      if (left == 0) {
	ret = 1;
	break;
      }
    }
  } while (sock == NULL);

  left = 30; /* how many iterations should we wait? */
  while (OK == requestStatistics(sock,
				 &waitForConnect,
				 NULL)) {
    printf(_("Waiting for peers to connect (%u iterations left)...\n"),
	   left);
    sleep(5);
    left--;
    if (left == 0) {
      ret = 1;
      break;
    }
  }
  releaseClientSocket(sock);
  if (daemon1 != -1) {
    if (! termProcess(daemon1))
      DIE_STRERROR("kill");
    GNUNET_ASSERT(OK == waitForGNUnetDaemonTermination(daemon1));
  }
  if (daemon2 != -1) {
    if (! termProcess(daemon2))
      DIE_STRERROR("kill");
    GNUNET_ASSERT(OK == waitForGNUnetDaemonTermination(daemon2));
  }
  doneUtil();
  return ret;
}

/* end of sessiontest.c */
