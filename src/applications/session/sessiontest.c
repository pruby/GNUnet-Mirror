/*
     This file is part of GNUnet.
     (C) 2005, 2006 Christian Grothoff (and other contributing authors)

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
#include "gnunet_util.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"
#include "gnunet_stats_lib.h"

static int ok;

static int waitForConnect(const char * name,
			  unsigned long long value,
			  void * cls) {
  if ( (value > 0) &&
       (0 == strcmp(_("# of connected peers"),
		    name)) ) {
    ok = 1;
    return SYSERR;
  }
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
  struct ClientServerConnection * sock;
  int left;
  struct GC_Configuration * cfg;

  cfg = GC_create_C_impl();
  if (-1 == GC_parse_configuration(cfg,
				   "check.conf")) {
    GC_free(cfg);
    return -1;  
  }
  daemon1  = os_daemon_start(NULL,
			     cfg,
			     "peer1.conf",
			     NO);
  daemon2 = os_daemon_start(NULL,
			    cfg,
			    "peer2.conf",
			    NO);
  /* in case existing hellos have expired */
  PTHREAD_SLEEP(30 * cronSECONDS);
  system("cp peer1/data/hosts/* peer2/data/hosts/");
  system("cp peer2/data/hosts/* peer1/data/hosts/");
  ret = 0;
  if (daemon1 != -1) {
    if (os_daemon_stop(NULL, daemon1) != YES)
      ret = 1;
  }
  if (daemon2 != -1) {
    if (os_daemon_stop(NULL, daemon2) != YES)
      ret = 1;
  }
  if (ret != 0)
    return 1;
  daemon1  = os_daemon_start(NULL,
			     cfg,
			     "peer1.conf",
			     NO);
  daemon2 = os_daemon_start(NULL,
			    cfg,
			    "peer2.conf",
			    NO);
  PTHREAD_SLEEP(5 * cronSECONDS);

  ret = 0;
  left = 5;
  /* wait for connection or abort with error */
  do {
    sock = client_connection_create(NULL,
				    cfg);
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
  while (OK == requestStatistics(NULL,
				 sock,
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
  connection_destroy(sock);
  if (daemon1 != -1) {
    if (os_daemon_stop(NULL, daemon1) != YES)
      ret = 1;
  }
  if (daemon2 != -1) {
    if (os_daemon_stop(NULL, daemon2) != YES)
      ret = 1;
  }
  if (ok == 0)
    ret = 1;

  GC_free(cfg);
  return ret;
}

/* end of sessiontest.c */
