/*
     This file is part of GNUnet.
     (C) 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/session/sessiontest_http.c
 * @brief Session establishment testcase for NAT over HTTP
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_util.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"
#include "gnunet_identity_lib.h"
#include "gnunet_stats_lib.h"

#define START_PEERS 1

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
 * Notify NATed peer about other peer.
 *
 * @param port1 client port of the first daemon
 * @param port2 client port of the second daemon
 * @return OK on success, SYSERR on failure
 */
static int connect_daemons(unsigned short port1,
			   unsigned short port2) {
  char host[128];
  GC_Configuration * cfg1 = GC_create_C_impl();
  GC_Configuration * cfg2 = GC_create_C_impl();
  struct ClientServerConnection * sock1;
  struct ClientServerConnection * sock2;
  int ret;
  P2P_hello_MESSAGE * h1;

  ret = SYSERR;
  SNPRINTF(host,
	   128,
	   "localhost:%u",
	   port1);
  GC_set_configuration_value_string(cfg1,
				    NULL,
				    "NETWORK",
				    "HOST",
				    host);
  SNPRINTF(host,
	   128,
	   "localhost:%u",
	   port2);
  GC_set_configuration_value_string(cfg2,
				    NULL,
				    "NETWORK",
				    "HOST",
				    host);
  if ( (OK == connection_wait_for_running(NULL,
					  cfg1,
					  300 * cronSECONDS) ) &&
       (OK == connection_wait_for_running(NULL,
					  cfg2,
					  300 * cronSECONDS) ) ) {
    sock1 = client_connection_create(NULL,
				     cfg1);
    sock2 = client_connection_create(NULL,
				     cfg2);
    h1 = NULL;
    fprintf(stderr, "Notifying NATed peer about other peer");
    if ( (OK == gnunet_identity_get_self(sock1,
				       &h1)) &&
	 (OK == gnunet_identity_peer_add(sock2,
					 h1)) ) {
      fprintf(stderr, "!\n");
      ret = OK;
    } else
      fprintf(stderr, "?\n");
    FREENONNULL(h1);
    connection_destroy(sock1);
    connection_destroy(sock2);
  } else {
    fprintf(stderr,
	    "Failed to establish connection with peers.\n");
  }
  GC_free(cfg1);
  GC_free(cfg2);
  return ret;
}


/**
 * Testcase to test p2p session key exchange.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0: ok, -1: error
 */
int main(int argc, char ** argv) {
#if START_PEERS
  pid_t peer1;
  pid_t peer2;
#endif
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
#if START_PEERS
  peer1 = os_daemon_start(NULL,
			  cfg,
			  "http-peer.conf",
			  NO);
  if (peer1 == -1) {
    GC_free(cfg);
    return -1;
  }
  peer2 = os_daemon_start(NULL,
			  cfg,
			  "nat-http-peer.conf",
			  NO);  
  if (peer2 == -1) {
    os_daemon_stop(NULL, peer1);
    GC_free(cfg);
    return -1;
  }
#endif
  connect_daemons(2087,
		  12087);
  if (OK == connection_wait_for_running(NULL,
					cfg,
					30 * cronSECONDS)) {
    sock = client_connection_create(NULL,
				    cfg);
    left = 30; /* how many iterations should we wait? */
    while (OK == STATS_getStatistics(NULL,
				     sock,
				     &waitForConnect,
				     NULL)) {
      printf("Waiting for peers to connect (%u iterations left)...\n",
	     left);
      sleep(5);
      left--;
      if (left == 0) {
	ret = 1;
	break;
      }
    }
    connection_destroy(sock);
  } else {
    printf("Could not establish connection with peer.\n");
    ret = 1;
  }
#if START_PEERS
  os_daemon_stop(NULL, peer1);
  os_daemon_stop(NULL, peer2);
#endif
  GC_free(cfg);
  return (ok == 0) ? 1 : 0;
}

/* end of sessiontest2.c */
