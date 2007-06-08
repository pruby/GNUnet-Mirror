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
 * @file applications/dht/tools/dhttest.c
 * @brief DHT testcase
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_dht_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_stats_lib.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"
#include "gnunet_util_cron.h"

#define NUM_PEERS 12

#define NUM_ROUNDS 4

static int ok;

static int waitForConnect(const char * name,
                         unsigned long long value,
                         void * cls) {
  if ( (value > 0) &&
       (0 == strcmp(_("# dht connections"),
                   name)) ) {
    ok = 1;
    return SYSERR;
  }
  return OK;
}

#define CHECK(a) do { if (!(a)) { ret = 1; GE_BREAK(ectx, 0); goto FAILURE; } } while(0)

/**
 * Testcase to test DHT routing (many peers).
 * @return 0: ok, -1: error
 */
int main(int argc,
	 const char ** argv) {
  struct DaemonContext * peers;
  int ret = 0;
  HashCode512 key;
  DataContainer * value;
  struct GE_Context * ectx;
  struct GC_Configuration * cfg;
  struct ClientServerConnection * sock;
  int left;
  int i;
  int j;
  int k;
  int found;
  char buf[128];

  ectx = NULL;
  cfg = GC_create_C_impl();
  if (-1 == GC_parse_configuration(cfg,
				   "check.conf")) {
    GC_free(cfg);
    return -1;
  }
  peers = gnunet_testing_start_daemons("tcp",
				       "advertising dht stats",
				       "/tmp/gnunet-dht-test",
				       2087,
				       10,
				       NUM_PEERS);
  if (peers == NULL) {
    GC_free(cfg);
    return -1;
  }
  for (i=0;i<NUM_PEERS;i++) {
    for (j=0;j<i;j++) {
      if (OK != gnunet_testing_connect_daemons(2087 + 10*i,
					       2087 + 10*j)) {
	gnunet_testing_stop_daemons(peers);
	fprintf(stderr,
		"Failed to connect the peers!\n");
	GC_free(cfg);
	return -1;
      }
    }
  }

  /* wait for some DHT's to find each other! */
  sock = client_connection_create(NULL,
				  cfg);
  left = 30; /* how many iterations should we wait? */
  while (OK == STATS_getStatistics(NULL,
				   sock,
				   &waitForConnect,
				   NULL)) {
    printf("Waiting for peers to DHT-connect (%u iterations left)...\n",
	   left);
    sleep(5);
    left--;
    if (left == 0)
      break;
  }
  connection_destroy(sock);
  if (ok == 0) {
    gnunet_testing_stop_daemons(peers);
    fprintf(stderr,
	    "Peers' DHTs failed to DHT-connect!\n");
    GC_free(cfg);
    return -1;
  }

  /* put loop */
  for (i=0;i<NUM_PEERS;i++) {
    SNPRINTF(buf,
	     128,
	     "localhost:%u",
	     2087 + i * 10);
    GC_set_configuration_value_string(cfg,
				      ectx,
				      "NETWORK",
				      "HOST",
				      buf);
    hash(buf, 4, &key);
    value = MALLOC(8);
    value->size = ntohl(8);
    memset(&value[1],
	   'A' + i,
	   4);
    CHECK(OK == DHT_LIB_put(cfg,
			    ectx,
			    &key,
			    DHT_STRING2STRING_BLOCK,
			    get_time() + 15 * cronMINUTES * NUM_ROUNDS * NUM_PEERS * NUM_PEERS,
			    value));
  }

  /* get loops */
  for (k=0;k<NUM_ROUNDS;k++) {
    found = 0;
    for (i=0;i<NUM_PEERS;i++) {
      SNPRINTF(buf,
	       128,
	       "localhost:%u",
	       2087 + i * 10);
      GC_set_configuration_value_string(cfg,
					ectx,
					"NETWORK",
					"HOST",
					buf);
      for (j=0;j<NUM_PEERS;j++) {
	SNPRINTF(buf,
		 128,
		 "localhost:%u",
		 2087 + j * 10);
	hash(buf, 4, &key);
	fprintf(stderr,
		"Peer %d gets key %d", i, j);
	if (0 < DHT_LIB_get(cfg,
			    ectx,
			    DHT_STRING2STRING_BLOCK,
			     &key,
			    (NUM_ROUNDS - k) * cronSECONDS,
			    NULL,
			    NULL)) {
	  fprintf(stderr,
		  " - found!\n");
	  found++;
	} else
	  fprintf(stderr,
		  " - NOT found!\n");
      }
    }
    /* end of actual test code */
    fprintf(stderr,
	    "Found %u out of %u attempts in round %u.\n",
	    found,
	    NUM_PEERS * NUM_PEERS,
	    k);
  }
 FAILURE:
  gnunet_testing_stop_daemons(peers);
  GC_free(cfg);
  return ret;
}

/* end of dhttest.c */
