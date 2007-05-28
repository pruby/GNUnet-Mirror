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


#define START_PEERS 1

#define CHECK(a) do { if (!(a)) { ret = 1; GE_BREAK(ectx, 0); goto FAILURE; } } while(0)

/**
 * Testcase to test gap routing (2 peers only).
 * @return 0: ok, -1: error
 */
int main(int argc,
	 const char ** argv) {
#if START_PEERS
  struct DaemonContext * peers;
#endif
  int ret;
  HashCode512 key;
  DataContainer * value;
  struct GE_Context * ectx;
  struct GC_Configuration * cfg;

  ectx = NULL;
  cfg = GC_create_C_impl();
  if (-1 == GC_parse_configuration(cfg,
				   "check.conf")) {
    GC_free(cfg);
    return -1;
  }
#if START_PEERS
  peers = gnunet_testing_start_daemons("tcp",
				       "advertising dht stats",				       
				       "/tmp/dht-test",
				       2087,
				       10000,
				       2);
  if (peers == NULL) {
    GC_free(cfg);
    return -1;
  }
#endif
  gnunet_testing_connect_daemons(2087,
				 12087);

  /* actual test code */
  hash("key2", 4, &key);
  value = MALLOC(8);
  value->size = ntohl(8);
  memset(&value[1],
	 'A',
	 4);
  printf("Peer1 stores key2\n");
  CHECK(OK == DHT_LIB_put(cfg,
			  ectx,
			  &key,
			  DHT_STRING2STRING_BLOCK,
			  5 * cronSECONDS,
			  value));
  printf("Peer1 gets key2\n");
  CHECK(1 == DHT_LIB_get(cfg,
			 ectx,
			 DHT_STRING2STRING_BLOCK,
			 &key,
			 10 * cronSECONDS,
			 NULL,
			 NULL));
  hash("key", 3, &key);
  
  /* switch to peer2 */
  GC_set_configuration_value_string(cfg,
				    ectx,
				    "NETWORK",
				    "HOST",
				    "localhost:12087");
  hash("key", 3, &key);
  value = MALLOC(8);
  value->size = ntohl(8);
  memset(&value[1],
	 'B',
	 4);
  printf("Peer2 stores key.\n");
  CHECK(OK == DHT_LIB_put(cfg,
			  ectx,
			  &key,
			  DHT_STRING2STRING_BLOCK,
			  5 * cronSECONDS,
			  value));
  printf("Peer2 gets key.\n");
  CHECK(1 == DHT_LIB_get(cfg,
			 ectx,
			 DHT_STRING2STRING_BLOCK,
			 &key,
			 10 * cronSECONDS,
			 NULL,
			 NULL));
  
  hash("key2", 4, &key);
  printf("Peer2 gets key2.\n");
  CHECK(1 == DHT_LIB_get(cfg,
			 ectx,
			 DHT_STRING2STRING_BLOCK,
			 &key,
			 60 * cronSECONDS,
			 NULL,
			 NULL));
  printf("Peer2 tests successful.\n");

  /* switch to peer1 */
  GC_set_configuration_value_string(cfg,
				    ectx,
				    "NETWORK",
				    "HOST",
				    "localhost:2087");
  printf("Peer1 gets key\n");
  CHECK(1 == DHT_LIB_get(cfg,
			 ectx,
			 DHT_STRING2STRING_BLOCK,
			 &key,
			 60 * cronSECONDS,
			 NULL,
			 NULL));
  printf("Peer1 tests successful, shutting down.\n");
  /* end of actual test code */

 FAILURE:
#if START_PEERS
  gnunet_testing_stop_daemons(peers);
#endif
  GC_free(cfg);
  return ret;
}

/* end of dhttest2.c */
