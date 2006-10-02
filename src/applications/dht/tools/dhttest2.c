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
#include "gnunet_dht_datastore_memory.h"
#include "gnunet_stats_lib.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"
#include "gnunet_util_cron.h"

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

#define START_PEERS 1

#define CHECK(a) do { if (!(a)) { ret = 1; GE_BREAK(ectx, 0); goto FAILURE; } } while(0)

#define CHECK2(a) do { if (!(a)) { ret = 1; GE_BREAK(ectx, 0); goto FAILURE2; } } while(0)

/**
 * Testcase to test gap routing (2 peers only).
 * @return 0: ok, -1: error
 */
int main(int argc,
	 const char ** argv) {
  pid_t daemon1;
  pid_t daemon2;
  pid_t sto2;
  int ret;
  int status;
  struct ClientServerConnection * sock;
  int left;
  DHT_TableId table;
  DHT_TableId key;
  DataContainer * value;
  Blockstore * store;
  struct GE_Context * ectx;
  struct GC_Configuration * cfg;

  enc2hash("BV3AS3KMIIBVIFCGEG907N6NTDTH26B7T6FODUSLSGK"
	   "5B2Q58IEU1VF5FTR838449CSHVBOAHLDVQAOA33O77F"
	   "OPDA8F1VIKESLSNBO",
	   &peer2.hashPubKey);
  cfg = GC_create_C_impl();
  if (-1 == GC_parse_configuration(cfg,
				   "check.conf")) {
    GC_free(cfg);
    return -1;  
  }
#if START_PEERS
  daemon1  = os_daemon_start(NULL,
			     cfg,
			     "peer1.conf",
			     NO);
  daemon2 = os_daemon_start(NULL,
			    cfg,
			    "peer2.conf",
			    NO);
#endif
  /* in case existing hellos have expired */
  PTHREAD_SLEEP(30 * cronSECONDS);
  system("cp peer1/data/hosts/* peer2/data/hosts/");
  system("cp peer2/data/hosts/* peer1/data/hosts/");
  ret = 0;
#if START_PEERS
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
#endif
  if (OK == connection_wait_for_running(NULL,
					cfg,
					30 * cronSECONDS)) {
    sock = client_connection_create(NULL,
				    cfg);
    left = 30; /* how many iterations should we wait? */
    while (OK == requestStatistics(ectx,
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

  ret = 0;
  left = 5;
  /* wait for connection or abort with error */
  do {
    sock = client_connection_create(ectx, cfg);
    if (sock == NULL) {
      printf(_("Waiting for gnunetd to start (%u iterations left)...\n"),
	     left);
      sleep(1);
      left--;
      CHECK(left > 0);
    }
  } while (sock == NULL);

  left = 30; /* how many iterations should we wait? */
  while (OK == requestStatistics(ectx,
				 sock,
				 &waitForConnect,
				 NULL)) {
    printf(_("Waiting for peers to connect (%u iterations left)...\n"),
	   left);
    sleep(5);
    left--;
    CHECK(left > 0);
  }
  connection_destroy(sock);
  printf("Peers connected.  Running actual test.\n");
  
  memset(&table, 33, sizeof(DHT_TableId));
  store = create_blockstore_memory(65536);

  /* actual test code */
  sto2 = fork();
  if (sto2 == 0) {
    /* switch to peer2 */
    GC_set_configuration_value_number(cfg,
				      ectx,
				      "NETWORK",
				      "PORT",
				      12087);
    printf("Peer2 joins DHT\n");
    DHT_LIB_join(store,
		 cfg,
		 ectx,
		 &table);
    hash("key", 3, &key);
    value = MALLOC(8);
    value->size = ntohl(8);
    printf("Peer2 stores key.\n");
    CHECK2(OK == DHT_LIB_put(cfg,
			     ectx,
			     &table,
			     &key,
			     0,
			     5 * cronSECONDS,
			     value));
    printf("Peer2 gets key.\n");
    CHECK2(1 == DHT_LIB_get(cfg,
			    ectx,
			    &table,
			    0,
			    0,
			    1,
			    &key,
			    10 * cronSECONDS,
			    NULL,
			    NULL));

    hash("key2", 4, &key);
    printf("Peer2 gets key2.\n");
    CHECK2(1 == DHT_LIB_get(cfg,
			    ectx,
			    &table,
			    0,
			    0,
			    1,
			    &key,
			    60 * cronSECONDS,
			    NULL,
			    NULL));
    printf("Peer2 tests successful.\n");
    PTHREAD_SLEEP(30 * cronSECONDS);
  FAILURE2:
    DHT_LIB_leave(&table);
    destroy_blockstore_memory(store);
    exit(ret);
  }
  printf("Peer1 joints DHT\n");
  DHT_LIB_join(store,
	       cfg,
	       ectx,
	       &table);
  hash("key2", 4, &key);
  value = MALLOC(8);
  value->size = ntohl(8);
  printf("Peer1 stores key2\n");
  CHECK(OK == DHT_LIB_put(cfg,
			  ectx,
			  &table,
			  &key,
			  0,
			  5 * cronSECONDS,
			  value));
  printf("Peer1 gets key2\n");
  CHECK(1 == DHT_LIB_get(cfg,
			 ectx,
			 &table,
			 0,
			 0,
			 1,
			 &key,
			 10 * cronSECONDS,
			 NULL,
			 NULL));
  hash("key", 3, &key);
  printf("Peer1 gets key\n");
  CHECK(1 == DHT_LIB_get(cfg,
			 ectx, 
			 &table,
			 0,
			 0,
			 1,
			 &key,
			 60 * cronSECONDS,
			 NULL,
			 NULL));
  printf("Peer1 tests successful, shutting down.\n");
  DHT_LIB_leave(&table);
  destroy_blockstore_memory(store);

  if (sto2 != waitpid(sto2, &status, 0))
    GE_DIE_STRERROR(ectx,
		    GE_FATAL | GE_USER | GE_IMMEDIATE,
		    "waitpid");
  /* end of actual test code */

 FAILURE:

#if START_PEERS
  if (daemon1 != -1) {
    if (os_daemon_stop(NULL, daemon1) != YES)
      ret = 1;
  }
  if (daemon2 != -1) {
    if (os_daemon_stop(NULL, daemon2) != YES)
      ret = 1;
  }
#endif
  GC_free(cfg);
  return ret;
}

/* end of dhttest2.c */
