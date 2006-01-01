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
 * @file applications/dht/tools/dhttest.c
 * @brief DHT testcase
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_dht_lib.h"
#include "gnunet_dht_datastore_memory.h"
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


#define CHECK(a) do { if (!(a)) { ret = 1; BREAK(); goto FAILURE; } } while(0)
#define CHECK2(a) do { if (!(a)) { ret = 1; BREAK(); goto FAILURE2; } } while(0)

/**
 * Testcase to test gap routing (2 peers only).
 * @return 0: ok, -1: error
 */
int main(int argc, char ** argv) {
  pid_t daemon1;
  pid_t daemon2;
  pid_t sto2;
  int ret;
  int status;
  GNUNET_TCP_SOCKET * sock;
  int left;
  DHT_TableId table;
  DHT_TableId key;
  DataContainer * value;
  Blockstore * store;

  GNUNET_ASSERT(OK ==
		enc2hash("BV3AS3KMIIBVIFCGEG907N6NTDTH26B7T6FODUSLSGK"
			 "5B2Q58IEU1VF5FTR838449CSHVBOAHLDVQAOA33O77F"
			 "OPDA8F1VIKESLSNBO",
			 &peer2.hashPubKey));
  if (OK != initUtil(argc,
		     argv,
		     &parseOptions))
    return -1;
  printf("Starting daemons (1st round)\n");
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
  printf("Re-starting daemons.\n");
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
  startCron();
  do {
    sock = getClientSocket();
    if (sock == NULL) {
      printf(_("Waiting for gnunetd to start (%u iterations left)...\n"),
	     left);
      sleep(1);
      left--;
      CHECK(left > 0);
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
    CHECK(left > 0);
  }
  releaseClientSocket(sock);
  printf("Peers connected.  Running actual test.\n");
  
  memset(&table, 33, sizeof(DHT_TableId));
  DHT_LIB_init();
  store = create_blockstore_memory(65536);

  /* actual test code */
  sto2 = fork();
  if (sto2 == 0) {
    /* switch to peer2 */
    setConfigurationInt("NETWORK",
			"PORT",
			12087);
    printf("Peer2 joins DHT\n");
    DHT_LIB_join(store,
		 &table);
    hash("key", 3, &key);
    value = MALLOC(8);
    value->size = ntohl(8);
    printf("Peer2 stores key.\n");
    CHECK2(OK == DHT_LIB_put(&table,
			     &key,
			     0,
			     5 * cronSECONDS,
			     value));
    printf("Peer2 gets key.\n");
    CHECK2(1 == DHT_LIB_get(&table,
			    0,
			    0,
			    1,
			    &key,
			    10 * cronSECONDS,
			    NULL,
			    NULL));

    hash("key2", 4, &key);
    printf("Peer2 gets key2.\n");
    CHECK2(1 == DHT_LIB_get(&table,
			    0,
			    0,
			    1,
			    &key,
			    60 * cronSECONDS,
			    NULL,
			    NULL));
    printf("Peer2 tests successful.\n");
    gnunet_util_sleep(30 * cronSECONDS);
  FAILURE2:
    DHT_LIB_leave(&table);
    destroy_blockstore_memory(store);
    DHT_LIB_done();
    stopCron();
    doneUtil();
    exit(ret);
  }
  printf("Peer1 joints DHT\n");
  DHT_LIB_join(store,
	       &table);
  hash("key2", 4, &key);
  value = MALLOC(8);
  value->size = ntohl(8);
  printf("Peer1 stores key2\n");
  CHECK(OK == DHT_LIB_put(&table,
			  &key,
			  0,
			  5 * cronSECONDS,
			  value));
  printf("Peer1 gets key2\n");
  CHECK(1 == DHT_LIB_get(&table,
			 0,
			 0,
			 1,
			 &key,
			 10 * cronSECONDS,
			 NULL,
			 NULL));
  hash("key", 3, &key);
  printf("Peer1 gets key\n");
  CHECK(1 == DHT_LIB_get(&table,
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
  DHT_LIB_done();

  if (sto2 != waitpid(sto2, &status, 0))
    DIE_STRERROR("waitpid");
  /* end of actual test code */

 FAILURE:
  stopCron();
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

/* end of dhttest2.c */
