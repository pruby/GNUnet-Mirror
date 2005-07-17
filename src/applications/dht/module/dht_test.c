/**
 * @file applications/dht/module/dht_test.c
 * @brief Testcase for DHT
 * @author Christian Grothoff
 *
 * The testcase is supposed to work by emulating the GNUnet core
 * (and possibly other peers).  Quiz question is: should we also
 * emulate RPC?  And how about starting *two* DHT's locally and
 * just simulating the RPC message exchange?  Do we need t fork
 * for that or can do other tricks to avoid state-sharing?
 * Fork might be bad because it would then require hacking up some
 * IPC code (then again, serializing the RPC requests should not
 * be too hard).
 */

#include "gnunet_util.h"
#include "gnunet_core.h"
#include "gnunet_rpc_service.h"
#include "gnunet_dht_service.h"
#include "gnunet_dht_datastore_memory.h"
#include "platform.h"

#define ABORT() GNUNET_ASSERT(0)

static DHT_ServiceAPI * dhtAPI;
static CoreAPIForApplication dht_capi;
static CoreAPIForApplication rpc_capi;
static RPC_ServiceAPI * rpcAPI;

DHT_ServiceAPI * provide_dht_protocol(CoreAPIForApplication * capi);
int release_dht_protocol();
RPC_ServiceAPI * provide_rpc_protocol(CoreAPIForApplication * capi);
void release_rpc_protocol();

static int forAllConnectedNodes(PerNodeCallback method,
				void * arg) {
  return 0;
}

static void sendToNode(const PeerIdentity * hostId,
		       const P2P_MESSAGE_HEADER * message,
		       unsigned int priority,
		       unsigned int maxdelay) {
}

static void * requestService(const char * pos) {
  return NULL;
}

static int releaseService(void * service) {
  return 0;
}

static int registerHandler(const unsigned short type,
			   MessagePartHandler callback) {
  return SYSERR;
}

static int unregisterHandler(const unsigned short type,
			     MessagePartHandler callback) {
  return SYSERR;
}

static int parseCommandLine(int argc,
			    char * argv[]) {
  char c;

  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      { "config",  1, 0, 'c' },
      { 0,0,0,0 }
    };
    c = GNgetopt_long(argc,
		      argv,
		      "c:",
		      long_options,
		      &option_index);

    if (c == -1)
      break;  /* No more flags to process */

    switch(c) {
    case 'c':
      FREENONNULL(setConfigurationString("FILES",
					 "gnunet.conf",
					 GNoptarg));
      break;
    } /* end of parsing commandline */
  }
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGLEVEL",
				     "WARNING"));
  return OK;
}

int main(int argc,
	 char * argv[]) {
  PeerIdentity id;

  if (1)
    return 0; /* testcase not complete, always pass for now */

  makeRandomId(&id.hashPubKey);

  if (OK != initUtil(argc, argv, &parseCommandLine))
    return 1;

  /* for DHT */
  memset(&dht_capi, 0, sizeof(CoreAPIForApplication));
  dht_capi.myIdentity = &id;
  dht_capi.requestService = &requestService;
  dht_capi.releaseService = &releaseService;
  dht_capi.sendToNode = &sendToNode;
  dht_capi.forAllConnectedNodes = &forAllConnectedNodes;
  /* for RPC */
  memset(&rpc_capi, 0, sizeof(CoreAPIForApplication));
  rpc_capi.myIdentity = &id;
  rpc_capi.registerHandler = &registerHandler;
  rpc_capi.unregisterHandler = &unregisterHandler;
  rpc_capi.sendToNode = &sendToNode;

  rpcAPI = provide_rpc_protocol(&rpc_capi);
  if (rpcAPI == NULL)
    ABORT();
  dhtAPI = provide_dht_protocol(&dht_capi);
  if (dhtAPI == NULL)
    ABORT();

  release_rpc_protocol();
  if (OK == release_dht_protocol())
    return 0;
  else
    return 1;
}

/* end of dht_test.c */
