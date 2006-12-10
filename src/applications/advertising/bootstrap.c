/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file advertising/bootstrap.c
 * @brief Cron-jobs that trigger bootstrapping
 *  if we have too few connections.
 *
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_bootstrap_service.h"
#include "gnunet_state_service.h"

#define DEBUG_BOOTSTRAP NO

#define hello_HELPER_TABLE_START_SIZE 64

static CoreAPIForApplication * coreAPI;

static Bootstrap_ServiceAPI * bootstrap;

static State_ServiceAPI * state;

static struct PTHREAD * pt;

typedef struct {
  P2P_hello_MESSAGE ** helos;
  unsigned int helosCount;
  unsigned int helosLen;
  int do_shutdown;
} HelloListClosure;

static HelloListClosure hlc;

static int testTerminate(void * cls) {
  HelloListClosure * c = cls;
  return ! c->do_shutdown;
}

static void processhellos(HelloListClosure * hcq) {
  int rndidx;
  int i;
  P2P_hello_MESSAGE * msg;

  if (NULL == hcq) {
    GE_BREAK(coreAPI->ectx, 0);
    return;
  }
  while ( (! hcq->do_shutdown) &&
	  (hcq->helosCount > 0) ) {
    /* select hello by random */
    rndidx = weak_randomi(hcq->helosCount);
#if DEBUG_BOOTSTRAP
    GE_LOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "%s chose hello %d of %d\n",
	   __FUNCTION__,
	   rndidx, hcq->helosCount);
#endif
    msg = (P2P_hello_MESSAGE*) hcq->helos[rndidx];
    hcq->helos[rndidx]
      = hcq->helos[hcq->helosCount-1];
    GROW(hcq->helos,
	 hcq->helosCount,
	 hcq->helosCount-1);

    coreAPI->injectMessage(&msg->senderIdentity,
			   (char*)msg,
			   P2P_hello_MESSAGE_size(msg),
			   NO,
			   NULL);
    FREE(msg);
    if ( (hcq->helosCount > 0) &&
	 (! hlc.do_shutdown) ) {
      /* wait a bit */
      unsigned int load;
      int nload;
      load = os_cpu_get_load(coreAPI->ectx,
			     coreAPI->cfg);
      if (load == (unsigned int)-1)
	load = 50;
      nload = os_network_monitor_get_load(coreAPI->load_monitor,
					  Upload);
      if (nload > load)
	load = nload;
      nload = os_network_monitor_get_load(coreAPI->load_monitor,
					  Download);
      if (nload > load)
	load = nload;
      if (load > 100)
	load = 100;

      PTHREAD_SLEEP(50 + weak_randomi((load+1)*(load+1)));
    }
  }
  for (i=0;i<hcq->helosCount;i++)
    FREE(hcq->helos[i]);
  GROW(hcq->helos,
       hcq->helosCount,
       0);
}

static void downloadHostlistCallback(const P2P_hello_MESSAGE * helo,
				     void * c) {
  HelloListClosure * cls = c;
  if (cls->helosCount >= cls->helosLen) {
    GROW(cls->helos,
	 cls->helosLen,
	 cls->helosLen + hello_HELPER_TABLE_START_SIZE);
  }
  cls->helos[cls->helosCount++] = MALLOC(P2P_hello_MESSAGE_size(helo));
  memcpy(cls->helos[cls->helosCount-1],
	 helo,
	 P2P_hello_MESSAGE_size(helo));
}

#define BOOTSTRAP_INFO "bootstrap-info"

static int needBootstrap() {
  static cron_t lastTest;
  static cron_t delta;
  cron_t now;
  char * data;

  now = get_time();
  if (coreAPI->forAllConnectedNodes(NULL, NULL) >= 3) {
    /* still change delta and lastTest; even
       if the peer _briefly_ drops below 4
       connections, we don't want it to immediately
       go for the hostlist... */
    delta = 5 * cronMINUTES;
    lastTest = now;
    return NO;
  }
  if (lastTest == 0) {
    /* first run in this process */
    if (-1 != state->read(coreAPI->ectx,
			  BOOTSTRAP_INFO,
			  (void**)&data)) {
      /* but not first on this machine */
      lastTest = now;
      delta = 2 * cronMINUTES; /* wait 2 minutes */
      FREE(data);
    } else {
      /* first on this machine, too! */
      state->write(coreAPI->ectx,
		   BOOTSTRAP_INFO,
		   1,
		   "X");
      delta = 60 * cronSECONDS;
    }
  }
  if (now - lastTest > delta) {
    lastTest = now;
    delta *= 2; /* exponential back-off */
    /* Maybe it should ALSO be based on how many peers
       we know (identity).
       Sure, in the end it goes to the topology, so
       probably that API should be extended here... */
    return YES;
  } else {
    /* wait a bit longer */
    return NO;
  }
}

static void * processThread(void * unused) {
  hlc.helos = NULL;
  while (NO == hlc.do_shutdown) {
    while (NO == hlc.do_shutdown) {
      PTHREAD_SLEEP(2 * cronSECONDS);
      if (needBootstrap())
	break;
    }
    if (YES == hlc.do_shutdown)
      break;
#if DEBUG_BOOTSTRAP
    GE_LOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "Starting bootstrap.\n");
#endif
    hlc.helosLen = 0;
    hlc.helosCount = 0;
    bootstrap->bootstrap(&downloadHostlistCallback,
			 &hlc,
			 &testTerminate,
			 &hlc);
    GROW(hlc.helos,
	 hlc.helosLen,
	 hlc.helosCount);
    processhellos(&hlc);
  }
  return NULL;
}

/**
 * Start using the bootstrap service to obtain
 * advertisements if needed.
 */
void startBootstrap(CoreAPIForApplication * capi) {
  coreAPI = capi;
  state = capi->requestService("state");
  GE_ASSERT(capi->ectx,
	    state != NULL);
  bootstrap = capi->requestService("bootstrap");
  GE_ASSERT(capi->ectx,
	    bootstrap != NULL);
  hlc.do_shutdown = NO;
  pt = PTHREAD_CREATE(&processThread,
		      NULL,
		      64 * 1024);
  GE_ASSERT(capi->ectx,
	    pt != NULL);
}

/**
 * Stop advertising.
 */
void stopBootstrap() {
  void * unused;

  hlc.do_shutdown = YES;
  PTHREAD_STOP_SLEEP(pt);
  PTHREAD_JOIN(pt, &unused);
  pt = NULL;
  coreAPI->releaseService(bootstrap);
  bootstrap = NULL;
  coreAPI->releaseService(state);
  state = NULL;
  coreAPI = NULL;
}

/* end of bootstrap.c */
