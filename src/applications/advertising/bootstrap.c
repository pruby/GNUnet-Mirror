/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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

#define DEBUG_BOOTSTRAP NO

#define hello_HELPER_TABLE_START_SIZE 64

static CoreAPIForApplication * coreAPI;

static Bootstrap_ServiceAPI * bootstrap;

static PTHREAD_T pt;

static int ptPID;

static int abort_bootstrap = YES;

typedef struct {
  P2P_hello_MESSAGE ** helos;
  unsigned int helosCount;
  unsigned int helosLen;
} HelloListClosure;

static void processhellos(HelloListClosure * hcq) {
  int rndidx;
  int i;
  P2P_hello_MESSAGE * msg;

  if (NULL == hcq) {
    BREAK();
    return;
  }
  while ( (abort_bootstrap == NO) &&
	  (hcq->helosCount > 0) ) {
    /* select hello by random */
    rndidx = weak_randomi(hcq->helosCount);
#if DEBUG_BOOTSTRAP
    LOG(LOG_DEBUG,
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
	 (abort_bootstrap == NO) ) {
      /* wait a bit */
      unsigned int load;
      int nload;
      load = getCPULoad();
      nload = getNetworkLoadUp();
      if (nload > load)
	load = nload;
      nload = getNetworkLoadDown();
      if (nload > load)
	load = nload;
      if (load > 100)
	load = 100;

      gnunet_util_sleep(50 + weak_randomi((load+1)*(load+1)));
    }
  }
  for (i=0;i<hcq->helosCount;i++)
    FREE(hcq->helos[i]);
  GROW(hcq->helos,
       hcq->helosCount,
       0);
}

static void downloadHostlistCallback(const P2P_hello_MESSAGE * helo,
				     HelloListClosure * cls) {
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

  cronTime(&now);
  if (coreAPI->forAllConnectedNodes(NULL, NULL) > 4) {
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
    if (-1 != stateReadContent(BOOTSTRAP_INFO,
			       (void**)&data)) {
      /* but not first on this machine */
      lastTest = cronTime(&now);
      delta = 2 * cronMINUTES; /* wait 2 minutes */
      FREE(data);
    } else {
      /* first on this machine, too! */
      stateWriteContent(BOOTSTRAP_INFO,
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

static void processThread(void * unused) {
  HelloListClosure cls;

  ptPID = getpid();
  cls.helos = NULL;
  while (abort_bootstrap == NO) {
    while (abort_bootstrap == NO) {
      gnunet_util_sleep(2 * cronSECONDS);
      if (needBootstrap())
	break;
    }
    if (abort_bootstrap != NO)
      break;
#if DEBUG_BOOTSTRAP
    LOG(LOG_DEBUG,
	"Starting bootstrap.\n");
#endif
    cls.helosLen = 0;
    cls.helosCount = 0;
    bootstrap->bootstrap((hello_Callback)&downloadHostlistCallback,
			 &cls);
    GROW(cls.helos,
	 cls.helosLen,
	 cls.helosCount);
    processhellos(&cls);
  }
  ptPID = 0;
}

/**
 * Start using the bootstrap service to obtain
 * advertisements if needed.
 */
void startBootstrap(CoreAPIForApplication * capi) {
  coreAPI = capi;
  bootstrap = capi->requestService("bootstrap");
  GNUNET_ASSERT(bootstrap != NULL);
  abort_bootstrap = NO;
  GNUNET_ASSERT(0 == PTHREAD_CREATE(&pt,
				    (PThreadMain)&processThread,
				    NULL,
				    8 * 1024));	
}

/**
 * Stop advertising.
 * @todo [WIN] Check if this works under Windows
 */
void stopBootstrap() {
  void * unused;

  abort_bootstrap = YES;
#if SOMEBSD || OSX || SOLARIS || MINGW
  PTHREAD_KILL(&pt, SIGALRM);
#else
  /* linux */
  if (ptPID != 0)
    kill(ptPID, SIGALRM);
#endif
  PTHREAD_JOIN(&pt, &unused);
  coreAPI->releaseService(bootstrap);
  bootstrap = NULL;
  coreAPI = NULL;
}

/* end of bootstrap.c */
