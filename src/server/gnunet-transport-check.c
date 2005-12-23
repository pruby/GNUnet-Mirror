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
 * @file server/gnunet-transport-check.c
 * @brief Test for the transports.
 * @author Christian Grothoff
 *
 * This utility can be used to test if a transport mechanism for
 * GNUnet is properly configured.
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_pingpong_service.h"
#include "gnunet_bootstrap_service.h"
#include "core.h"
#include "connection.h"
#include "handler.h"
#include "startup.h"

#define DEBUG_TRANSPORT_CHECK NO

#define DEFAULT_MSG "Hello World"

static Semaphore * sem;

static int terminate;

static cron_t timeout = 5 * cronSECONDS;

static Transport_ServiceAPI * transport;

static Identity_ServiceAPI * identity;

static Pingpong_ServiceAPI * pingpong;

static Bootstrap_ServiceAPI * bootstrap;

static int ok;

static char * expectedValue;

static unsigned short expectedSize;

static void semUp(Semaphore * sem) {
#if DEBUG_TRANSPORT_CHECK
  LOG(LOG_DEBUG,
      "semUp timeout happened!\n");
#endif
  terminate = YES;
  SEMAPHORE_UP(sem);
}

static int noiseHandler(const PeerIdentity *peer,
			const P2P_MESSAGE_HEADER * msg,
			TSession * s) {
  if ( (ntohs(msg->size) ==
	sizeof(P2P_MESSAGE_HEADER) + expectedSize) &&
       (0 == memcmp(expectedValue,
		    &msg[1],
		    expectedSize)) )
    ok = YES;
  SEMAPHORE_UP(sem);
  return OK;
}

/**
 * Test the given transport API.
 */
static void testTAPI(TransportAPI * tapi,
		     int * res) {
  P2P_hello_MESSAGE * helo;
  TSession * tsession;
  unsigned int repeat;
  cron_t start;
  cron_t end;
  CS_MESSAGE_HEADER * noise;

  if (tapi == NULL)
    errexit("Could not initialize transport!\n");
  if (tapi->protocolNumber == NAT_PROTOCOL_NUMBER) {
    *res = OK;
    return; /* NAT cannot be tested */
  }
  helo = tapi->createhello();
  if (helo == NULL) {
    fprintf(stderr,
	    _("`%s': Could not create hello.\n"),
	    tapi->transName);
    *res = SYSERR;
    return;
  }
  tsession = NULL;
  if (OK != tapi->connect(helo,
			  &tsession)) {
    fprintf(stderr,
	    _("`%s': Could not connect.\n"),
	    tapi->transName);
    *res = SYSERR;
    FREE(helo);
    return;
  }
  FREE(helo);
  repeat = getConfigurationInt("TRANSPORT-CHECK",
			       "REPEAT");
  if (repeat == 0) {
    repeat = 1;
    setConfigurationInt("TRANSPORT-CHECK",
			"REPEAT",
			1);
  }
  sem = SEMAPHORE_NEW(0);
  cronTime(&start);
  noise = MALLOC(expectedSize + sizeof(P2P_MESSAGE_HEADER));
  noise->type = htons(P2P_PROTO_noise);
  noise->size = htons(expectedSize + sizeof(P2P_MESSAGE_HEADER));
  memcpy(&noise[1],
	 expectedValue,
	 expectedSize);
  while (repeat > 0) {
    repeat--;
    ok = NO;
    if (OK != sendPlaintext(tsession,
			    (char*)noise,
			    ntohs(noise->size))) {
      fprintf(stderr,
	      _("`%s': Could not send.\n"),
	      tapi->transName);
      *res = SYSERR;
      tapi->disconnect(tsession);
      SEMAPHORE_FREE(sem);
      FREE(noise);
      return;
    }
    addCronJob((CronJob)&semUp,
	       timeout,
	       0,
	       sem);
    SEMAPHORE_DOWN(sem);
    suspendCron();
    delCronJob((CronJob)&semUp,
	       0,
	       sem);
    resumeCron();
    if (ok != YES) {
      FPRINTF(stderr,
	      _("`%s': Did not receive message within %llu ms.\n"),
	      tapi->transName,
	      timeout);
      *res = SYSERR;
      tapi->disconnect(tsession);
      SEMAPHORE_FREE(sem);
      FREE(noise);
      return;
    }
  }
  FREE(noise);
  cronTime(&end);
  if (OK != tapi->disconnect(tsession)) {
    fprintf(stderr,
	    _("`%s': Could not disconnect.\n"),
	    tapi->transName);
    *res = SYSERR;
    SEMAPHORE_FREE(sem);
    return;
  }
  SEMAPHORE_FREE(sem);
  printf(_("`%s' transport OK.  It took %ums to transmit %d messages of %d bytes each.\n"),
	 tapi->transName,
	 (unsigned int) ((end - start)/cronMILLIS),
	 getConfigurationInt("TRANSPORT-CHECK",
			     "REPEAT"),
	 expectedSize);
}

static void pingCallback(void * unused) {
#if DEBUG_TRANSPORT_CHECK
  LOG(LOG_DEBUG,
      "PONG callback called!\n");
#endif
  ok = YES;
  SEMAPHORE_UP(sem);
}

static void testPING(P2P_hello_MESSAGE * xhelo,
		     int * stats) {
  TSession * tsession;
  P2P_hello_MESSAGE * helo;
  P2P_hello_MESSAGE * myHelo;
  P2P_MESSAGE_HEADER * ping;
  char * msg;
  int len;
  PeerIdentity peer;

  if (testConfigurationString("GNUNET-TRANSPORT-CHECK",
			      "VERBOSE",
			      "YES")) {
    char * str;
    str = transport->heloToString(xhelo);
    fprintf(stderr,
	    _("\nContacting `%s'."),
	    str);
    FREE(str);
  } else
    fprintf(stderr, ".");
  helo = MALLOC(ntohs(xhelo->header.size));
  memcpy(helo, xhelo, ntohs(xhelo->header.size));

  stats[0]++; /* one more seen */
  if (NO == transport->isAvailable(ntohs(helo->protocol))) {
    fprintf(stderr,
	    _(" Transport %d not available\n"),
	    ntohs(helo->protocol));
    FREE(helo);
    return;
  }
  myHelo = transport->createhello(ntohs(xhelo->protocol));
  if (myHelo == NULL) {
    FREE(helo);
    return;
  }
  if (testConfigurationString("GNUNET-TRANSPORT-CHECK",
			      "VERBOSE",
			      "YES"))
    fprintf(stderr, ".");

  stats[1]++; /* one more with transport 'available' */
  tsession = NULL;
  peer = helo->senderIdentity;
  tsession = transport->connect(helo);
  FREE(helo);
  if (tsession == NULL) {
    fprintf(stderr,
	    _(" Connection failed\n"));
    return;
  }
  if (tsession == NULL) {
    BREAK();
    fprintf(stderr,
	    _(" Connection failed (bug?)\n"));
    return;
  }
  if (testConfigurationString("GNUNET-TRANSPORT-CHECK",
			      "VERBOSE",
			      "YES"))
    fprintf(stderr, ".");

  sem = SEMAPHORE_NEW(0);

  ping = pingpong->pingUser(&peer,
			    &pingCallback,
			    NULL,
			    YES);
  len = ntohs(ping->size) + ntohs(myHelo->header.size);
  msg = MALLOC(len);
  memcpy(msg,
	 myHelo,
	 ntohs(myHelo->header.size));
  memcpy(&msg[ntohs(myHelo->header.size)],
	 ping,
	 ntohs(ping->size));
  FREE(myHelo);
  FREE(ping);
  /* send ping */
  ok = NO;
#if DEBUG_TRANSPORT_CHECK
  LOG(LOG_DEBUG,
      "Sending PING\n");
#endif
  if (OK != sendPlaintext(tsession,
			  msg,
			  len)) {
    fprintf(stderr,
	    "Send failed.\n");
    FREE(msg);
    transport->disconnect(tsession);
    return;
  }
  FREE(msg);
  if (testConfigurationString("GNUNET-TRANSPORT-CHECK",
			      "VERBOSE",
			      "YES"))
    fprintf(stderr, ".");
  /* check: received pong? */
#if DEBUG_TRANSPORT_CHECK
  LOG(LOG_DEBUG,
      "Waiting for PONG\n");
#endif
  terminate = NO;
  addCronJob((CronJob)&semUp,
	     timeout,
	     5 * cronSECONDS,
	     sem);
  SEMAPHORE_DOWN(sem);

  if (testConfigurationString("GNUNET-TRANSPORT-CHECK",
			      "VERBOSE",
			      "YES")) {
    if (ok != YES)
      FPRINTF(stderr,
	      _("No reply received within %llums.\n"),
	      timeout);
  }
  suspendCron();
  delCronJob((CronJob)&semUp,
	     5 * cronSECONDS,
	     sem);
  resumeCron();
  SEMAPHORE_FREE(sem);
  sem = NULL;
  transport->disconnect(tsession);
  if (ok == YES)
    stats[2]++;
}

/**
 * Perform option parsing from the command line.
 */
static int parser(int argc,
		  char * argv[]) {
  int cont = OK;
  int c;

  /* set the 'magic' code that indicates that
     this process is 'gnunetd' (and not any of
     the user-tools).  Needed such that we use
     the right configuration file... */
  FREENONNULL(setConfigurationString("GNUNETD",
				     "_MAGIC_",
				     "YES"));

  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      { "config",  1, 0, 'c' },
      { "help",    0, 0, 'h' },
      { "loglevel",1, 0, 'L' },
      { "ping",    0, 0, 'p' },
      { "Xport",   1, 0, 'P' },
      { "repeat",  1, 0, 'r' },
      { "size",    1, 0, 's'},
      { "transport", 1, 0, 't' },
      { "timeout", 1, 0, 'T' },
#ifndef MINGW	/* not supported */ 
      { "user", 0, 0, 'u' },
#endif
      { "version", 0, 0, 'v' },
      { "verbose", 0, 0, 'V' },
      { "Xrepeat", 1, 0, 'X' },
      { 0,0,0,0 }
    };

    c = GNgetopt_long(argc,
		      argv,
		      "vhc:L:t:r:s:X:P:pVT:",
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
    case 'h': {
      static Help help[] = {
	HELP_CONFIG,
	HELP_HELP,
	HELP_LOGLEVEL,
	{ 'p', "ping", NULL,
	  gettext_noop("ping peers from HOSTLISTURL that match transports") },
	{ 'r', "repeat", "COUNT",
	  gettext_noop("send COUNT messages") },
	{ 's', "size", "SIZE",
	  gettext_noop("send messages with SIZE bytes payload") },
	{ 't', "transport", "TRANSPORT",
	  gettext_noop("specifies which TRANSPORT should be tested") },
	{ 'T', "timeout", "MS",
	  gettext_noop("specifies after how many MS to time-out") },
#ifndef MINGW	/* not supported */
    { 'u', "user", "LOGIN",
      gettext_noop("run as user LOGIN") },
#endif
	HELP_VERSION,
        HELP_VERBOSE,
	HELP_END,
      };
      formatHelp("gnunet-transport-check [OPTIONS]",
		 _("Tool to test if GNUnet transport services are operational."),
		 help);
      cont = SYSERR;
      break;
    }
    case 'L':
      FREENONNULL(setConfigurationString("GNUNETD",
					 "LOGLEVEL",
					 GNoptarg));
      break;
    case 'p':
      FREENONNULL(setConfigurationString("TRANSPORT-CHECK",
					 "PING",
					 "YES"));
      break;
    case 'P':{
      unsigned int port;
      if (1 != sscanf(GNoptarg, "%ud", &port)) {
	LOG(LOG_FAILURE,
	    "You must pass a number to the -P option.\n");
	return SYSERR;
      } else {
	setConfigurationInt("TCP", "PORT", port);
	setConfigurationInt("UDP", "PORT", port);
	setConfigurationInt("TCP6", "PORT", port);
	setConfigurationInt("UDP6", "PORT", port);
	setConfigurationInt("HTTP", "PORT", port);
      }
      break;
    }
    case 'r':{
      unsigned int repeat;
      if (1 != sscanf(GNoptarg, "%ud", &repeat)) {
	LOG(LOG_FAILURE,
	    _("You must pass a number to the `%s' option.\n"),
	    "-r");
	return SYSERR;
      } else {
	setConfigurationInt("TRANSPORT-CHECK",
			    "REPEAT",
			    repeat);
      }
      break;
    }
    case 's':{
      unsigned int size;
      if (1 != sscanf(GNoptarg, "%ud", &size)) {
	LOG(LOG_FAILURE,
	    _("You must pass a number to the `%s' option.\n"),
	    "-s");
	return SYSERR;
      } else {
	if (size == 0)
	  size = 1;
	expectedSize = size;
	expectedValue = MALLOC(size);
	expectedValue[--size] = '\0';
	while (size > 0)
	  expectedValue[--size] = 'A';
      }
      break;
    }
    case 'T':{
      if (1 != SSCANF(GNoptarg, "%llu", &timeout)) {
	LOG(LOG_FAILURE,
	    _("You must pass a number to the `%s' option.\n"),
	    "-T");
	return SYSERR;
      }
      break;
    }
    case 't':
      FREENONNULL(setConfigurationString("GNUNETD",
					 "TRANSPORTS",
					 GNoptarg));
      break;
#ifndef MINGW	/* not supported */
    case 'u':
      changeUser(GNoptarg);
      break;
#endif
    case 'v':
      printf("gnunet-transport-check v%s\n",
	     VERSION);
      cont = SYSERR;
      break;
    case 'V':
      FREENONNULL(setConfigurationString("GNUNET-TRANSPORT-CHECK",
					 "VERBOSE",
					 "YES"));
      break;
    case 'X':{
      unsigned int repeat;
      if (1 != sscanf(GNoptarg, "%ud", &repeat)) {
	LOG(LOG_FAILURE,
	    _("You must pass a number to the `%s' option.\n"),
	    "-X");
	return SYSERR;
      } else {
	setConfigurationInt("TRANSPORT-CHECK",
			    "X-REPEAT",
			    repeat);
      }
      break;
    }
    default:
      LOG(LOG_FAILURE,
	  _("Use --help to get a list of options.\n"));
      cont = SYSERR;
    } /* end of parsing commandline */
  }
  if (GNoptind < argc) {
    LOG(LOG_WARNING,
	_("Invalid arguments: "));
    while (GNoptind < argc)
      LOG(LOG_WARNING,
	  "%s ", argv[GNoptind++]);
    LOG(LOG_FATAL,
	_("Invalid arguments. Exiting.\n"));
    return SYSERR;
  }
  return cont;
}


int main(int argc, char *argv[]) {
  int res;
  int Xrepeat;
  char * trans;
  char * user;
  int ping;
  int stats[3];

  if (OK != initUtil(argc, argv, &parser)) {
    return SYSERR;
  }
#ifndef MINGW
  user = getConfigurationString("GNUNETD", "USER");
  if (user && strlen(user))
    changeUser(user);
  FREENONNULL(user);
#endif

  if (expectedValue == NULL) {
    expectedValue = STRDUP(DEFAULT_MSG);
    expectedSize = strlen(DEFAULT_MSG);
  }

  trans = getConfigurationString("GNUNETD",
				 "TRANSPORTS");
  if (trans == NULL)
    errexit(_("You must specify a non-empty set of transports to test!\n"));
  ping = testConfigurationString("TRANSPORT-CHECK",
				 "PING",
				 "YES");
  if (! ping)
    printf(_("Testing transport(s) %s\n"),
	   trans);
  else
    printf(_("Available transport(s): %s\n"),
	   trans);
  FREE(trans);
  if (! ping) {
    /* disable blacklists (loopback is often blacklisted)... */
    FREENONNULL(setConfigurationString("TCP",
				       "BLACKLIST",
				       NULL));
    FREENONNULL(setConfigurationString("UDP",
				       "BLACKLIST",
				       NULL));
    FREENONNULL(setConfigurationString("TCP6",
				       "BLACKLIST",
				       NULL));
    FREENONNULL(setConfigurationString("UDP6",
				       "BLACKLIST",
				       NULL));
    FREENONNULL(setConfigurationString("HTTP",
				       "BLACKLIST",
				       NULL));
  }
  initCore();
  initConnection();
  registerPlaintextHandler(P2P_PROTO_noise,
			   &noiseHandler);
  enableCoreProcessing();
  identity = requestService("identity");
  transport = requestService("transport");
  pingpong = requestService("pingpong");
  startCron();

  Xrepeat = getConfigurationInt("TRANSPORT-CHECK",
				"X-REPEAT");
  if (Xrepeat == 0)
    Xrepeat = 1;
  res = OK;
  if (ping) {
    bootstrap = requestService("bootstrap");

    stats[0] = 0;
    stats[1] = 0;
    stats[2] = 0;
    bootstrap->bootstrap((hello_Callback)&testPING,
			 &stats[0]);
    printf(_("%d out of %d peers contacted successfully (%d times transport unavailable).\n"),
	   stats[2],
	   stats[1],
	   stats[0] - stats[1]);
    releaseService(bootstrap);
  } else {
    while (Xrepeat-- > 0)
      transport->forEach((TransportCallback)&testTAPI,
			 &res);
  }
  stopCron();
  releaseService(identity);
  releaseService(transport);
  releaseService(pingpong);
  disableCoreProcessing();
  unregisterPlaintextHandler(P2P_PROTO_noise,
			     &noiseHandler);
  doneConnection();
  doneCore();
  doneUtil();
  FREE(expectedValue);
  if (res == OK)
    return 0;
  else
    return -1;
}


/* end of gnunet-transport-check */
