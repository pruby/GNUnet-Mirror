/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/vpn/gnunet-vpn.c
 * @brief Utility to admin VPN
 * @author Michael John Wensley
 */

#include "gnunet_util.h"
#include "platform.h"

#define TEMPLATE_VERSION "2006072900"

#define buf ((CS_MESSAGE_HEADER*)&buffer)

/**
 * Most are commands availabe to clients
 * except VPN_MSG (general loggable output) and
 * VPN_REPLY = output from a command.
 * The commands output their last using their own code
 * instead of the VPN_REPLY so the UI knows it has
 * seen all the output.
 */
#define CS_PROTO_VPN_MSG 0xf0
#define CS_PROTO_VPN_REPLY 0xf1
#define CS_PROTO_VPN_DEBUGOFF 0xf2
#define CS_PROTO_VPN_DEBUGON 0xf3
#define CS_PROTO_VPN_TUNNELS 0xf4
#define CS_PROTO_VPN_ROUTES 0xf5
#define CS_PROTO_VPN_REALISED 0xf6
#define CS_PROTO_VPN_RESET 0xf7
#define CS_PROTO_VPN_REALISE 0xf8
#define CS_PROTO_VPN_ADD 0xf9
#define CS_PROTO_VPN_TRUST 0xfa

static Semaphore * doneSem;
static Semaphore * cmdAck;
static Semaphore * exitCheck;
static Mutex lock;
static int wantExit;
static int silent = NO;

/**
 * Parse the options, set the timeout.
 * @param argc the number of options
 * @param argv the option list (including keywords)
 * @return OK on error, SYSERR if we should exit
 */
static int parseOptions(int argc,
			char ** argv) {
  int option_index;
  int c;

  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  while (1) {
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "silent", 0, 0, 's' },
      { 0,0,0,0 }
    };
    option_index=0;
    c = GNgetopt_long(argc,
		      argv,
		      "svhdc:L:H:t",
		      long_options,
		      &option_index);
    if (c == -1)
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'h': {
      static Help help[] = {
	HELP_CONFIG,
	HELP_HELP,
	HELP_LOGLEVEL,
	{ 's', "silent", NULL,
	  gettext_noop("Suppress display of asynchronous log messages") },
	HELP_VERSION,
	HELP_END,
      };
      formatHelp("gnunet-vpn [OPTIONS]",
		 _("VPN over GNUnet."),
		 help);

      return SYSERR;
    }
    case 'v':
      printf("GNUnet v%s, gnunet-vpn v%s\n",
	     VERSION,
	     TEMPLATE_VERSION);
      return SYSERR;
    case 's':
      silent = YES;
      break;
    default:
      LOG(LOG_FAILURE,
	  _("Use --help to get a list of options.\n"));
      return -1;
    } /* end of parsing commandline */
  } /* while (1) */
  return OK;
}

static void * receiveThread(GNUNET_TCP_SOCKET * sock) {
  /* printf("Welcome to the VPN console: (Ctrl-D to exit)\n"); */
  /* CS_MESSAGE_HEADER *buffer; */
  char buffer[MAX_BUFFER_SIZE];
  CS_MESSAGE_HEADER* bufp = buf;
      
  /* buffer = MALLOC(MAX_BUFFER_SIZE); */
  while (OK == readFromSocket(sock, &bufp)) {
	switch (ntohs(buf->type)) {
		case CS_PROTO_VPN_DEBUGOFF:
		case CS_PROTO_VPN_DEBUGON:
		case CS_PROTO_VPN_TUNNELS:
		case CS_PROTO_VPN_ROUTES:
		case CS_PROTO_VPN_REALISED:
		case CS_PROTO_VPN_RESET:
		case CS_PROTO_VPN_REALISE:
		case CS_PROTO_VPN_ADD:
		case CS_PROTO_VPN_TRUST:
			if (ntohs(buf->size) > sizeof(CS_MESSAGE_HEADER)) {
			fwrite( buffer+sizeof(CS_MESSAGE_HEADER),
				sizeof(char),
				ntohs(buf->size)-sizeof(CS_MESSAGE_HEADER),
				stdout);
			}

			SEMAPHORE_UP(cmdAck);
			SEMAPHORE_DOWN(exitCheck);
			MUTEX_LOCK(&lock);
			if (wantExit == YES) {
				MUTEX_UNLOCK(&lock);
				SEMAPHORE_UP(doneSem);
				return NULL;
			}
			MUTEX_UNLOCK(&lock);
		break;;
		case CS_PROTO_VPN_MSG:
			if (silent == YES) break;;
		case CS_PROTO_VPN_REPLY:
		
		if (ntohs(buf->size) > sizeof(CS_MESSAGE_HEADER)) {
			fwrite( buffer+sizeof(CS_MESSAGE_HEADER),
				sizeof(char),
				ntohs(buf->size)-sizeof(CS_MESSAGE_HEADER),
				stdout);
		}
		break;;
	}
  }
  /* FREE(buffer); */
  SEMAPHORE_UP(doneSem);
  return NULL;
}

/**
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return value from gnunet-template: 0: ok, -1: error
 */
int main(int argc, char ** argv) {
  GNUNET_TCP_SOCKET * sock;
  PTHREAD_T messageReceiveThread;
  void * unused;
  char buffer[sizeof(CS_MESSAGE_HEADER) + 1024];
  int rancommand = 0;

  doneSem = SEMAPHORE_NEW(0);
  cmdAck = SEMAPHORE_NEW(0);
  exitCheck = SEMAPHORE_NEW(0);
  MUTEX_CREATE(&lock);
  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return 0; /* parse error, --help, etc. */


  sock = getClientSocket();
  wantExit = NO;

  if (0 != PTHREAD_CREATE(&messageReceiveThread,
			  (PThreadMain) &receiveThread,
			  sock,
			  128 * 1024)) DIE_STRERROR("pthread_create");


  /* accept keystrokes from user and send to gnunetd */
  while (NULL != fgets(buffer, 1024, stdin)) {
	if (rancommand) {
		rancommand = 0;
		SEMAPHORE_UP(exitCheck);
	}
	if (strncmp(buffer, "debug0", 6) == 0) {
		((CS_MESSAGE_HEADER*)&buffer)->type = htons(CS_PROTO_VPN_DEBUGOFF);
		((CS_MESSAGE_HEADER*)&buffer)->size = htons(sizeof(CS_MESSAGE_HEADER));
		if (SYSERR == writeToSocket(sock, (CS_MESSAGE_HEADER*)&buffer)) return -1;
		rancommand = 1;
		SEMAPHORE_DOWN(cmdAck);
	} else if (strncmp(buffer, "debug1", 6) == 0) {
		((CS_MESSAGE_HEADER*)&buffer)->type = htons(CS_PROTO_VPN_DEBUGON);
		((CS_MESSAGE_HEADER*)&buffer)->size = htons(sizeof(CS_MESSAGE_HEADER));
		if (SYSERR == writeToSocket(sock, (CS_MESSAGE_HEADER*)&buffer)) return -1;
		rancommand = 1;
		SEMAPHORE_DOWN(cmdAck);
	} else if (strncmp(buffer, "tunnels", 7) == 0) {
		((CS_MESSAGE_HEADER*)&buffer)->type = htons(CS_PROTO_VPN_TUNNELS);
		((CS_MESSAGE_HEADER*)&buffer)->size = htons(sizeof(CS_MESSAGE_HEADER));
		if (SYSERR == writeToSocket(sock, (CS_MESSAGE_HEADER*)&buffer)) return -1;
		rancommand = 1;
		SEMAPHORE_DOWN(cmdAck);
	} else if (strncmp(buffer, "route", 5) == 0) {
		((CS_MESSAGE_HEADER*)&buffer)->type = htons(CS_PROTO_VPN_ROUTES);
		((CS_MESSAGE_HEADER*)&buffer)->size = htons(sizeof(CS_MESSAGE_HEADER));
		if (SYSERR == writeToSocket(sock, (CS_MESSAGE_HEADER*)&buffer)) return -1;
		rancommand = 1;
		SEMAPHORE_DOWN(cmdAck);
	} else if (strncmp(buffer, "realised", 8) == 0) {
		((CS_MESSAGE_HEADER*)&buffer)->type = htons(CS_PROTO_VPN_REALISED);
		((CS_MESSAGE_HEADER*)&buffer)->size = htons(sizeof(CS_MESSAGE_HEADER));
		if (SYSERR == writeToSocket(sock, (CS_MESSAGE_HEADER*)&buffer)) return -1;
		rancommand = 1;
		SEMAPHORE_DOWN(cmdAck);
	} else if (strncmp(buffer, "reset", 5) == 0) {
		((CS_MESSAGE_HEADER*)&buffer)->type = htons(CS_PROTO_VPN_RESET);
		((CS_MESSAGE_HEADER*)&buffer)->size = htons(sizeof(CS_MESSAGE_HEADER));
		if (SYSERR == writeToSocket(sock, (CS_MESSAGE_HEADER*)&buffer)) return -1;
		rancommand = 1;
		SEMAPHORE_DOWN(cmdAck);
	} else if (strncmp(buffer, "realise", 7) == 0) {
		((CS_MESSAGE_HEADER*)&buffer)->type = htons(CS_PROTO_VPN_REALISE);
		((CS_MESSAGE_HEADER*)&buffer)->size = htons(sizeof(CS_MESSAGE_HEADER));
		if (SYSERR == writeToSocket(sock, (CS_MESSAGE_HEADER*)&buffer)) return -1;
		rancommand = 1;
		SEMAPHORE_DOWN(cmdAck);
	} else if (strncmp(buffer, "trust", 5) == 0) {
		((CS_MESSAGE_HEADER*)&buffer)->type = htons(CS_PROTO_VPN_TRUST);
		((CS_MESSAGE_HEADER*)&buffer)->size = htons(sizeof(CS_MESSAGE_HEADER));
		if (SYSERR == writeToSocket(sock, (CS_MESSAGE_HEADER*)&buffer)) return -1;
		rancommand = 1;
		SEMAPHORE_DOWN(cmdAck);
	} else if (strncmp(buffer, "add ", 4) == 0) {
		/* message header is 4 bytes long, we overwrite "add " with it
		 * also don't include \r or \n in the message
		 */
		if (strlen(&buffer[4]) > 1) {
			((CS_MESSAGE_HEADER*)&buffer)->type = htons(CS_PROTO_VPN_ADD);
			((CS_MESSAGE_HEADER*)&buffer)->size = htons(sizeof(CS_MESSAGE_HEADER) + strlen(&buffer[5]));
			if (SYSERR == writeToSocket(sock, (CS_MESSAGE_HEADER*)&buffer)) return -1;
			rancommand = 1;
			SEMAPHORE_DOWN(cmdAck);
		} else {
			printf("add requires hash as a parameter!\n");
		}
	} else {
		printf("debug0, debug1, tunnels, route, realise, realised, reset, trust, add <hash>\n");
	}
  }
  /* wait for shutdown... */
  if (rancommand) {
    MUTEX_LOCK(&lock);
    wantExit = YES;
    MUTEX_UNLOCK(&lock);
    SEMAPHORE_UP(exitCheck);
  }

  /* we can't guarantee that this can be called while the other thread is waiting for read */
  closeSocketTemporarily(sock);
  SEMAPHORE_DOWN(doneSem);

  SEMAPHORE_FREE(doneSem);
  SEMAPHORE_FREE(cmdAck);
  SEMAPHORE_FREE(exitCheck);
  MUTEX_DESTROY(&lock);
  PTHREAD_JOIN(&messageReceiveThread, &unused);
  releaseClientSocket(sock);

  doneUtil();
  return 0;
}

/* end of gnunet-template.c */
