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

#define TEMPLATE_VERSION "0.0.0"

#define CS_PROTO_VPN_MSG 0xfa

static Semaphore * doneSem;

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
      { 0,0,0,0 }
    };
    option_index=0;
    c = GNgetopt_long(argc,
		      argv,
		      "vhdc:L:H:t",
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
	{ 't', "longoptionname", "ARGUMENT",
	  gettext_noop("helptext for -t") },
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
    default:
      LOG(LOG_FAILURE,
	  _("Use --help to get a list of options.\n"));
      return -1;
    } /* end of parsing commandline */
  } /* while (1) */
  return OK;
}

static void * receiveThread(GNUNET_TCP_SOCKET * sock) {
  int i;
  CS_MESSAGE_HEADER *buffer;
  buffer = MALLOC(MAX_BUFFER_SIZE);
  while (OK == readFromSocket(sock, &buffer)) {
	if (ntohs(buffer->type) == CS_PROTO_VPN_MSG) {
		for (i = sizeof(CS_MESSAGE_HEADER); i < ntohs(buffer->size); i++) {
			putchar(*(((char*)buffer)+i));
		}
	}
  }
  FREE(buffer);
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

  doneSem = SEMAPHORE_NEW(0);
  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return 0; /* parse error, --help, etc. */
  sock = getClientSocket();

  if (0 != PTHREAD_CREATE(&messageReceiveThread,
			  (PThreadMain) &receiveThread,
			  sock,
			  128 * 1024)) DIE_STRERROR("pthread_create");


  /* accept keystrokes from user and send to gnunetd */
  ((CS_MESSAGE_HEADER*)&buffer)->type = htons(CS_PROTO_VPN_MSG);
  printf("Welcome to the VPN console: (Ctrl-D to exit)\n");
  while (1) {
	if (NULL == fgets(&buffer[sizeof(CS_MESSAGE_HEADER)], 1024, stdin)) break;
	((CS_MESSAGE_HEADER*)&buffer)->size = htons(sizeof(CS_MESSAGE_HEADER) + strlen(&buffer[sizeof(CS_MESSAGE_HEADER)]));
	if (SYSERR == writeToSocket(sock, (CS_MESSAGE_HEADER*)&buffer)) return -1;
  }
  /* wait for shutdown... */
  closeSocketTemporarily(sock);
  SEMAPHORE_DOWN(doneSem);
  SEMAPHORE_FREE(doneSem);
  PTHREAD_JOIN(&messageReceiveThread, &unused);
  releaseClientSocket(sock);

  doneUtil();
  return 0;
}

/* end of gnunet-template.c */
