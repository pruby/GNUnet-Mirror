/*
     This file is part of GNUnet.
     (C) 2001, 2002 Christian Grothoff (and other contributing authors)

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
 * @file applications/chat/gnunet-chat.c
 * @brief Chat command line tool
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "chat.h"

#define CHAT_VERSION "0.0.3"

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
      { "nickname", 1, 0, 'n' },
      { 0,0,0,0 }
    };
    option_index=0;
    c = GNgetopt_long(argc,
		      argv,
		      "vhdc:L:H:n:",
		      long_options,
		      &option_index);
    if (c == -1)
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'n':
      FREENONNULL(setConfigurationString("GNUNET-CHAT",
					 "NICK",
					 GNoptarg));
      break;
    case 'v':
      printf("GNUnet v%s, gnunet-chat v%s\n",
	     VERSION,
	     CHAT_VERSION);
      return SYSERR;
    case 'h': {
      static Help help[] = {
	HELP_CONFIG,
	HELP_HELP,
	HELP_LOGLEVEL,
	{ 'n', "nickname", NULL,
	  gettext_noop("specify nickname") },
	HELP_VERSION,
	HELP_END,
      };
      formatHelp("gnunet-chat [OPTIONS]",
		 _("Start GNUnet chat client."),
		 help);
      return SYSERR;
    }
    default:
      LOG(LOG_FAILURE,
	  _("Use --help to get a list of options.\n"));
      return -1;
    } /* end of parsing commandline */
  } /* while (1) */
  return OK;
}

static void * receiveThread(void * arg) {
  GNUNET_TCP_SOCKET * sock = arg;
  CS_chat_MESSAGE * buffer;

  buffer = MALLOC(MAX_BUFFER_SIZE);
  while (OK == readFromSocket(sock,
			      (CS_MESSAGE_HEADER **)&buffer)) {
    char timebuf[64];
    time_t timetmp;
    struct tm * tmptr;
	
    time(&timetmp);
    tmptr = localtime(&timetmp);
    strftime(timebuf,
             64,
             "%b %e %H:%M ",
             tmptr);
			
   if ( (ntohs(buffer->header.size) != sizeof(CS_chat_MESSAGE)) ||
        (ntohs(buffer->header.type) != CS_PROTO_chat_MSG) )
      continue;
    buffer->nick[CHAT_NICK_LENGTH-1] = '\0';
    buffer->message[CHAT_MSG_LENGTH-1] = '\0';
    printf("[%s][%s]: %s",
           timebuf,
	   &buffer->nick[0],
	   &buffer->message[0]);
  }
  FREE(buffer);
  SEMAPHORE_UP(doneSem);
  printf("CHAT receive loop ends!\n");
  return NULL;
}

/**
 * The main function to search for files on GNet.
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return value from gnunetsearch: 0: ok, -1: error
 */
int main(int argc, char ** argv) {
  GNUNET_TCP_SOCKET * sock;
  PTHREAD_T messageReceiveThread;
  void * unused;
  CS_chat_MESSAGE msg;
  char * nick;

  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return 0; /* parse error, --help, etc. */
  sock = getClientSocket();
  if (sock == NULL)
    errexit(_("Could not connect to gnunetd.\n"));

  nick = getConfigurationString("GNUNET-CHAT", "NICK");
  if (nick == NULL)
    errexit(_("You must specify a nickname (use option `%s').\n"),
	    "-n");

  doneSem = SEMAPHORE_NEW(0);
  if (0 != PTHREAD_CREATE(&messageReceiveThread,
			  &receiveThread,
			  sock,
			  128 * 1024))
    DIE_STRERROR("pthread_create");

  memset(&msg,
	 0,
	 sizeof(CS_chat_MESSAGE));
  memcpy(&msg.message[0],
	 "Hi!\n",
	 strlen("Hi!\n"));
  msg.header.size
    = htons(sizeof(CS_chat_MESSAGE));
  msg.header.type
    = htons(CS_PROTO_chat_MSG);
  memcpy(&msg.nick[0],
	 nick,
	 strlen(nick));

  /* send first "Hi!" message to gnunetd to indicate "join" */
  if (SYSERR == writeToSocket(sock,
			      &msg.header))
    errexit(_("Could not send join message to gnunetd\n"));

  /* read messages from command line and send */
  while (1) {
    memset(&msg.message, 0, 1024);
    if (NULL == fgets(&msg.message[0], 1024, stdin))
      break;
    if (SYSERR == writeToSocket(sock,
				&msg.header))
      errexit(_("Could not send message to gnunetd\n"));
  }
  closeSocketTemporarily(sock);
  SEMAPHORE_DOWN(doneSem);
  SEMAPHORE_FREE(doneSem);
  PTHREAD_JOIN(&messageReceiveThread, &unused);
  releaseClientSocket(sock);

  doneUtil();
  return 0;
}

/* end of gnunet-chat.c */
