/*
     This file is part of GNUnet.
     (C) 2007 Christian Grothoff (and other contributing authors)

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
 * @brief Minimal chat command line tool
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_chat_lib.h"

static struct GC_Configuration *cfg;

static struct GE_Context *ectx;

static char * cfgFilename = DEFAULT_CLIENT_CONFIG_FILE;

static char * nickname;

static char * roomname = "gnunet";

/**
 * All gnunet-chat command line options
 */
static struct CommandLineOption gnunetchatOptions[] = {
  COMMAND_LINE_OPTION_HELP (gettext_noop ("Join a chat on GNUnet.")),      /* -h */
  COMMAND_LINE_OPTION_HOSTNAME, /* -H */
  COMMAND_LINE_OPTION_LOGGING,  /* -L */
  {'n', "nick", "NAME",
   gettext_noop ("set the nickname to use (requred)"),
   1, &gnunet_getopt_configure_set_string, &nickname},
  {'r', "room", "NAME",
   gettext_noop ("set the chat room to join (requred)"),
   1, &gnunet_getopt_configure_set_string, &roomname},
  COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION),        /* -v */
  COMMAND_LINE_OPTION_VERBOSE,
  COMMAND_LINE_OPTION_END,
};

/**
 * A message was send in the chat to us.
 *
 * @param timestamp when was the message sent?
 * @param senderNick what is the nickname of the sender? (maybe NULL)
 * @param message the message (maybe NULL, especially if confirmation
 *        is requested before delivery; the protocol will ensure
 *        that this function is called again with the full message
 *        if a confirmation is transmitted; if the message is NULL,
 *        the user is merely asked if engaging in the exchange is ok
 * @param room in which room was the message received?
 * @param options options for the message
 * @return OK to accept the message now, NO to 
 *         accept (but user is away), SYSERR to signal denied delivery
 */
static int receive_callback(void * cls,
			    struct GNUNET_CHAT_Room * room,
			    const char * senderNick,
			    const char * message,
			    cron_t timestamp,
			    GNUNET_CHAT_MSG_OPTIONS options) {
  fprintf(stdout,
	  "%s: %s\n",
	  senderNick,
	  message);
  return OK;
}

/**
 * Message delivery confirmations.
 *
 * @param timestamp when was the message sent?
 * @param senderNick what is the nickname of the receiver?
 * @param message the message (maybe NULL)
 * @param room in which room was the message received?
 * @param options what were the options of the message
 * @param response what was the receivers response (OK, NO, SYSERR).
 * @param receipt signature confirming delivery (maybe NULL, only
 *        if confirmation was requested)
 * @return OK to continue, SYSERR to refuse processing further
 *         confirmations from anyone for this message
 */
static int confirmation_callback(void * cls,
				 struct GNUNET_CHAT_Room * room,
				 const char * receiverNick,
				 const PublicKey * receiverKey,
				 const char * message,
				 cron_t timestamp,
				 GNUNET_CHAT_MSG_OPTIONS options,
				 int response,
				 const Signature * receipt) {
  return OK;
}

/**
 * GNUnet-chat main.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return  0: ok, otherwise error
 */
int
main (int argc, char **argv)
{
  struct GNUNET_CHAT_Room * room;
  PublicKey * my_pub;
  struct PrivateKey * my_priv;
  char message[1024];
  
  if (SYSERR == GNUNET_init (argc, 
			     argv,
			     "gnunet-chat [OPTIONS]",
			     &cfgFilename,
			     gnunetchatOptions,
			     &ectx,
			     &cfg))
    return 1;                   /* parse error, --help, etc. */
  if (nickname == NULL) {
    fprintf(stderr,
	    _("You must specify a nickname\n"));
    return 1;
  }
  /* FIXME: load/generate private key! */
  room = GNUNET_CHAT_join_room(ectx,
			       cfg,
			       nickname,
			       my_pub,
			       my_priv,
			       "",
			       &receive_callback,
			       NULL);
  if (room == NULL) {
    fprintf(stderr,
	    _("Failed to join the room\n"));
    return 1;
  }

  /* read messages from command line and send */
  while (1)
    {
      memset (message, 0, 1024);
      if (NULL == fgets (message, 1023, stdin))
        break;
      if (OK != GNUNET_CHAT_send_message(room,
					 message,
					 &confirmation_callback,
					 NULL,
					 GNUNET_CHAT_MSG_OPTION_NONE,
					 NULL)) {
	fprintf(stderr,
		_("Failed to send message.\n"));
      }
    }
  GNUNET_CHAT_leave_room(room);
  GNUNET_fini(ectx, cfg);
  return 0;
}

/* end of gnunet-chat.c */
