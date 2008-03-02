/*
     This file is part of GNUnet.
     (C) 2007, 2008 Christian Grothoff (and other contributing authors)

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
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_directories.h"
#include "gnunet_chat_lib.h"

#define MAX_MESSAGE_LENGTH 1024

#define QUIT_COMMAND "quit"

static struct GNUNET_GC_Configuration *cfg;

static struct GNUNET_GE_Context *ectx;

static char *cfgFilename = GNUNET_DEFAULT_CLIENT_CONFIG_FILE;

static char *nickname;

static char *room_name = "gnunet";

/**
 * All gnunet-chat command line options
 */
static struct GNUNET_CommandLineOption gnunetchatOptions[] = {
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Join a chat on GNUnet.")),    /* -h */
  GNUNET_COMMAND_LINE_OPTION_HOSTNAME,  /* -H */
  GNUNET_COMMAND_LINE_OPTION_LOGGING,   /* -L */
  {'n', "nick", "NAME",
   gettext_noop ("set the nickname to use (required)"),
   1, &GNUNET_getopt_configure_set_string, &nickname},
  {'r', "room", "NAME",
   gettext_noop ("set the chat room to join"),
   1, &GNUNET_getopt_configure_set_string, &room_name},
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION), /* -v */
  GNUNET_COMMAND_LINE_OPTION_VERBOSE,
  GNUNET_COMMAND_LINE_OPTION_END,
};

/**
 * A message was sent in the chat to us.
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
 * @return GNUNET_OK to accept the message now, GNUNET_NO to
 *         accept (but user is away), GNUNET_SYSERR to signal denied delivery
 */
static int
receive_callback (void *cls,
                  struct GNUNET_CHAT_Room *room,
                  const char *senderNick,
                  const char *message,
                  GNUNET_CronTime timestamp, GNUNET_CHAT_MSG_OPTIONS options)
{
  fprintf (stdout, _("`%s' said: %s\n"), senderNick, message);
  return GNUNET_OK;
}

/**
 * Message delivery confirmations.
 *
 * @param timestamp when was the message sent?
 * @param senderNick what is the nickname of the receiver?
 * @param message the message (maybe NULL)
 * @param room in which room was the message received?
 * @param options what were the options of the message
 * @param response what was the receivers response (GNUNET_OK, GNUNET_NO, GNUNET_SYSERR).
 * @param receipt signature confirming delivery (maybe NULL, only
 *        if confirmation was requested)
 * @return GNUNET_OK to continue, GNUNET_SYSERR to refuse processing further
 *         confirmations from anyone for this message
 */
static int
confirmation_callback (void *cls,
                       struct GNUNET_CHAT_Room *room,
                       const char *receiverNick,
                       const GNUNET_RSA_PublicKey * receiverKey,
                       const char *message,
                       GNUNET_CronTime timestamp,
                       GNUNET_CHAT_MSG_OPTIONS options,
                       int response, const GNUNET_RSA_Signature * receipt)
{
  return GNUNET_OK;
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
  struct GNUNET_CHAT_Room *room;
  struct GNUNET_RSA_PrivateKey *my_priv;
  GNUNET_RSA_PublicKey my_pub;
  char message[MAX_MESSAGE_LENGTH + 1];

  /* GNUNET_disable_entropy_gathering (); */

  if (GNUNET_SYSERR == GNUNET_init (argc,
                                    argv,
                                    "gnunet-chat [OPTIONS]",
                                    &cfgFilename, gnunetchatOptions, &ectx,
                                    &cfg))
    return -1;
  if (nickname == NULL)
    {
      fprintf (stderr, _("You must specify a nickname\n"));
      GNUNET_fini (ectx, cfg);
      return -1;
    }

  fprintf (stderr, "Generating public/private key pair\n");
  /* FIXME: try to read key from disk! */
  my_priv = GNUNET_RSA_create_key ();
  GNUNET_RSA_get_public_key (my_priv, &my_pub);
  room = GNUNET_CHAT_join_room (ectx,
                                cfg,
                                nickname, room_name,
                                &my_pub, my_priv, "", &receive_callback,
                                NULL);
  if (room == NULL)
    {
      fprintf (stderr, _("Failed to join room `%s'\n"), room_name);
      GNUNET_RSA_free_key (my_priv);
      GNUNET_fini (ectx, cfg);
      return -1;
    }
  fprintf (stdout,
           _
           ("Joined room `%s'.\nType message and hit return to send.\nType `%s' when ready to quit.\n"),
           room_name, QUIT_COMMAND);
  /* read messages from command line and send */
  while ((0 != strcmp (message, QUIT_COMMAND)) &&
         (GNUNET_shutdown_test () == GNUNET_NO))
    {
      memset (message, 0, MAX_MESSAGE_LENGTH + 1);
      if (NULL == fgets (message, MAX_MESSAGE_LENGTH, stdin))
        break;
      if (0 == strcmp (message, QUIT_COMMAND))
        break;
      if (message[strlen (message) - 1] == '\n')
        message[strlen (message) - 1] = '\0';
      if (GNUNET_OK != GNUNET_CHAT_send_message (room,
                                                 message,
                                                 &confirmation_callback,
                                                 NULL,
                                                 GNUNET_CHAT_MSG_OPTION_NONE,
                                                 NULL))
        fprintf (stderr, _("Failed to send message.\n"));
    }

  GNUNET_CHAT_leave_room (room);
  GNUNET_RSA_free_key (my_priv);
  GNUNET_fini (ectx, cfg);
  return 0;
}

/* end of gnunet-chat.c */
