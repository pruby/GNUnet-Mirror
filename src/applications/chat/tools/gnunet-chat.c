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
 * @file applications/chat/tools/gnunet-chat.c
 * @brief Minimal chat command line tool
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_directories.h"
#include "gnunet_chat_lib.h"

#define MAX_MESSAGE_LENGTH (32 * 1024)

static struct GNUNET_GC_Configuration *cfg;

static struct GNUNET_GE_Context *ectx;

static char *cfgFilename = GNUNET_DEFAULT_CLIENT_CONFIG_FILE;

static char *nickname;

static char *room_name;

static struct GNUNET_Mutex *lock;

static struct GNUNET_CHAT_Room *room;

static struct GNUNET_MetaData *meta;

struct UserList
{
  struct UserList *next;
  GNUNET_RSA_PublicKey pkey;
  int ignored;
};

static struct UserList *users;

struct ChatCommand
{
  const char *command;
  int (*Action) (const char *arguments, const void *xtra);
  const char *helptext;
};

static void
free_user_list ()
{
  struct UserList *next;
  while (users != NULL)
    {
      next = users->next;
      GNUNET_free (users);
      users = next;
    }
}

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
                  const GNUNET_HashCode * sender,
                  const struct GNUNET_MetaData *meta,
                  const char *message, GNUNET_CHAT_MSG_OPTIONS options)
{
  char *nick;
  const char *fmt;

  if (sender != NULL)
    nick = GNUNET_pseudonym_id_to_name (ectx, cfg, sender);
  else
    nick = GNUNET_strdup (_("anonymous"));
  fmt = NULL;
  switch (options)
    {
    case GNUNET_CHAT_MSG_OPTION_NONE:
    case GNUNET_CHAT_MSG_ANONYMOUS:
      fmt = _("`%s' said: %s\n");
      break;
    case GNUNET_CHAT_MSG_PRIVATE:
      fmt = _("`%s' said to you: %s\n");
      break;
    case GNUNET_CHAT_MSG_PRIVATE | GNUNET_CHAT_MSG_ANONYMOUS:
      fmt = _("`%s' said to you: %s\n");
      break;
    case GNUNET_CHAT_MSG_AUTHENTICATED:
      fmt = _("`%s' said for sure: %s\n");
      break;
    case GNUNET_CHAT_MSG_PRIVATE | GNUNET_CHAT_MSG_AUTHENTICATED:
      fmt = _("`%s' said to you for sure: %s\n");
      break;
    case GNUNET_CHAT_MSG_ACKNOWLEDGED:
      fmt = _("`%s' was confirmed that you received: %s\n");
      break;
    case GNUNET_CHAT_MSG_PRIVATE | GNUNET_CHAT_MSG_ACKNOWLEDGED:
      fmt = _("`%s' was confirmed that you and only you received: %s\n");
      break;
    case GNUNET_CHAT_MSG_AUTHENTICATED | GNUNET_CHAT_MSG_ACKNOWLEDGED:
      fmt = _("`%s' was confirmed that you received from him or her: %s\n");
      break;
    case GNUNET_CHAT_MSG_AUTHENTICATED | GNUNET_CHAT_MSG_PRIVATE | GNUNET_CHAT_MSG_ACKNOWLEDGED:
      fmt =
        _
        ("`%s' was confirmed that you and only you received from him or her: %s\n");
      break;
    case GNUNET_CHAT_MSG_OFF_THE_RECORD:
      fmt = _("`%s' said off the record: %s\n");
      break;
    default:
      fmt = _("<%s> said using an unknown message type: %s\n");
      break;
    }
  fprintf (stdout, fmt, nick, message);
  GNUNET_free (nick);
  return GNUNET_OK;
}

static int
member_list_callback (void *cls,
                      const struct GNUNET_MetaData *member_info,
                      const GNUNET_RSA_PublicKey * member_id,
                      GNUNET_CHAT_MSG_OPTIONS options)
{
  char *nick;
  GNUNET_HashCode id;
  struct UserList *pos;
  struct UserList *prev;

  GNUNET_hash (member_id, sizeof (GNUNET_RSA_PublicKey), &id);
  nick = GNUNET_pseudonym_id_to_name (ectx, cfg, &id);
  fprintf (stdout, member_info != NULL
           ? _("`%s' entered the room\n") : _("`%s' left the room\n"), nick);
  GNUNET_free (nick);
  GNUNET_mutex_lock (lock);
  if (member_info != NULL)
    {
      /* user joining */
      pos = GNUNET_malloc (sizeof (struct UserList));
      pos->next = users;
      pos->pkey = *member_id;
      pos->ignored = GNUNET_NO;
      users = pos;
    }
  else
    {
      /* user leaving */
      prev = NULL;
      pos = users;
      while ((pos != NULL) &&
             (0 != memcmp (&pos->pkey,
                           member_id, sizeof (GNUNET_RSA_PublicKey))))
        {
          prev = pos;
          pos = pos->next;
        }
      if (pos == NULL)
        {
          GNUNET_GE_BREAK (NULL, 0);
        }
      else
        {
          if (prev == NULL)
            users = pos->next;
          else
            prev->next = pos->next;
          GNUNET_free (pos);
        }
    }
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

/**
 * Message delivery confirmations.
 *
 * @param timestamp when was the message received?
 * @param message the message (maybe NULL)
 * @param room in which room was the message received?
 * @param receipt signature confirming delivery (maybe NULL, only
 *        if confirmation was requested)
 * @return GNUNET_OK to continue, GNUNET_SYSERR to refuse processing further
 *         confirmations from anyone for this message
 */
static int
confirmation_callback (void *cls,
                       struct GNUNET_CHAT_Room *room,
                       unsigned int orig_seq_number,
                       GNUNET_CronTime timestamp,
                       const GNUNET_HashCode * receiver,
                       const GNUNET_HashCode * msg_hash,
                       const GNUNET_RSA_Signature * receipt)
{
  return GNUNET_OK;
}

static int
do_transmit (const char *msg, const void *xtra)
{
  unsigned int seq;
  if (GNUNET_OK != GNUNET_CHAT_send_message (room,
                                             msg,
                                             GNUNET_CHAT_MSG_OPTION_NONE,
                                             NULL, &seq))
    fprintf (stderr, _("Failed to send message.\n"));
  return GNUNET_OK;
}

static int
do_join (const char *arg, const void *xtra)
{
  char *my_name;
  GNUNET_HashCode me;

  if (arg[0] == '#')
    arg++;                      /* ignore first hash */
  GNUNET_CHAT_leave_room (room);
  free_user_list ();
  GNUNET_free (room_name);
  room_name = GNUNET_strdup (arg);
  room = GNUNET_CHAT_join_room (ectx,
                                cfg,
                                nickname,
                                meta,
                                room_name,
                                -1,
                                &receive_callback, NULL,
                                &member_list_callback, NULL,
                                &confirmation_callback, NULL, &me);
  my_name = GNUNET_pseudonym_id_to_name (ectx, cfg, &me);
  fprintf (stdout, _("Joined room `%s' as user `%s'.\n"), room_name, my_name);
  GNUNET_free (my_name);
  return GNUNET_OK;
}

static int
do_nick (const char *msg, const void *xtra)
{
  char *my_name;
  GNUNET_HashCode me;

  GNUNET_CHAT_leave_room (room);
  free_user_list ();
  GNUNET_free (nickname);
  GNUNET_meta_data_destroy (meta);
  nickname = GNUNET_strdup (msg);
  meta = GNUNET_meta_data_create ();
  GNUNET_meta_data_insert (meta, EXTRACTOR_TITLE, nickname);
  room = GNUNET_CHAT_join_room (ectx,
                                cfg,
                                nickname,
                                meta,
                                room_name,
                                -1,
                                &receive_callback, NULL,
                                &member_list_callback, NULL,
                                &confirmation_callback, NULL, &me);
  my_name = GNUNET_pseudonym_id_to_name (ectx, cfg, &me);
  fprintf (stdout, _("Changed username to `%s'.\n"), my_name);
  GNUNET_free (my_name);
  return GNUNET_OK;
}

static int
do_unknown (const char *msg, const void *xtra)
{
  fprintf (stderr, _("Unknown command `%s'.\n"), msg);
  return GNUNET_OK;
}

static int
do_pm (const char *msg, const void *xtra)
{
  char *user;
  GNUNET_HashCode uid;
  GNUNET_HashCode pid;
  unsigned int seq;
  struct UserList *pos;

  if (NULL == strstr (msg, " "))
    {
      fprintf (stderr, _("Syntax: /msg USERNAME MESSAGE"));
      return GNUNET_OK;
    }
  user = GNUNET_strdup (msg);
  strstr (user, " ")[0] = '\0';
  msg += strlen (user) + 1;
  if (GNUNET_OK != GNUNET_pseudonym_name_to_id (ectx, cfg, user, &uid))
    {
      fprintf (stderr, _("Unknown user `%s'\n"), user);
      GNUNET_free (user);
      return GNUNET_OK;
    }
  GNUNET_mutex_lock (lock);
  pos = users;
  while (pos != NULL)
    {
      GNUNET_hash (&pos->pkey, sizeof (GNUNET_RSA_PublicKey), &pid);
      if (0 == memcmp (&pid, &uid, sizeof (GNUNET_HashCode)))
        break;
      pos = pos->next;
    }
  if (pos == NULL)
    {
      fprintf (stderr, _("User `%s' is currently not in the room!\n"), user);
      GNUNET_free (user);
      GNUNET_mutex_unlock (lock);
      return GNUNET_OK;
    }
  if (GNUNET_OK != GNUNET_CHAT_send_message (room,
                                             msg,
                                             GNUNET_CHAT_MSG_PRIVATE,
                                             &pos->pkey, &seq))
    fprintf (stderr, _("Failed to send message.\n"));
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

static int
do_names (const char *msg, const void *xtra)
{
  char *name;
  struct UserList *pos;
  GNUNET_HashCode pid;

  GNUNET_mutex_lock (lock);
  fprintf (stdout, _("Users in room `%s': "), room_name);
  pos = users;
  while (pos != NULL)
    {
      GNUNET_hash (&pos->pkey, sizeof (GNUNET_RSA_PublicKey), &pid);
      name = GNUNET_pseudonym_id_to_name (ectx, cfg, &pid);
      fprintf (stdout, "`%s' ", name);
      GNUNET_free (name);
      pos = pos->next;
    }
  fprintf (stdout, "\n");
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

static int
do_quit (const char *args, const void *xtra)
{
  return GNUNET_SYSERR;
}

static int do_help (const char *args, const void *xtra);

/**
 * List of supported IRC commands. The order matters!
 */
static struct ChatCommand commands[] = {
  {"/join ", &do_join,
   gettext_noop
   ("Use `/join #roomname' to join a chat room. Joining a room will cause you to leave the current room")},
  {"/nick ", &do_nick,
   gettext_noop
   ("Use `/nick nickname' to change your nickname.  This will cause you to leave the current room and immediately rejoin it with the new name.")},
  {"/msg ", &do_pm,
   gettext_noop
   ("Use `/msg nickname message' to send a private message to the specified user")},
  {"/notice ", &do_pm,
   gettext_noop ("The `/notice' command is an alias for `/msg'")},
  {"/query ", &do_pm,
   gettext_noop ("The `/query' command is an alias for `/msg'")},
  {"/quit", &do_quit,
   gettext_noop ("Use `/quit' to terminate gnunet-chat")},
  {"/leave", &do_quit,
   gettext_noop ("The `/leave' command is an alias for `/quit'")},
  {"/names", &do_names,
   gettext_noop
   ("Use `/names' to list all of the current members in the chat room")},
  {"/help", &do_help,
   gettext_noop ("Use `/help command' to get help for a specific command")},
  /* Add standard commands:
     /help (print help texts),
     /whois (print metadata),
     /ignore (set flag, check on receive!) */
  /* Add special commands (currently supported):
     + anonymous msgs
     + authenticated msgs
   */
  /* the following three commands must be last! */
  {"/", &do_unknown, NULL},
  {"", &do_transmit, NULL},
  {NULL, NULL, NULL},
};

static int
do_help (const char *args, const void *xtra)
{
  int i;
  i = 0;
  while ((args != NULL) &&
	 (0 != strlen(args)) &&
	 (commands[i].Action != &do_help))
    {
      if (0 == strncasecmp (&args[1], &commands[i].command[1], strlen(args)-1))
        {
          fprintf (stdout, "%s\n", gettext (commands[i].helptext));
          return GNUNET_OK;
	}        
      i++;
    }
  i = 0;
  fprintf (stdout, "Available commands:");
  while (commands[i].Action != &do_help)
    {
      fprintf (stdout, " %s", gettext (commands[i].command));
      i++;
    }
  fprintf (stdout, "\n");
  fprintf (stdout, "%s\n", gettext (commands[i].helptext));
  return GNUNET_OK;
}


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
 * GNUnet-chat main.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return  0: ok, otherwise error
 */
int
main (int argc, char **argv)
{
  char message[MAX_MESSAGE_LENGTH + 1];
  char *my_name;
  GNUNET_HashCode me;
  int i;

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
  lock = GNUNET_mutex_create (GNUNET_NO);
  if (room_name == NULL)
    room_name = GNUNET_strdup ("gnunet");
  meta = GNUNET_meta_data_create ();
  GNUNET_meta_data_insert (meta, EXTRACTOR_TITLE, nickname);
  room = GNUNET_CHAT_join_room (ectx,
                                cfg,
                                nickname,
                                meta,
                                room_name,
                                -1,
                                &receive_callback, NULL,
                                &member_list_callback, NULL,
                                &confirmation_callback, NULL, &me);
  if (room == NULL)
    {
      fprintf (stderr, _("Failed to join room `%s'\n"), room_name);
      GNUNET_free (room_name);
      GNUNET_free (nickname);
      GNUNET_meta_data_destroy (meta);
      GNUNET_mutex_destroy (lock);
      GNUNET_fini (ectx, cfg);
      return -1;
    }
  my_name = GNUNET_pseudonym_id_to_name (ectx, cfg, &me);
  fprintf (stdout, _("Joined room `%s' as user `%s'.\n"), room_name, my_name);
  GNUNET_free (my_name);
  /* read messages from command line and send */
  while (GNUNET_shutdown_test () == GNUNET_NO)
    {
      memset (message, 0, MAX_MESSAGE_LENGTH + 1);
      if (NULL == fgets (message, MAX_MESSAGE_LENGTH, stdin))
        break;
      if (strlen (message) == 0)
        continue;
      if (message[strlen (message) - 1] == '\n')
        message[strlen (message) - 1] = '\0';
      if (strlen (message) == 0)
        continue;
      i = 0;
      while ((commands[i].command != NULL) &&
             (0 != strncasecmp (commands[i].command,
                                message, strlen (commands[i].command))))
        i++;
      if (GNUNET_OK !=
          commands[i].Action (&message[strlen (commands[i].command)], NULL))
        break;
    }
  GNUNET_CHAT_leave_room (room);
  free_user_list ();
  GNUNET_meta_data_destroy (meta);
  GNUNET_free (room_name);
  GNUNET_free (nickname);
  GNUNET_fini (ectx, cfg);
  GNUNET_mutex_destroy (lock);
  return 0;
}

/* end of gnunet-chat.c */
