/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2006 Christian Grothoff (and other contributing authors)

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
#include "gnunet_util_network_client.h"
#include "gnunet_util_boot.h"
#include "gnunet_protocols.h"
#include "platform.h"

#define TEMPLATE_VERSION "2006072900"

#define buf ((MESSAGE_HEADER*)&buffer)


static struct SEMAPHORE *doneSem;
static struct SEMAPHORE *cmdAck;
static struct SEMAPHORE *exitCheck;
static struct MUTEX *lock;
static int wantExit;
static int silent;

static char *cfgFilename;

/**
 * All gnunet-transport-check command line options
 */
static struct CommandLineOption gnunetvpnOptions[] = {
  COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),  /* -c */
  COMMAND_LINE_OPTION_HELP (gettext_noop ("Print statistics about GNUnet operations.")),        /* -h */
  COMMAND_LINE_OPTION_HOSTNAME, /* -H */
  COMMAND_LINE_OPTION_LOGGING,  /* -L */
  {'s', "silent", NULL,
   gettext_noop ("Suppress display of asynchronous log messages"),
   0, &gnunet_getopt_configure_set_one, &silent},
  COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION),        /* -v */
  COMMAND_LINE_OPTION_END,
};

static void *
receiveThread (void *arg)
{
  struct ClientServerConnection *sock = arg;
  char buffer[MAX_BUFFER_SIZE];
  MESSAGE_HEADER *bufp = buf;

  /* buffer = MALLOC(MAX_BUFFER_SIZE); */
  while (OK == connection_read (sock, &bufp))
    {
      switch (ntohs (buf->type))
        {
        case CS_PROTO_VPN_DEBUGOFF:
        case CS_PROTO_VPN_DEBUGON:
        case CS_PROTO_VPN_TUNNELS:
        case CS_PROTO_VPN_ROUTES:
        case CS_PROTO_VPN_REALISED:
        case CS_PROTO_VPN_RESET:
        case CS_PROTO_VPN_REALISE:
        case CS_PROTO_VPN_ADD:
        case CS_PROTO_VPN_TRUST:
          if (ntohs (buf->size) > sizeof (MESSAGE_HEADER))
            {
              fwrite (buffer + sizeof (MESSAGE_HEADER),
                      sizeof (char),
                      ntohs (buf->size) - sizeof (MESSAGE_HEADER), stdout);
            }

          SEMAPHORE_UP (cmdAck);
          SEMAPHORE_DOWN (exitCheck, YES);
          MUTEX_LOCK (lock);
          if (wantExit == YES)
            {
              MUTEX_UNLOCK (lock);
              SEMAPHORE_UP (doneSem);
              return NULL;
            }
          MUTEX_UNLOCK (lock);
          break;;
        case CS_PROTO_VPN_MSG:
          if (silent == YES)
            break;;
        case CS_PROTO_VPN_REPLY:

          if (ntohs (buf->size) > sizeof (MESSAGE_HEADER))
            {
              fwrite (buffer + sizeof (MESSAGE_HEADER),
                      sizeof (char),
                      ntohs (buf->size) - sizeof (MESSAGE_HEADER), stdout);
            }
          break;;
        }
    }
  /* FREE(buffer); */
  SEMAPHORE_UP (doneSem);
  return NULL;
}

/**
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return value from gnunet-template: 0: ok, -1: error
 */
int
main (int argc, char *const *argv)
{
  struct ClientServerConnection *sock;
  struct PTHREAD *messageReceiveThread;
  void *unused;
  char buffer[sizeof (MESSAGE_HEADER) + 1024];
  int rancommand = 0;
  struct GC_Configuration *cfg;
  struct GE_Context *ectx;
  int i;

  i = GNUNET_init (argc,
                   argv,
                   "gnunet-vpn", &cfgFilename, gnunetvpnOptions, &ectx, &cfg);
  if (i == -1)
    {
      GNUNET_fini (ectx, cfg);
      return -1;
    }
  sock = client_connection_create (ectx, cfg);
  if (sock == NULL)
    {
      fprintf (stderr, _("Error establishing connection with gnunetd.\n"));
      GNUNET_fini (ectx, cfg);
      return 1;
    }

  doneSem = SEMAPHORE_CREATE (0);
  cmdAck = SEMAPHORE_CREATE (0);
  exitCheck = SEMAPHORE_CREATE (0);
  lock = MUTEX_CREATE (NO);
  wantExit = NO;

  messageReceiveThread = PTHREAD_CREATE (&receiveThread, sock, 128 * 1024);
  if (messageReceiveThread == NULL)
    GE_DIE_STRERROR (ectx,
                     GE_FATAL | GE_ADMIN | GE_USER | GE_IMMEDIATE,
                     "pthread_create");


  /* accept keystrokes from user and send to gnunetd */
  while (NULL != fgets (buffer, 1024, stdin))
    {
      if (rancommand)
        {
          rancommand = 0;
          SEMAPHORE_UP (exitCheck);
        }
      if (strncmp (buffer, "debug0", 6) == 0)
        {
          ((MESSAGE_HEADER *) & buffer)->type = htons (CS_PROTO_VPN_DEBUGOFF);
          ((MESSAGE_HEADER *) & buffer)->size =
            htons (sizeof (MESSAGE_HEADER));
          if (SYSERR == connection_write (sock, (MESSAGE_HEADER *) & buffer))
            return -1;
          rancommand = 1;
          SEMAPHORE_DOWN (cmdAck, YES);
        }
      else if (strncmp (buffer, "debug1", 6) == 0)
        {
          ((MESSAGE_HEADER *) & buffer)->type = htons (CS_PROTO_VPN_DEBUGON);
          ((MESSAGE_HEADER *) & buffer)->size =
            htons (sizeof (MESSAGE_HEADER));
          if (SYSERR == connection_write (sock, (MESSAGE_HEADER *) & buffer))
            return -1;
          rancommand = 1;
          SEMAPHORE_DOWN (cmdAck, YES);
        }
      else if (strncmp (buffer, "tunnels", 7) == 0)
        {
          ((MESSAGE_HEADER *) & buffer)->type = htons (CS_PROTO_VPN_TUNNELS);
          ((MESSAGE_HEADER *) & buffer)->size =
            htons (sizeof (MESSAGE_HEADER));
          if (SYSERR == connection_write (sock, (MESSAGE_HEADER *) & buffer))
            return -1;
          rancommand = 1;
          SEMAPHORE_DOWN (cmdAck, YES);
        }
      else if (strncmp (buffer, "route", 5) == 0)
        {
          ((MESSAGE_HEADER *) & buffer)->type = htons (CS_PROTO_VPN_ROUTES);
          ((MESSAGE_HEADER *) & buffer)->size =
            htons (sizeof (MESSAGE_HEADER));
          if (SYSERR == connection_write (sock, (MESSAGE_HEADER *) & buffer))
            return -1;
          rancommand = 1;
          SEMAPHORE_DOWN (cmdAck, YES);
        }
      else if (strncmp (buffer, "realised", 8) == 0)
        {
          ((MESSAGE_HEADER *) & buffer)->type = htons (CS_PROTO_VPN_REALISED);
          ((MESSAGE_HEADER *) & buffer)->size =
            htons (sizeof (MESSAGE_HEADER));
          if (SYSERR == connection_write (sock, (MESSAGE_HEADER *) & buffer))
            return -1;
          rancommand = 1;
          SEMAPHORE_DOWN (cmdAck, YES);
        }
      else if (strncmp (buffer, "reset", 5) == 0)
        {
          ((MESSAGE_HEADER *) & buffer)->type = htons (CS_PROTO_VPN_RESET);
          ((MESSAGE_HEADER *) & buffer)->size =
            htons (sizeof (MESSAGE_HEADER));
          if (SYSERR == connection_write (sock, (MESSAGE_HEADER *) & buffer))
            return -1;
          rancommand = 1;
          SEMAPHORE_DOWN (cmdAck, YES);
        }
      else if (strncmp (buffer, "realise", 7) == 0)
        {
          ((MESSAGE_HEADER *) & buffer)->type = htons (CS_PROTO_VPN_REALISE);
          ((MESSAGE_HEADER *) & buffer)->size =
            htons (sizeof (MESSAGE_HEADER));
          if (SYSERR == connection_write (sock, (MESSAGE_HEADER *) & buffer))
            return -1;
          rancommand = 1;
          SEMAPHORE_DOWN (cmdAck, YES);
        }
      else if (strncmp (buffer, "trust", 5) == 0)
        {
          ((MESSAGE_HEADER *) & buffer)->type = htons (CS_PROTO_VPN_TRUST);
          ((MESSAGE_HEADER *) & buffer)->size =
            htons (sizeof (MESSAGE_HEADER));
          if (SYSERR == connection_write (sock, (MESSAGE_HEADER *) & buffer))
            return -1;
          rancommand = 1;
          SEMAPHORE_DOWN (cmdAck, YES);
        }
      else if (strncmp (buffer, "add ", 4) == 0)
        {
          /* message header is 4 bytes long, we overwrite "add " with it
           * also don't include \r or \n in the message
           */
          if (strlen (&buffer[4]) > 1)
            {
              ((MESSAGE_HEADER *) & buffer)->type = htons (CS_PROTO_VPN_ADD);
              ((MESSAGE_HEADER *) & buffer)->size =
                htons (sizeof (MESSAGE_HEADER) + strlen (&buffer[5]));
              if (SYSERR ==
                  connection_write (sock, (MESSAGE_HEADER *) & buffer))
                return -1;
              rancommand = 1;
              SEMAPHORE_DOWN (cmdAck, YES);
            }
          else
            {
              printf ("add requires hash as a parameter!\n");
            }
        }
      else
        {
          printf
            ("debug0, debug1, tunnels, route, realise, realised, reset, trust, add <hash>\n");
        }
    }
  /* wait for shutdown... */
  if (rancommand)
    {
      MUTEX_LOCK (lock);
      wantExit = YES;
      MUTEX_UNLOCK (lock);
      SEMAPHORE_UP (exitCheck);
    }

  /* we can't guarantee that this can be called while the other thread is waiting for read */
  connection_close_forever (sock);
  SEMAPHORE_DOWN (doneSem, YES);

  SEMAPHORE_DESTROY (doneSem);
  SEMAPHORE_DESTROY (cmdAck);
  SEMAPHORE_DESTROY (exitCheck);
  MUTEX_DESTROY (lock);
  PTHREAD_JOIN (messageReceiveThread, &unused);
  connection_destroy (sock);
  GNUNET_fini (ectx, cfg);

  return 0;
}

/* end of gnunet-vpn.c */
