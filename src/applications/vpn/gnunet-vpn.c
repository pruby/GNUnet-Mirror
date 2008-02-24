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
 *
 * TODO:
 * - clean up use of semaphores / signaling
 * - make proper use of structs
 */

#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_directories.h"
#include "platform.h"

#define TEMPLATE_VERSION "2006072900"

#define buf ((GNUNET_MessageHeader*)&buffer)

static struct GNUNET_Semaphore *doneSem;

static struct GNUNET_Semaphore *cmdAck;

static struct GNUNET_Semaphore *exitCheck;

static struct GNUNET_Mutex *lock;

static int wantExit;

static int silent;

static char *cfgFilename = GNUNET_DEFAULT_CLIENT_CONFIG_FILE;

/**
 * All gnunet-transport-check command line options
 */
static struct GNUNET_CommandLineOption gnunetvpnOptions[] = {
  GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),   /* -c */
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Print statistics about GNUnet operations.")), /* -h */
  GNUNET_COMMAND_LINE_OPTION_HOSTNAME,  /* -H */
  GNUNET_COMMAND_LINE_OPTION_LOGGING,   /* -L */
  {'s', "silent", NULL,
   gettext_noop ("Suppress display of asynchronous log messages"),
   0, &GNUNET_getopt_configure_set_one, &silent},
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION), /* -v */
  GNUNET_COMMAND_LINE_OPTION_END,
};

static void *
receiveThread (void *arg)
{
  struct GNUNET_ClientServerConnection *sock = arg;
  char buffer[GNUNET_MAX_BUFFER_SIZE];
  GNUNET_MessageHeader *bufp = buf;

  while (GNUNET_OK == GNUNET_client_connection_read (sock, &bufp))
    {
      switch (ntohs (buf->type))
        {
        case GNUNET_CS_PROTO_VPN_TUNNELS:
        case GNUNET_CS_PROTO_VPN_ROUTES:
        case GNUNET_CS_PROTO_VPN_REALISED:
        case GNUNET_CS_PROTO_VPN_RESET:
        case GNUNET_CS_PROTO_VPN_ADD:
        case GNUNET_CS_PROTO_VPN_TRUST:
          if (ntohs (buf->size) > sizeof (GNUNET_MessageHeader))
            {
              fwrite (buffer + sizeof (GNUNET_MessageHeader),
                      sizeof (char),
                      ntohs (buf->size) - sizeof (GNUNET_MessageHeader),
                      stdout);
            }

          GNUNET_semaphore_up (cmdAck);
          GNUNET_semaphore_down (exitCheck, GNUNET_YES);
          GNUNET_mutex_lock (lock);
          if (wantExit == GNUNET_YES)
            {
              GNUNET_mutex_unlock (lock);
              GNUNET_semaphore_up (doneSem);
              return NULL;
            }
          GNUNET_mutex_unlock (lock);
          break;
        case GNUNET_CS_PROTO_VPN_MSG:
          if (silent == GNUNET_YES)
            break;
        case GNUNET_CS_PROTO_VPN_REPLY:

          if (ntohs (buf->size) > sizeof (GNUNET_MessageHeader))
            {
              fwrite (buffer + sizeof (GNUNET_MessageHeader),
                      sizeof (char),
                      ntohs (buf->size) - sizeof (GNUNET_MessageHeader),
                      stdout);
            }
          break;;
        }
    }
  GNUNET_semaphore_up (doneSem);
  return NULL;
}

#define COMMAND_LINE_SIZE 1024

/**
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return value from gnunet-template: 0: ok, -1: error
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_ClientServerConnection *sock;
  struct GNUNET_ThreadHandle *messageReceiveThread;
  void *unused;
  char buffer[sizeof (GNUNET_MessageHeader) + COMMAND_LINE_SIZE];
  int rancommand = 0;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_GE_Context *ectx;
  int i;

  i = GNUNET_init (argc,
                   argv,
                   "gnunet-vpn", &cfgFilename, gnunetvpnOptions, &ectx, &cfg);
  if (i == -1)
    {
      GNUNET_fini (ectx, cfg);
      return -1;
    }
  sock = GNUNET_client_connection_create (ectx, cfg);
  if (sock == NULL)
    {
      fprintf (stderr, _("Error establishing connection with gnunetd.\n"));
      GNUNET_fini (ectx, cfg);
      return 1;
    }

  doneSem = GNUNET_semaphore_create (0);
  cmdAck = GNUNET_semaphore_create (0);
  exitCheck = GNUNET_semaphore_create (0);
  lock = GNUNET_mutex_create (GNUNET_NO);
  wantExit = GNUNET_NO;

  messageReceiveThread =
    GNUNET_thread_create (&receiveThread, sock, 128 * 1024);
  if (messageReceiveThread == NULL)
    GNUNET_GE_DIE_STRERROR (ectx,
                            GNUNET_GE_FATAL | GNUNET_GE_ADMIN | GNUNET_GE_USER
                            | GNUNET_GE_IMMEDIATE, "pthread_create");


  /* accept keystrokes from user and send to gnunetd */
  while (NULL != fgets (buffer, COMMAND_LINE_SIZE, stdin))
    {
      if (rancommand)
        {
          rancommand = 0;
          GNUNET_semaphore_up (exitCheck);
        }
      else if (strncmp (buffer, "tunnels", 7) == 0)
        {
          ((GNUNET_MessageHeader *) & buffer)->type =
            htons (GNUNET_CS_PROTO_VPN_TUNNELS);
          ((GNUNET_MessageHeader *) & buffer)->size =
            htons (sizeof (GNUNET_MessageHeader));
          if (GNUNET_SYSERR ==
              GNUNET_client_connection_write (sock,
                                              (GNUNET_MessageHeader *) &
                                              buffer))
            return -1;
          rancommand = 1;
          GNUNET_semaphore_down (cmdAck, GNUNET_YES);
        }
      else if (strncmp (buffer, "route", 5) == 0)
        {
          ((GNUNET_MessageHeader *) & buffer)->type =
            htons (GNUNET_CS_PROTO_VPN_ROUTES);
          ((GNUNET_MessageHeader *) & buffer)->size =
            htons (sizeof (GNUNET_MessageHeader));
          if (GNUNET_SYSERR ==
              GNUNET_client_connection_write (sock,
                                              (GNUNET_MessageHeader *) &
                                              buffer))
            return -1;
          rancommand = 1;
          GNUNET_semaphore_down (cmdAck, GNUNET_YES);
        }
      else if (strncmp (buffer, "realised", 8) == 0)
        {
          ((GNUNET_MessageHeader *) & buffer)->type =
            htons (GNUNET_CS_PROTO_VPN_REALISED);
          ((GNUNET_MessageHeader *) & buffer)->size =
            htons (sizeof (GNUNET_MessageHeader));
          if (GNUNET_SYSERR ==
              GNUNET_client_connection_write (sock,
                                              (GNUNET_MessageHeader *) &
                                              buffer))
            return -1;
          rancommand = 1;
          GNUNET_semaphore_down (cmdAck, GNUNET_YES);
        }
      else if (strncmp (buffer, "reset", 5) == 0)
        {
          ((GNUNET_MessageHeader *) & buffer)->type =
            htons (GNUNET_CS_PROTO_VPN_RESET);
          ((GNUNET_MessageHeader *) & buffer)->size =
            htons (sizeof (GNUNET_MessageHeader));
          if (GNUNET_SYSERR ==
              GNUNET_client_connection_write (sock,
                                              (GNUNET_MessageHeader *) &
                                              buffer))
            return -1;
          rancommand = 1;
          GNUNET_semaphore_down (cmdAck, GNUNET_YES);
        }
      else if (strncmp (buffer, "trust", 5) == 0)
        {
          ((GNUNET_MessageHeader *) & buffer)->type =
            htons (GNUNET_CS_PROTO_VPN_TRUST);
          ((GNUNET_MessageHeader *) & buffer)->size =
            htons (sizeof (GNUNET_MessageHeader));
          if (GNUNET_SYSERR ==
              GNUNET_client_connection_write (sock,
                                              (GNUNET_MessageHeader *) &
                                              buffer))
            return -1;
          rancommand = 1;
          GNUNET_semaphore_down (cmdAck, GNUNET_YES);
        }
      else if (strncmp (buffer, "add ", 4) == 0)
        {
          /* message header is 4 bytes long, we overwrite "add " with it
           * also don't include \r or \n in the message
           */
          if (strlen (&buffer[4]) > 1)
            {
              ((GNUNET_MessageHeader *) & buffer)->type =
                htons (GNUNET_CS_PROTO_VPN_ADD);
              ((GNUNET_MessageHeader *) & buffer)->size =
                htons (sizeof (GNUNET_MessageHeader) + strlen (&buffer[5]));
              if (GNUNET_SYSERR ==
                  GNUNET_client_connection_write (sock,
                                                  (GNUNET_MessageHeader *) &
                                                  buffer))
                return -1;
              rancommand = 1;
              GNUNET_semaphore_down (cmdAck, GNUNET_YES);
            }
          else
            {
              printf ("add requires hash as a parameter!\n");
            }
        }
      else
        {
          printf ("tunnels, route, realised, reset, trust, add <hash>\n");
        }
    }
  /* wait for shutdown... */
  if (rancommand)
    {
      GNUNET_mutex_lock (lock);
      wantExit = GNUNET_YES;
      GNUNET_mutex_unlock (lock);
      GNUNET_semaphore_up (exitCheck);
    }

  /* we can't guarantee that this can be called while the other thread is waiting for read */
  GNUNET_client_connection_close_forever (sock);
  GNUNET_semaphore_down (doneSem, GNUNET_YES);
  GNUNET_semaphore_destroy (doneSem);
  GNUNET_semaphore_destroy (cmdAck);
  GNUNET_semaphore_destroy (exitCheck);
  GNUNET_mutex_destroy (lock);
  GNUNET_thread_join (messageReceiveThread, &unused);
  GNUNET_client_connection_destroy (sock);
  GNUNET_fini (ectx, cfg);

  return 0;
}

/* end of gnunet-vpn.c */
