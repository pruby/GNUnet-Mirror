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
 * @file applications/template/gnunet-template.c
 * @brief template for writing a GNUnet tool (client)
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_util.h"
#include "platform.h"

#define TEMPLATE_VERSION "0.0.0"

static struct GNUNET_Semaphore *doneSem;

static char *cfgFilename;

/**
 * All gnunetd command line options
 */
static struct GNUNET_CommandLineOption gnunettemplateOptions[] = {
  GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),   /* -c */
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Template description.")),     /* -h */
  GNUNET_COMMAND_LINE_OPTION_HOSTNAME,  /* -H */
  GNUNET_COMMAND_LINE_OPTION_LOGGING,   /* -L */
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION), /* -v */
  GNUNET_COMMAND_LINE_OPTION_END,
};

static void *
receiveThread (void *cls)
{
  struct GNUNET_ClientServerConnection *sock = cls;
  void *buffer;

  buffer = GNUNET_malloc (GNUNET_MAX_BUFFER_SIZE);
  while (GNUNET_OK ==
         GNUNET_client_connection_read (sock,
                                        (GNUNET_MessageHeader **) & buffer))
    {
      /* process */
    }
  GNUNET_free (buffer);
  GNUNET_semaphore_up (doneSem);
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
  struct GNUNET_ClientServerConnection *sock;
  struct GNUNET_ThreadHandle *messageReceiveThread;
  void *unused;
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GC_Configuration *cfg;
  int i;

  i = GNUNET_init (argc,
                   argv,
                   "gnunet-template",
                   &cfgFilename, gnunettemplateOptions, &ectx, &cfg);
  if (-1 == i)
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
  messageReceiveThread =
    GNUNET_thread_create (&receiveThread, sock, 128 * 1024);
  if (messageReceiveThread == NULL)
    {
      GNUNET_GE_DIE_STRERROR (ectx,
                              GNUNET_GE_IMMEDIATE | GNUNET_GE_FATAL |
                              GNUNET_GE_USER | GNUNET_GE_ADMIN,
                              "pthread_create");
    }

  /* wait for shutdown... */

  GNUNET_client_connection_close_forever (sock);
  GNUNET_semaphore_down (doneSem, GNUNET_YES);
  GNUNET_semaphore_destroy (doneSem);
  GNUNET_thread_join (messageReceiveThread, &unused);
  GNUNET_client_connection_destroy (sock);
  GNUNET_fini (ectx, cfg);
  return 0;
}

/* end of gnunet-template.c */
