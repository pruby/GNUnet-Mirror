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
 * @file applications/template/gnunet-template.c
 * @brief template for writing a GNUnet tool (client)
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_util_network_client.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_error_loggers.h"
#include "platform.h"

#define TEMPLATE_VERSION "0.0.0"

static struct SEMAPHORE * doneSem;

static char * cfgFilename;

/**
 * All gnunetd command line options
 */
static struct CommandLineOption gnunettemplateOptions[] = {
  COMMAND_LINE_OPTION_CFG_FILE(&cfgFilename), /* -c */
  COMMAND_LINE_OPTION_HELP(gettext_noop("Template description.")), /* -h */
  COMMAND_LINE_OPTION_HOSTNAME, /* -H */
  COMMAND_LINE_OPTION_LOGGING, /* -L */
  COMMAND_LINE_OPTION_VERSION(PACKAGE_VERSION), /* -v */
  COMMAND_LINE_OPTION_END,
};

static void * receiveThread(void * cls) {
  struct ClientServerConnection * sock = cls;
  void * buffer;

  buffer = MALLOC(MAX_BUFFER_SIZE);
  while (OK == connection_read(sock,
			       (MESSAGE_HEADER**)&buffer)) {
    /* process */
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
int main(int argc, 
	 const char ** argv) {
  struct ClientServerConnection * sock;
  struct PTHREAD * messageReceiveThread;
  void * unused;
  struct GE_Context * ectx;
  struct GC_Configuration * cfg;

  ectx = GE_create_context_stderr(NO, 
				  GE_WARNING | GE_ERROR | GE_FATAL |
				  GE_USER | GE_ADMIN | GE_DEVELOPER |
				  GE_IMMEDIATE | GE_BULK);
  GE_setDefaultContext(ectx);
  cfg = GC_create_C_impl();
  GE_ASSERT(ectx, cfg != NULL);
  os_init(ectx);
  if (-1 == gnunet_parse_options("gnunet-template",
				 ectx,
				 cfg,
				 gnunettemplateOptions,
				 (unsigned int) argc,
				 argv)) {
    GC_free(cfg);
    GE_free_context(ectx);
    return -1;  
  }

  sock = client_connection_create(ectx,
				  cfg);
  if (sock == NULL) {
    fprintf(stderr,
	    _("Error establishing connection with gnunetd.\n"));
    GC_free(cfg);
    GE_free_context(ectx);
    return 1;
  }
  messageReceiveThread = PTHREAD_CREATE(&receiveThread,
					sock,
					128 * 1024);
  if (messageReceiveThread == NULL) {
    GE_DIE_STRERROR(ectx,
		    GE_IMMEDIATE | GE_FATAL | GE_USER | GE_ADMIN, 
		    "pthread_create");
  }

  /* wait for shutdown... */

  connection_close_temporarily(sock);
  SEMAPHORE_DOWN(doneSem, YES);
  SEMAPHORE_DESTROY(doneSem);
  PTHREAD_JOIN(messageReceiveThread, &unused);
  connection_destroy(sock);
  GC_free(cfg);
  GE_free_context(ectx);
  return 0;
}

/* end of gnunet-template.c */
