/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file server/gnunet-peer-info.c
 * @brief Print information about other known peers.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_directories.h"
#include "gnunet_transport_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_core.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_error_loggers.h"
#include "gnunet_util_cron.h"
#include "core.h"

static Transport_ServiceAPI * transport;

static Identity_ServiceAPI * identity;

static struct GE_Context * ectx;

static char * cfgFilename = DEFAULT_DAEMON_CONFIG_FILE;

/**
 * All gnunet-peer-info command line options
 */
static struct CommandLineOption gnunetpeerinfoOptions[] = {
  COMMAND_LINE_OPTION_CFG_FILE(&cfgFilename), /* -c */
  COMMAND_LINE_OPTION_HELP(gettext_noop("Print information about GNUnet peers.")), /* -h */
  COMMAND_LINE_OPTION_HOSTNAME, /* -H */
  COMMAND_LINE_OPTION_LOGGING, /* -L */
  COMMAND_LINE_OPTION_VERSION(PACKAGE_VERSION), /* -v */
  COMMAND_LINE_OPTION_END,
};

/**
 * Print information about the peer.
 * Currently prints the PeerIdentity, trust and the IP.
 * Could of course do more (e.g. resolve via DNS).
 */
static void printHostInfo(const PeerIdentity * id,
			  const unsigned short proto,
			  int verified,
			  void * data) {
  P2P_hello_MESSAGE * helo;
  char * info;
  EncName enc;

  hash2enc(&id->hashPubKey,
	   &enc);
  helo = identity->identity2Helo(id,
				 proto,
				 NO);
  if (NULL == helo) {
    GE_LOG(ectx, GE_WARNING | GE_BULK | GE_USER,
	   _("Could not get address of peer `%s'.\n"),
	   &enc);
    return;
  }
  if (SYSERR == verifySig(&helo->senderIdentity,
			  P2P_hello_MESSAGE_size(helo) - sizeof(Signature) - sizeof(PublicKey) - sizeof(MESSAGE_HEADER),
			  &helo->signature,
			  &helo->publicKey)) {
    GE_LOG(ectx, GE_WARNING | GE_BULK | GE_USER,
	_("hello message invalid (signature invalid).\n"));
  }
  info = transport->heloToString(helo);
  FREE(helo);
  if (info == NULL) {
    GE_LOG(ectx, GE_WARNING | GE_BULK | GE_USER,
	_("Could not get address of peer `%s'.\n"),
	&enc);
    return;
  }

  printf(_("Peer `%s' with trust %8u and address `%s'\n"),
	 (char*)&enc,
	 identity->getHostTrust(id),
	 info);
  FREE(info);
}

int main(int argc, 
	 const char *argv[]) {
  struct GC_Configuration * cfg;
  struct CronManager * cron;

  ectx = GE_create_context_stderr(NO, 
				  GE_WARNING | GE_ERROR | GE_FATAL |
				  GE_USER | GE_ADMIN | GE_DEVELOPER |
				  GE_IMMEDIATE | GE_BULK);
  GE_setDefaultContext(ectx);
  os_init(ectx);
  cfg = GC_create_C_impl();
  GE_ASSERT(ectx, cfg != NULL);
  if (-1 == gnunet_parse_options("gnunet-peer-info",
				 ectx,
				 cfg,
				 gnunetpeerinfoOptions,
				 (unsigned int) argc,
				 argv)) {
    GC_free(cfg);
    GE_free_context(ectx);
    return -1;  
  } 
  if (-1 == GC_parse_configuration(cfg,
	 			   cfgFilename)) {
    GC_free(cfg);
    GE_free_context(ectx);
    return -1;  
  }
  GE_ASSERT(ectx,
	    0 == GC_set_configuration_value_string(cfg,
						   ectx,
						   "TCPSERVER",
						   "DISABLE",
						   "YES"));
  cron = cron_create(ectx);
  initCore(ectx, cfg, cron, NULL);
  identity = requestService("identity");
  transport = requestService("transport");
  identity->forEachHost(0, /* no timeout */
			&printHostInfo,
			NULL);
  releaseService(identity);
  releaseService(transport);
  doneCore();
  cron_destroy(cron);
  GC_free(cfg);
  GE_free_context(ectx);
  return 0;
}


/* end of gnunet-peer-info.c */
