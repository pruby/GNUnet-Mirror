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
#include "gnunet_util_boot.h"
#include "gnunet_util_cron.h"
#include "core.h"

static Transport_ServiceAPI *transport;

static Identity_ServiceAPI *identity;

static struct GE_Context *ectx;

static char *cfgFilename = DEFAULT_DAEMON_CONFIG_FILE;

static int no_resolve = NO;

/**
 * All gnunet-peer-info command line options
 */
static struct CommandLineOption gnunetpeerinfoOptions[] = {
  COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),  /* -c */
  COMMAND_LINE_OPTION_HELP (gettext_noop ("Print information about GNUnet peers.")),    /* -h */
  COMMAND_LINE_OPTION_HOSTNAME, /* -H */
  COMMAND_LINE_OPTION_LOGGING,  /* -L */
  {'n', "numeric", NULL,
   gettext_noop ("don't resolve host names"),
   0, &gnunet_getopt_configure_set_one, &no_resolve},
  COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION),        /* -v */
  COMMAND_LINE_OPTION_END,
};

#if HAVE_ADNS
/**
 * Prepass just to resolve DNS entries.
 */
static int
resolveHostInfo (const PeerIdentity * id,
                 const unsigned short proto, int verified, void *data)
{
  P2P_hello_MESSAGE *hello;
  void *addr;
  unsigned int addr_len;
  char *info;
  int have_addr;

  if (GNUNET_SHUTDOWN_TEST () == YES)
    return SYSERR;
  hello = identity->identity2Hello (id, proto, NO);
  if (NULL == hello)
    return OK;
  addr = NULL;
  addr_len = 0;
  have_addr = transport->helloToAddress (hello, &addr, &addr_len);
  FREE (hello);
  if (have_addr == OK)
    {
      info = network_get_ip_as_string (addr, addr_len, !no_resolve);
      FREE (addr);
      addr = NULL;
      FREENONNULL (info);
    }
  return OK;
}

#endif

/**
 * Print information about the peer.
 * Currently prints the PeerIdentity, trust and the IP.
 * Could of course do more (e.g. resolve via DNS).
 */
static int
printHostInfo (const PeerIdentity * id,
               const unsigned short proto, int verified, void *data)
{
  P2P_hello_MESSAGE *hello;
  void *addr;
  unsigned int addr_len;
  char *info;
  int have_addr;
  EncName enc;

  if (GNUNET_SHUTDOWN_TEST () == YES)
    return SYSERR;
  hash2enc (&id->hashPubKey, &enc);
  hello = identity->identity2Hello (id, proto, NO);
  if (NULL == hello)
    {
      GE_LOG (ectx,
              GE_WARNING | GE_BULK | GE_USER,
              _("Could not get address of peer `%s'.\n"), &enc);
      return OK;
    }
  if (SYSERR == verifySig (&hello->senderIdentity,
                           P2P_hello_MESSAGE_size (hello) -
                           sizeof (Signature) - sizeof (PublicKey) -
                           sizeof (MESSAGE_HEADER), &hello->signature,
                           &hello->publicKey))
    {
      GE_LOG (ectx,
              GE_WARNING | GE_BULK | GE_USER,
              _("hello message invalid (signature invalid).\n"));
    }
  addr = NULL;
  addr_len = 0;
  have_addr = transport->helloToAddress (hello, &addr, &addr_len);
  FREE (hello);
  if (have_addr != OK)
    {
      info = STRDUP ("NAT");    /* most likely */
    }
  else
    {
      info = network_get_ip_as_string (addr, addr_len, !no_resolve);
      FREE (addr);
      addr = NULL;
    }
  if (info == NULL)
    {
      GE_LOG (ectx,
              GE_DEBUG | GE_BULK | GE_USER,
              _("Could not get address of peer `%s'.\n"), &enc);
      printf (_("Peer `%s' with trust %8u\n"),
              (char *) &enc, identity->getHostTrust (id));
      return OK;
    }
  printf (_("Peer `%s' with trust %8u and address `%s'\n"),
          (char *) &enc, identity->getHostTrust (id), info);
  FREE (info);
  return OK;
}

int
main (int argc, char *const *argv)
{
  struct GC_Configuration *cfg;
  struct CronManager *cron;
  int ret;

  ret = GNUNET_init (argc,
                     argv,
                     "gnunet-peer-info",
                     &cfgFilename, gnunetpeerinfoOptions, &ectx, &cfg);
  if (ret == -1)
    {
      GNUNET_fini (ectx, cfg);
      return -1;
    }
  GE_ASSERT (ectx,
             0 == GC_set_configuration_value_string (cfg,
                                                     ectx,
                                                     "TCPSERVER",
                                                     "DISABLE", "YES"));
  cron = cron_create (ectx);
  initCore (ectx, cfg, cron, NULL);
  identity = requestService ("identity");
  transport = requestService ("transport");
  if (no_resolve != YES)
    {
#if HAVE_ADNS
      identity->forEachHost (0, /* no timeout */
                             &resolveHostInfo, NULL);
      /* give GNU ADNS time to resolve... */
      PTHREAD_SLEEP (2 * cronSECONDS);
#endif
    }
  identity->forEachHost (0,     /* no timeout */
                         &printHostInfo, NULL);
  releaseService (identity);
  releaseService (transport);
  doneCore ();
  cron_destroy (cron);
  GNUNET_fini (ectx, cfg);
  return 0;
}


/* end of gnunet-peer-info.c */
