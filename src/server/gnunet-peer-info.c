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
#include "core.h"

static GNUNET_Transport_ServiceAPI *transport;

static GNUNET_Identity_ServiceAPI *identity;

static struct GNUNET_GE_Context *ectx;

static char *cfgFilename = GNUNET_DEFAULT_DAEMON_CONFIG_FILE;

static int no_resolve = GNUNET_NO;

static int get_self = GNUNET_NO;

static int be_quiet = GNUNET_NO;

/**
 * All gnunet-peer-info command line options
 */
static struct GNUNET_CommandLineOption gnunetpeerinfoOptions[] = {
  GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),   /* -c */
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Print information about GNUnet peers.")),     /* -h */
  GNUNET_COMMAND_LINE_OPTION_HOSTNAME,  /* -H */
  GNUNET_COMMAND_LINE_OPTION_LOGGING,   /* -L */
  {'n', "numeric", NULL,
   gettext_noop ("don't resolve host names"),
   0, &GNUNET_getopt_configure_set_one, &no_resolve},
  {'q', "quiet", NULL,
   gettext_noop ("output only the identity strings"),
   0, &GNUNET_getopt_configure_set_one, &be_quiet},
  {'s', "self", NULL,
   gettext_noop ("output our own identity only"),
   0, &GNUNET_getopt_configure_set_one, &get_self},
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION), /* -v */
  GNUNET_COMMAND_LINE_OPTION_END,
};

#if HAVE_ADNS | HAVE_C_ARES
/**
 * Prepass just to resolve DNS entries.
 */
static int
resolveHostInfo (const GNUNET_PeerIdentity * id,
                 const unsigned short proto, int verified, void *data)
{
  GNUNET_MessageHello *hello;
  void *addr;
  unsigned int addr_len;
  char *info;
  int have_addr;

  if (GNUNET_shutdown_test () == GNUNET_YES)
    return GNUNET_SYSERR;
  hello = identity->identity2Hello (id, proto, GNUNET_NO);
  if (NULL == hello)
    return GNUNET_OK;
  addr = NULL;
  addr_len = 0;
  have_addr = transport->hello_to_address (hello, &addr, &addr_len);
  GNUNET_free (hello);
  if (have_addr == GNUNET_OK)
    {
      info = GNUNET_get_ip_as_string (addr, addr_len, !no_resolve);
      GNUNET_free (addr);
      addr = NULL;
      GNUNET_free_non_null (info);
    }
  return GNUNET_OK;
}

#endif

/**
 * Print information about the peer.
 * Currently prints the GNUNET_PeerIdentity, trust and the IP.
 * Could of course do more (e.g. resolve via DNS).
 */
static int
printHostInfo (const GNUNET_PeerIdentity * id,
               const unsigned short proto, int verified, void *data)
{
  GNUNET_MessageHello *hello;
  void *addr;
  unsigned int addr_len;
  char *info;
  int have_addr;
  GNUNET_EncName enc;

  if (GNUNET_shutdown_test () == GNUNET_YES)
    return GNUNET_SYSERR;
  GNUNET_hash_to_enc (&id->hashPubKey, &enc);
  hello = identity->identity2Hello (id, proto, GNUNET_NO);
  if (NULL == hello)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Could not get address of peer `%s'.\n"), &enc);
      return GNUNET_OK;
    }
  if (GNUNET_SYSERR == GNUNET_RSA_verify (&hello->senderIdentity,
                                          GNUNET_sizeof_hello (hello) -
                                          sizeof (GNUNET_RSA_Signature) -
                                          sizeof (GNUNET_RSA_PublicKey) -
                                          sizeof (GNUNET_MessageHeader),
                                          &hello->signature,
                                          &hello->publicKey))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("`%s' message invalid (signature invalid).\n"),
                     "HELLO");
    }
  addr = NULL;
  addr_len = 0;
  have_addr = transport->hello_to_address (hello, &addr, &addr_len);
  GNUNET_free (hello);
  if (have_addr != GNUNET_OK)
    {
      info = GNUNET_strdup ("NAT");     /* most likely */
    }
  else
    {
      info = GNUNET_get_ip_as_string (addr, addr_len, !no_resolve);
      GNUNET_free (addr);
      addr = NULL;
    }
  if (info == NULL)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Could not get address of peer `%s'.\n"), &enc);
      if (be_quiet)
        printf ("%s\n", (char *) &enc);
      else
        printf (_("Peer `%s' with trust %8u\n"),
                (char *) &enc, identity->getHostTrust (id));
      return GNUNET_OK;
    }
  if (be_quiet)
    printf ("%s\n", (char *) &enc);
  else
    printf (_("Peer `%s' with trust %8u and address `%s'\n"),
            (char *) &enc, identity->getHostTrust (id), info);
  GNUNET_free (info);
  return GNUNET_OK;
}

int
main (int argc, char *const *argv)
{
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_CronManager *cron;
  const GNUNET_RSA_PublicKey *me;
  GNUNET_PeerIdentity id;
  GNUNET_EncName enc;
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
  GNUNET_GE_ASSERT (ectx,
                    0 == GNUNET_GC_set_configuration_value_string (cfg,
                                                                   ectx,
                                                                   "TCPSERVER",
                                                                   "DISABLE",
                                                                   "YES"));
  cron = GNUNET_cron_create (ectx);
  if (GNUNET_OK != GNUNET_CORE_init (ectx, cfg, cron, NULL))
    {
      GNUNET_cron_destroy (cron);
      GNUNET_fini (ectx, cfg);
      return -1;
    }
  identity = GNUNET_CORE_request_service ("identity");
  if (identity == NULL)
    {
      GNUNET_CORE_done ();
      GNUNET_cron_destroy (cron);
      GNUNET_fini (ectx, cfg);
      return -1;
    }
  transport = GNUNET_CORE_request_service ("transport");
  if (transport == NULL)
    {
      GNUNET_CORE_release_service (identity);
      GNUNET_CORE_done ();
      GNUNET_cron_destroy (cron);
      GNUNET_fini (ectx, cfg);
      return -1;
    }
  if (get_self != GNUNET_YES)
    {
      if (no_resolve != GNUNET_YES)
        {
#if HAVE_ADNS | HAVE_C_ARES
          identity->forEachHost (0,     /* no timeout */
                                 &resolveHostInfo, NULL);
          /* give GNU ADNS time to resolve... */
          GNUNET_thread_sleep (2 * GNUNET_CRON_SECONDS);
#endif
        }
      identity->forEachHost (0, /* no timeout */
                             &printHostInfo, NULL);
    }
  else
    {
      me = identity->getPublicPrivateKey ();
      identity->getPeerIdentity (me, &id);
      GNUNET_hash_to_enc (&id.hashPubKey, &enc);
      if (be_quiet)
        printf ("%s\n", (char *) &enc);
      else
        printf (_("I am peer `%s'.\n"), (const char *) &enc);
    }
  GNUNET_CORE_release_service (identity);
  GNUNET_CORE_release_service (transport);
  GNUNET_CORE_done ();
  GNUNET_cron_destroy (cron);
  GNUNET_fini (ectx, cfg);
  return 0;
}


/* end of gnunet-peer-info.c */
