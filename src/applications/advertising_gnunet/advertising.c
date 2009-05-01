/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file advertising_gnunet/advertising.c
 * @brief Advertising plugin that operates on GNUnet itself
 *
 * @author Christian Grothoff
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_identity_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_stats_service.h"
#include "gnunet_topology_service.h"
#include "bootstrap.h"

/**
 * Send our hello to a random connected host on a regular basis.
 */
#define HELLO_BROADCAST_FREQUENCY (2 * GNUNET_CRON_MINUTES)

#define DEBUG_ADVERTISING GNUNET_NO

static GNUNET_CoreAPIForPlugins *coreAPI;

static GNUNET_Transport_ServiceAPI *transport;

static GNUNET_Identity_ServiceAPI *identity;

static GNUNET_Topology_ServiceAPI *topology;

static GNUNET_Stats_ServiceAPI *stats;

static struct GNUNET_GE_Context *ectx;

static int stat_hello_out;


static double
getConnectPriority ()
{
  double preference;

  /* we should'nt give lots of bandwidth for hellos if we're close to
     the connection goal */
  preference = topology->getSaturation ();
  if (preference <= 0.0001)
    preference = 0xFFFF;
  else
    preference = 1 / preference;
  /* always give some decent, but compared to (migrated) content
     competitive amount of bandwidth to peers sending (valid)
     hellos */
  if (preference < 0.2)
    preference = 0.2;
  return preference;
}

typedef struct
{
  /* the hello message */
  GNUNET_MessageHello *m;
  /* send the hello in 1 out of n cases */
  int n;
} SendData;

static int
broadcastHelper (const GNUNET_PeerIdentity * hi,
                 const unsigned short proto, int confirmed, void *cls)
{
  SendData *sd = cls;
  GNUNET_MessageHello *hello;
  GNUNET_TSession *tsession;
  int prio;
#if DEBUG_ADVERTISING
  GNUNET_EncName other;
#endif

  if (confirmed == GNUNET_NO)
    return GNUNET_OK;
  if (proto == GNUNET_TRANSPORT_PROTOCOL_NUMBER_NAT)
    {
      sd->n--;
      return GNUNET_OK;         /* don't advertise NAT addresses via broadcast */
    }
  if ((sd->n != 0)
      && (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, sd->n) != 0))
    return GNUNET_OK;
#if DEBUG_ADVERTISING
  IF_GELOG (ectx,
            GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&hi->hashPubKey, &other));
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Entering with target `%s'.\n", &other);
#endif
  if (0 == memcmp (hi, coreAPI->my_identity, sizeof (GNUNET_PeerIdentity)))
    return GNUNET_OK;           /* never advertise to myself... */
  prio = (int) getConnectPriority ();
  if (prio >= GNUNET_EXTREME_PRIORITY)
    prio = GNUNET_EXTREME_PRIORITY / 4;
  if (GNUNET_OK == coreAPI->p2p_connection_status_check (hi, NULL, NULL))
    {
      coreAPI->ciphertext_send (hi, &sd->m->header, prio,
                                HELLO_BROADCAST_FREQUENCY);
      if (stats != NULL)
        stats->change (stat_hello_out, 1);
      return GNUNET_OK;
    }
  /* with even lower probability (with n peers
     trying to contact with a probability of 1/n^2,
     we get a probability of 1/n for this, which
     is what we want: fewer attempts to contact fresh
     peers as the network grows): */
  if ((sd->n != 0)
      && (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, sd->n) != 0))
    return GNUNET_OK;

  /* establish short-lived connection, send, tear down */
  hello = identity->identity2Hello (hi, proto, GNUNET_NO);
  if (NULL == hello)
    return GNUNET_OK;
  tsession = transport->connect (hello, __FILE__, GNUNET_YES);
  GNUNET_free (hello);
  if (tsession == NULL)
    return GNUNET_OK;           /* could not connect */
  if (stats != NULL)
    stats->change (stat_hello_out, 1);
  coreAPI->plaintext_send (tsession,
                           (char *) &sd->m->header,
                           GNUNET_sizeof_hello (sd->m));
  transport->disconnect (tsession, __FILE__);
  return GNUNET_OK;
}

/**
 * @brief Advertise this peer's identity
 * @param msg the hello message
 * @param prob send the hello in 1 out of n cases
 */
static void *advertise(GNUNET_MessageHello *msg,
                     int prob)
{
  SendData sd;

  sd.n = prob;
  sd.m = msg;
  identity->forEachHost (now, &broadcastHelper, &sd);
}

GNUNET_Advertising_ServiceAPI *provide_module_advertising_gnunet (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_Advertising_ServiceAPI api;
  
  api.advertise = advertise;

  coreAPI = capi;
  ectx = capi->ectx;
  identity = capi->service_request ("identity");
  if (identity == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  transport = capi->service_request ("transport");
  if (transport == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      capi->service_release (identity);
      identity = NULL;
      return GNUNET_SYSERR;
    }
  topology = capi->service_request ("topology");
  if (topology == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      capi->service_release (identity);
      identity = NULL;
      capi->service_release (transport);
      transport = NULL;
      return GNUNET_SYSERR;
    }
  stats = capi->service_request ("stats");
  if (stats != NULL)
    {
      stat_hello_out =
        stats->create (gettext_noop ("# Self advertisments transmitted"));
    }

  GNUNET_GE_ASSERT (capi->ectx,
                    0 == GNUNET_GC_set_configuration_value_string (capi->cfg,
                                                                   capi->ectx,
                                                                   "ABOUT",
                                                                   "advertising_gnunet",
                                                                   _
                                                                   ("ensures that this peer is known by other"
                                                                    " peers and discovers other peers")));
  
  return &api;
}

/**
 * Stop advertising.
 */
void
release_module_advertising_gnunet ()
{
  coreAPI->service_release (transport);
  transport = NULL;
  coreAPI->service_release (identity);
  identity = NULL;
  coreAPI->service_release (topology);
  topology = NULL;
  if (stats != NULL)
    {
      coreAPI->service_release (stats);
      stats = NULL;
    }
  coreAPI = NULL;
}




/* end of advertising.c */
