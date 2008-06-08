/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file advertising/advertising.c
 * @brief Cron-jobs that exchange hellos to ensure that the network is
 * connected (nodes know of each other).  This is implemented as
 * an application and not a service (since no API is provided for
 * clients to call on -- this just happens in the background).
 *
 * Nevertheless, every GNUnet peer should probably run advertising
 * at the moment.
 *
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_identity_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_pingpong_service.h"
#include "gnunet_stats_service.h"
#include "gnunet_topology_service.h"
#include "bootstrap.h"

/**
 * Send our hello to a random connected host on a regular basis.
 */
#define HELLO_BROADCAST_FREQUENCY (2 * GNUNET_CRON_MINUTES)

/**
 * From time to time, forward one hello from one peer to
 * a random other peer.
 */
#define HELLO_FORWARD_FREQUENCY (45 * GNUNET_CRON_SECONDS)

/**
 * Meanings of the bits in activeCronJobs (ACJ).
 */
#define ACJ_NONE 0
#define ACJ_ANNOUNCE 1
#define ACJ_FORWARD 2
#define ACJ_ALL (ACJ_ANNOUNCE | ACJ_FORWARD)

#define DEBUG_ADVERTISING GNUNET_NO

static GNUNET_CoreAPIForPlugins *coreAPI;

static GNUNET_Transport_ServiceAPI *transport;

static GNUNET_Identity_ServiceAPI *identity;

static GNUNET_Pingpong_ServiceAPI *pingpong;

static GNUNET_Topology_ServiceAPI *topology;

static GNUNET_Stats_ServiceAPI *stats;

static struct GNUNET_GE_Context *ectx;

static int stat_hello_in;

static int stat_hello_nat_in;

static int stat_hello_verified;

static int stat_hello_update;

static int stat_hello_discard;

static int stat_hello_no_transport;

static int stat_hello_ping_busy;

static int stat_hello_noselfad;

static int stat_hello_send_error;

static int stat_hello_out;

static int stat_hello_fwd;

static int stat_plaintextPingSent;


/**
 * Which types of cron-jobs are currently scheduled
 * with cron?
 */
static int activeCronJobs = ACJ_NONE;

static GNUNET_CronTime lasthelloMsg = 0;

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

static void
callAddHost (void *cls)
{
  GNUNET_MessageHello *hello = cls;

  if (stats != NULL)
    stats->change (stat_hello_verified, 1);
  identity->addHost (hello);
  GNUNET_free (hello);
}

/**
 * We have received a hello.  Verify (signature, integrity,
 * ping-pong) and store identity if ok.
 *
 * @param message the hello message
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
static int
receivedhello (const GNUNET_PeerIdentity * sender,
               const GNUNET_MessageHeader * message)
{
  GNUNET_TSession *tsession;
  GNUNET_MessageHello *copy;
  GNUNET_PeerIdentity foreignId;
  const GNUNET_MessageHello *msg;
  GNUNET_MessageHeader *ping;
  char *buffer;
  int helloEnd;
  int mtu;
  int res;
  GNUNET_CronTime now;
  GNUNET_EncName enc;

  /* first verify that it is actually a valid hello */
  msg = (const GNUNET_MessageHello *) message;
  if ((ntohs (msg->header.size) < sizeof (GNUNET_MessageHello)) ||
      (ntohs (msg->header.size) != GNUNET_sizeof_hello (msg)))
    {
      GNUNET_GE_BREAK_OP (ectx, 0);
      return GNUNET_SYSERR;
    }
  identity->getPeerIdentity (&msg->publicKey, &foreignId);
  if (0 != memcmp (&msg->senderIdentity.hashPubKey,
                   &foreignId.hashPubKey, sizeof (GNUNET_HashCode)))
    {
      GNUNET_GE_BREAK_OP (ectx, 0);
      return GNUNET_SYSERR;     /* public key and host GNUNET_hash do not match */
    }
  if (GNUNET_SYSERR == GNUNET_RSA_verify (&msg->senderIdentity,
                                          GNUNET_sizeof_hello (msg)
                                          - sizeof (GNUNET_RSA_Signature)
                                          - sizeof (GNUNET_RSA_PublicKey)
                                          - sizeof (GNUNET_MessageHeader),
                                          &msg->signature, &msg->publicKey))
    {
      IF_GELOG (ectx,
                GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                GNUNET_hash_to_enc (&msg->senderIdentity.hashPubKey, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("HELLO message from `%s' has an invalid signature. Dropping.\n"),
                     (char *) &enc);
      GNUNET_GE_BREAK_OP (ectx, 0);
      return GNUNET_SYSERR;     /* message invalid */
    }
  if ((GNUNET_Int32Time) ntohl (msg->expiration_time) >
      GNUNET_get_time_int32 (NULL) + GNUNET_MAX_HELLO_EXPIRES)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("HELLO message has expiration too far in the future. Dropping.\n"));
      GNUNET_GE_BREAK_OP (ectx, 0);
      return GNUNET_SYSERR;
    }
  if (GNUNET_SYSERR == transport->hello_verify (msg))
    {
#if DEBUG_ADVERTISING
      IF_GELOG (ectx,
                GNUNET_GE_INFO | GNUNET_GE_BULK | GNUNET_GE_USER,
                GNUNET_hash_to_enc (&msg->senderIdentity.hashPubKey, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_USER,
                     "Transport verification of HELLO message from `%s' failed (%u).\n",
                     &enc, ntohs (msg->protocol));
#endif
      return GNUNET_OK;         /* not good, but do process rest of message */
    }
  if (stats != NULL)
    stats->change (stat_hello_in, 1);
#if DEBUG_ADVERTISING
  IF_GELOG (ectx,
            GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&msg->senderIdentity.hashPubKey, &enc));
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "HELLO advertisement from `%s' for protocol %d received.\n",
                 &enc, ntohs (msg->protocol));
#endif
  if (ntohs (msg->protocol) == GNUNET_TRANSPORT_PROTOCOL_NUMBER_NAT)
    {
      /* We *can* not verify NAT.  Ever.  So all we
         can do is just accept it.  The best thing
         that we may do is check that it was not
         forwarded by another peer (forwarding NAT
         advertisements is invalid), but even that
         check can not be done securely (since we
         have to accept hellos in plaintext).  Thus
         we take NAT advertisements at face value
         (which is GNUNET_OK since we never attempt to
         connect to a NAT). */
      identity->addHost (msg);
      if (stats != NULL)
        stats->change (stat_hello_nat_in, 1);
#if DEBUG_ADVERTISING
      IF_GELOG (ectx,
                GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                GNUNET_hash_to_enc (&msg->senderIdentity.hashPubKey, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "HELLO advertisement from `%s' for NAT, no verification required.\n",
                     &enc);
#endif
      return GNUNET_OK;
    }

  /* Then check if we have seen this hello before, if it is identical
     except for the TTL, we trust it and do not play PING-PONG */
  copy =
    identity->identity2Hello (&foreignId, ntohs (msg->protocol), GNUNET_NO);
  if (NULL != copy)
    {
      if ((ntohs (copy->senderAddressSize) ==
           ntohs (msg->senderAddressSize)) &&
          (0 == memcmp (&msg->MTU,
                        &copy->MTU,
                        sizeof (unsigned short) * 2 +
                        sizeof (unsigned int) +
                        ntohs (copy->senderAddressSize))))
        {
          /* ok, we've seen this one exactly like this before (at most the
             TTL has changed); thus we can 'trust' it without playing
             ping-pong */
          identity->addHost (msg);
          if (stats != NULL)
            stats->change (stat_hello_update, 1);
          GNUNET_free (copy);
#if DEBUG_ADVERTISING
          IF_GELOG (ectx,
                    GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                    GNUNET_hash_to_enc (&msg->senderIdentity.hashPubKey,
                                        &enc));
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "HELLO advertisement from `%s' for protocol %d updates old advertisement, no verification required.\n",
                         &enc, ntohs (msg->protocol));
#endif
          return GNUNET_OK;
        }
#if DEBUG_ADVERTISING
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "HELLO advertisement differs from prior knowledge,"
                     " requireing ping-pong confirmation.\n");
#endif
      GNUNET_free (copy);
    }

  if (GNUNET_YES == GNUNET_GC_get_configuration_value_yesno (coreAPI->cfg,
                                                             "GNUNETD",
                                                             "PRIVATE-NETWORK",
                                                             GNUNET_NO))
    {
      /* the option 'PRIVATE-NETWORK' can be used
         to limit the connections of this peer to
         peers of which the hostkey has been copied
         by hand to data/hosts;  if this option is
         given, GNUnet will not accept advertisements
         of peers that the local node does not already
         know about.  Note that in order for this
         option to work, HOSTLISTURL should either
         not be set at all or be set to a trusted
         peer that only advertises the private network.
         Also, the option does NOT work at the moment
         if the NAT transport is loaded; for that,
         a couple of lines above would need some minor
         editing :-). */
#if DEBUG_ADVERTISING
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_BULK | GNUNET_GE_USER,
                     "Private network, discarding unknown advertisements\n");
#endif
      return GNUNET_SYSERR;
    }

  /* Ok, must play PING-PONG. Add the hello to the temporary
     (in-memory only) buffer to make it available for a short
     time in order to play PING-PONG */
  identity->addHostTemporarily (msg);

  now = GNUNET_get_time ();
  if ((sender != NULL) &&
      ((now - lasthelloMsg) / GNUNET_CRON_SECONDS) *
      (GNUNET_network_monitor_get_limit (coreAPI->load_monitor,
                                         GNUNET_ND_DOWNLOAD))
      < GNUNET_sizeof_hello (msg) * 10)
    {
      /* do not use more than about 10% of the
         available bandwidth to VERIFY hellos (by sending
         our own with a PING).  This does not affect
         the hello advertising.  Sure, we should not
         advertise much more than what other peers
         can verify, but the problem is that buggy/
         malicious peers can spam us with hellos, and
         we don't want to follow that up with massive
         hello-ing by ourselves. */
#if DEBUG_ADVERTISING
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_BULK | GNUNET_GE_USER,
                     "Not enough resources to verify HELLO message at this time (%u * %u < %u * 10)\n",
                     (unsigned int) ((now - lasthelloMsg) /
                                     GNUNET_CRON_SECONDS),
                     (unsigned int)
                     GNUNET_network_monitor_get_limit (coreAPI->load_monitor,
                                                       GNUNET_ND_DOWNLOAD),
                     (unsigned int) GNUNET_sizeof_hello (msg));
#endif
      if (stats != NULL)
        stats->change (stat_hello_discard, 1);
      return GNUNET_SYSERR;
    }
  lasthelloMsg = now;


  /* Establish session as advertised in the hello */
  tsession = transport->connect (msg, __FILE__, GNUNET_NO);
  if (tsession == NULL)
    {
      if (stats != NULL)
        stats->change (stat_hello_no_transport, 1);
#if DEBUG_ADVERTISING
      IF_GELOG (ectx,
                GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                GNUNET_hash_to_enc (&msg->senderIdentity.hashPubKey, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Failed to connect to `%s'.  Verification failed.\n",
                     &enc);
#endif
      return GNUNET_SYSERR;     /* could not connect */
    }

  /* build message to send, ping must contain return-information,
     such as a selection of our hellos... */
  mtu = transport->mtu_get (tsession->ttype);
  if (mtu == 0)
    {
      mtu = 2048;               /* bound size */
    }
  else
    {
      GNUNET_GE_ASSERT (ectx, mtu > GNUNET_P2P_MESSAGE_OVERHEAD);
      mtu -= GNUNET_P2P_MESSAGE_OVERHEAD;
    }
  copy = GNUNET_malloc (GNUNET_sizeof_hello (msg));
  memcpy (copy, msg, GNUNET_sizeof_hello (msg));
  ping = pingpong->pingUser (&msg->senderIdentity,
                             &callAddHost, copy, GNUNET_YES, rand ());
  if (ping == NULL)
    {
      res = GNUNET_SYSERR;
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     _("Could not send HELLO+PING, ping buffer full.\n"));
      transport->disconnect (tsession, __FILE__);
      if (stats != NULL)
        stats->change (stat_hello_ping_busy, 1);
      return GNUNET_SYSERR;
    }
  buffer = GNUNET_malloc (mtu);
  if (mtu > ntohs (ping->size))
    {
      helloEnd =
        transport->hello_advertisements_get (mtu - ntohs (ping->size),
                                             buffer);
      GNUNET_GE_ASSERT (ectx, mtu - ntohs (ping->size) >= helloEnd);
    }
  else
    {
      helloEnd = -2;
    }
  if (helloEnd <= 0)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("Failed to create an advertisement for this peer. Will not send PING.\n"));
      GNUNET_free (buffer);
      if (stats != NULL)
        stats->change (stat_hello_noselfad, 1);
      transport->disconnect (tsession, __FILE__);
#if DEBUG_ADVERTISING
      IF_GELOG (ectx,
                GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                GNUNET_hash_to_enc (&msg->senderIdentity.hashPubKey, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Failed to connect advertisement for myself.  Verification failed.\n",
                     &enc);
#endif
      return GNUNET_SYSERR;
    }
  res = GNUNET_OK;
  memcpy (&buffer[helloEnd], ping, ntohs (ping->size));
  helloEnd += ntohs (ping->size);
  GNUNET_free (ping);

  /* ok, finally we can send! */
  if ((res == GNUNET_OK) &&
      (GNUNET_SYSERR == coreAPI->plaintext_send (tsession, buffer, helloEnd)))
    {

      if (stats != NULL)
        stats->change (stat_hello_send_error, 1);
#if DEBUG_ADVERTISING
      IF_GELOG (ectx,
                GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                GNUNET_hash_to_enc (&msg->senderIdentity.hashPubKey, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Failed to transmit advertisement for myself.  Verification failed.\n",
                     &enc);
#endif
      res = GNUNET_SYSERR;
    }
  if (res == GNUNET_OK)
    {
      if (stats != NULL)
        stats->change (stat_plaintextPingSent, 1);
    }
  GNUNET_free (buffer);
  if (GNUNET_SYSERR == transport->disconnect (tsession, __FILE__))
    res = GNUNET_SYSERR;
  return res;
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
 * Tell a couple of random hosts on the currentKnownHost list
 * that we exist (called for each transport)...
 */
static void
broadcasthelloTransport (GNUNET_TransportAPI * tapi, void *cls)
{
  const int *prob = cls;
  SendData sd;
  GNUNET_CronTime now;

  if (GNUNET_network_monitor_get_load
      (coreAPI->load_monitor, GNUNET_ND_UPLOAD) > 100)
    return;                     /* network load too high... */
  if (((*prob) != 0)
      && (0 != GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, *prob)))
    return;                     /* ignore */
  now = GNUNET_get_time ();
  sd.n = identity->forEachHost (now, NULL, NULL);       /* just count */
  sd.m = transport->hello_create (tapi->protocol_number);
  if (sd.m == NULL)
    return;
#if DEBUG_ADVERTISING
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _("Advertising my transport %d to selected peers.\n"),
                 tapi->protocol_number);
#endif
  identity->addHost (sd.m);
  if (sd.n < 1)
    {
      if (identity->forEachHost (0, NULL, NULL) == 0)
        GNUNET_GE_LOG (ectx,
                       GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                       _("Announcing ourselves pointless: "
                         "no other peers are known to us so far.\n"));
      GNUNET_free (sd.m);
      return;                   /* no point in trying... */
    }
  identity->forEachHost (now, &broadcastHelper, &sd);
  GNUNET_free (sd.m);
}

/**
 * Tell a couple of random hosts on the currentKnownHost list
 * that we exist...
 */
static void
broadcasthello (void *unused)
{
  unsigned int i;

  if (GNUNET_network_monitor_get_load
      (coreAPI->load_monitor, GNUNET_ND_UPLOAD) > 100)
    return;                     /* network load too high... */
  if (GNUNET_cpu_get_load (coreAPI->ectx, coreAPI->cfg) > 100)
    return;                     /* CPU load too high... */
  i = transport->iterate_available (NULL, NULL);
  if (i > 0)
    transport->iterate_available (&broadcasthelloTransport, &i);
}

typedef struct
{
  GNUNET_MessageHello *msg;
  int prob;
} FCC;

static void
forwardCallback (const GNUNET_PeerIdentity * peer, void *cls)
{
  FCC *fcc = cls;
  if (GNUNET_network_monitor_get_load
      (coreAPI->load_monitor, GNUNET_ND_UPLOAD) > 100)
    return;                     /* network load too high... */
  if ((fcc->prob != 0)
      && (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, fcc->prob) != 0))
    return;                     /* only forward with a certain chance */
  if (0 == memcmp (&peer->hashPubKey,
                   &fcc->msg->senderIdentity.hashPubKey,
                   sizeof (GNUNET_HashCode)))
    return;                     /* do not bounce the hello of a peer back
                                   to the same peer! */
  if (stats != NULL)
    stats->change (stat_hello_fwd, 1);
  coreAPI->ciphertext_send (peer, &fcc->msg->header, 0, /* priority */
                            HELLO_BROADCAST_FREQUENCY);
}

/**
 * Forward hellos from all known hosts to all connected hosts.
 */
static int
forwardhelloHelper (const GNUNET_PeerIdentity * peer,
                    unsigned short protocol, int confirmed, void *data)
{
  int *probability = data;
  GNUNET_MessageHello *hello;
  GNUNET_Int32Time now;
  int count;
  FCC fcc;

  if (GNUNET_network_monitor_get_load
      (coreAPI->load_monitor, GNUNET_ND_UPLOAD) > 100)
    return GNUNET_SYSERR;       /* network load too high... */
  if (confirmed == GNUNET_NO)
    return GNUNET_OK;
  if (protocol == GNUNET_TRANSPORT_PROTOCOL_NUMBER_NAT)
    return GNUNET_OK;           /* don't forward NAT addresses */
  hello = identity->identity2Hello (peer, protocol, GNUNET_NO);
  if (NULL == hello)
    return GNUNET_OK;           /* this should not happen */
  /* do not forward expired hellos */
  GNUNET_get_time_int32 (&now);
  if ((GNUNET_Int32Time) ntohl (hello->expiration_time) < now)
    {
#if DEBUG_ADVERTISING
      GNUNET_EncName enc;
      /* remove hellos that expired */
      IF_GELOG (ectx,
                GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                GNUNET_hash_to_enc (&peer->hashPubKey, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Removing HELLO from peer `%s' (expired %ds ago).\n",
                     &enc, now - ntohl (hello->expiration_time));
#endif
      identity->delHostFromKnown (peer, protocol);
      GNUNET_free (hello);
      (*probability)--;
      return GNUNET_OK;
    }
  if (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, (*probability) + 1) != 0)
    {
      GNUNET_free (hello);
      return GNUNET_OK;         /* only forward with a certain chance,
                                   (on average: 1 peer per run!) */
    }
  count = coreAPI->p2p_connections_iterate (NULL, NULL);
  if (count > 0)
    {
      fcc.msg = hello;
      fcc.prob = count;
      coreAPI->p2p_connections_iterate (&forwardCallback, &fcc);
    }
  GNUNET_free (hello);
  return GNUNET_OK;
}

/**
 * Forward hellos from all known hosts to all connected hosts.
 * We do on average 1 forwarding (by random selection of
 * source and target).
 */
static void
forwardhello (void *unused)
{
  int count;

  if (GNUNET_cpu_get_load (coreAPI->ectx, coreAPI->cfg) > 100)
    return;                     /* CPU load too high... */
  if (GNUNET_network_monitor_get_load
      (coreAPI->load_monitor, GNUNET_ND_UPLOAD) > 100)
    return;                     /* network load too high... */
  count = identity->forEachHost (0, NULL, NULL);
  if (count > 0)
    identity->forEachHost (0,   /* ignore blacklisting */
                           &forwardhelloHelper, &count);
}

/**
 * Type for a hello send via an encrypted channel.
 */
static int
ehelloHandler (const GNUNET_PeerIdentity * sender,
               const GNUNET_MessageHeader * message)
{
  if (GNUNET_OK == receivedhello (sender, message))
    {
      /* if the hello was ok, update traffic preference
         for the peer (depending on how much we like
         to learn about other peers) */
      coreAPI->p2p_connection_preference_increase (sender,
                                                   getConnectPriority ());
    }
  return GNUNET_OK;             /* even if we had errors processing the hello, keep going */
}

/**
 * Type for a hello send in plaintext.
 */
static int
phelloHandler (const GNUNET_PeerIdentity * sender,
               const GNUNET_MessageHeader * message,
               GNUNET_TSession * session)
{
  receivedhello (sender, message);
  return GNUNET_OK;
}

/**
 * The configuration has changed, update set of running cron jobs.
 * Does not have to suspend cron since this guaranteed to be a cron
 * job!
 */
static int
configurationUpdateCallback (void *ctx,
                             struct GNUNET_GC_Configuration *cfg,
                             struct GNUNET_GE_Context *ectx,
                             const char *section, const char *option)
{
  if (0 != strcmp (section, "NETWORK"))
    return 0;
  if (ACJ_ANNOUNCE == (activeCronJobs & ACJ_ANNOUNCE))
    {
      if (GNUNET_YES == GNUNET_GC_get_configuration_value_yesno (cfg,
                                                                 "NETWORK",
                                                                 "DISABLE-ADVERTISEMENTS",
                                                                 GNUNET_NO))
        GNUNET_cron_del_job (coreAPI->cron,
                             &broadcasthello, HELLO_BROADCAST_FREQUENCY,
                             NULL);
      activeCronJobs -= ACJ_ANNOUNCE;
    }
  else
    {
      if (GNUNET_YES != GNUNET_GC_get_configuration_value_yesno (cfg,
                                                                 "NETWORK",
                                                                 "DISABLE-ADVERTISEMENTS",
                                                                 GNUNET_NO))
        GNUNET_cron_add_job (coreAPI->cron,
                             &broadcasthello,
                             15 * GNUNET_CRON_SECONDS,
                             HELLO_BROADCAST_FREQUENCY, NULL);
      activeCronJobs += ACJ_ANNOUNCE;
    }
  if (ACJ_FORWARD == (activeCronJobs & ACJ_FORWARD))
    {
      if (GNUNET_YES != GNUNET_GC_get_configuration_value_yesno (cfg,
                                                                 "NETWORK",
                                                                 "HELLOEXCHANGE",
                                                                 GNUNET_YES))
        {
          GNUNET_cron_del_job (coreAPI->cron, &forwardhello, HELLO_FORWARD_FREQUENCY, NULL);    /* seven minutes: exchange */
        }
      activeCronJobs -= ACJ_FORWARD;
    }
  else
    {
      if (GNUNET_YES == GNUNET_GC_get_configuration_value_yesno (cfg,
                                                                 "NETWORK",
                                                                 "HELLOEXCHANGE",
                                                                 GNUNET_YES))
        {
          GNUNET_cron_add_job (coreAPI->cron,
                               &forwardhello,
                               15 * GNUNET_CRON_SECONDS,
                               HELLO_FORWARD_FREQUENCY, NULL);
        }
      activeCronJobs += ACJ_FORWARD;
    }
  return 0;
}

/**
 * Start advertising.
 */
int
initialize_module_advertising (GNUNET_CoreAPIForPlugins * capi)
{
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
  pingpong = capi->service_request ("pingpong");
  if (pingpong == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      capi->service_release (identity);
      identity = NULL;
      capi->service_release (transport);
      transport = NULL;
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
      capi->service_release (pingpong);
      pingpong = NULL;
      return GNUNET_SYSERR;
    }
  stats = capi->service_request ("stats");
  if (stats != NULL)
    {
      stat_hello_in =
        stats->create (gettext_noop ("# Peer advertisements received"));
      stat_hello_nat_in =
        stats->create (gettext_noop
                       ("# Peer advertisements of type NAT received"));
      stat_hello_verified =
        stats->create (gettext_noop
                       ("# Peer advertisements confirmed via PONG"));
      stat_hello_update =
        stats->create (gettext_noop
                       ("# Peer advertisements updating earlier HELLOs"));
      stat_hello_discard =
        stats->create (gettext_noop
                       ("# Peer advertisements discarded due to load"));
      stat_hello_no_transport =
        stats->create (gettext_noop
                       ("# Peer advertisements for unsupported transport"));
      stat_hello_ping_busy =
        stats->create (gettext_noop
                       ("# Peer advertisements not confirmed due to ping busy"));
      stat_hello_noselfad =
        stats->create (gettext_noop
                       ("# Peer advertisements not confirmed due to lack of self ad"));
      stat_hello_send_error =
        stats->create (gettext_noop
                       ("# Peer advertisements not confirmed due to send error"));
      stat_hello_out =
        stats->create (gettext_noop ("# Self advertisments transmitted"));
      stat_hello_fwd =
        stats->create (gettext_noop ("# Foreign advertisements forwarded"));
      stat_plaintextPingSent =
        stats->create (gettext_noop ("# plaintext PING messages sent"));
    }

  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _
                 ("`%s' registering handler %d (plaintext and ciphertext)\n"),
                 "advertising", GNUNET_P2P_PROTO_HELLO);

  capi->p2p_ciphertext_handler_register (GNUNET_P2P_PROTO_HELLO,
                                         &ehelloHandler);
  capi->p2p_plaintext_handler_register (GNUNET_P2P_PROTO_HELLO,
                                        &phelloHandler);
  if (0 !=
      GNUNET_GC_attach_change_listener (capi->cfg,
                                        &configurationUpdateCallback, NULL))
    GNUNET_GE_BREAK (capi->ectx, 0);
  startBootstrap (capi);
  GNUNET_GE_ASSERT (capi->ectx,
                    0 == GNUNET_GC_set_configuration_value_string (capi->cfg,
                                                                   capi->ectx,
                                                                   "ABOUT",
                                                                   "advertising",
                                                                   _
                                                                   ("ensures that this peer is known by other"
                                                                    " peers and discovers other peers")));
  return GNUNET_OK;
}

/**
 * Stop advertising.
 */
void
done_module_advertising ()
{
  stopBootstrap ();
  GNUNET_GC_detach_change_listener (coreAPI->cfg,
                                    &configurationUpdateCallback, NULL);
  if (ACJ_ANNOUNCE == (activeCronJobs & ACJ_ANNOUNCE))
    {
      GNUNET_cron_del_job (coreAPI->cron,
                           &broadcasthello, HELLO_BROADCAST_FREQUENCY, NULL);
      activeCronJobs -= ACJ_ANNOUNCE;
    }
  if (ACJ_FORWARD == (activeCronJobs & ACJ_FORWARD))
    {
      GNUNET_cron_del_job (coreAPI->cron, &forwardhello, HELLO_FORWARD_FREQUENCY, NULL);        /* seven minutes: exchange */
      activeCronJobs -= ACJ_FORWARD;
    }
  coreAPI->p2p_ciphertext_handler_unregister (GNUNET_P2P_PROTO_HELLO,
                                              &ehelloHandler);
  coreAPI->p2p_plaintext_handler_unregister (GNUNET_P2P_PROTO_HELLO,
                                             &phelloHandler);
  coreAPI->service_release (transport);
  transport = NULL;
  coreAPI->service_release (identity);
  identity = NULL;
  coreAPI->service_release (pingpong);
  pingpong = NULL;
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
