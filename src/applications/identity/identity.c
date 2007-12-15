/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2007 Christian Grothoff (and other contributing authors)

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
 * @file identity/identity.c
 * @brief maintains list of known peers
 *
 * Code to maintain the list of currently known hosts (in memory
 * structure of data/hosts) and (temporary) blacklisting information
 * and a list of hellos that are temporary unless confirmed via PONG
 * (used to give the transport module the required information for the
 * PING).
 *
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_directories.h"
#include "gnunet_identity_service.h"
#include "gnunet_transport_service.h"
#include "identity.h"
#include "hostkey.h"

#define DEBUG_IDENTITY GNUNET_NO

#define MAX_TEMP_HOSTS 32

#define TRUSTDIR "data/credit/"
#define HOST_DIR "data/hosts/"

/**
 * Masks to keep track when the trust has changed and
 * to get the real trust value.
 */
#define TRUST_REFRESH_MASK 0x80000000

#define TRUST_ACTUAL_MASK  0x7FFFFFFF

#define MAX_DATA_HOST_FREQ (5 * GNUNET_CRON_MINUTES)

#define CRON_DATA_HOST_FREQ (15 * GNUNET_CRON_MINUTES)

#define CRON_TRUST_FLUSH_FREQ (5 * GNUNET_CRON_MINUTES)

#define CRON_DISCARD_HOSTS_INTERVAL (GNUNET_CRON_DAYS)

#define CRON_DISCARDS_HOSTS_AFTER (3 * GNUNET_CRON_MONTHS)

typedef struct
{

  GNUNET_PeerIdentity identity;

  /**
   * How long is this host blacklisted? (if at all)
   */
  GNUNET_CronTime until;

  /**
   * what would be the next increment for blacklisting?
   */
  GNUNET_CronTime delta;

  /**
   * hellos for the peer (maybe NULL)!
   */
  GNUNET_MessageHello **hellos;

  unsigned int helloCount;

  /**
   * for which protocols is this host known?
   */
  unsigned short *protocols;

  unsigned int protocolCount;

  /**
   * should we also reject incoming messages? (GNUNET_YES/GNUNET_NO)
   */
  int strict;

  /**
   * trust rating for this peer
   */
  unsigned int trust;

} HostEntry;

/**
 * The list of known hosts.
 */
static HostEntry **hosts_ = NULL;

/**
 * The current (allocated) size of knownHosts
 */
static unsigned int sizeOfHosts_ = 0;

/**
 * The number of actual entries in knownHosts
 */
static unsigned int numberOfHosts_;

/**
 * A lock for accessing knownHosts
 */
static struct GNUNET_Mutex *lock_;

/**
 * Directory where the hellos are stored in (data/hosts)
 */
static char *networkIdDirectory;

/**
 * Where do we store trust information?
 */
static char *trustDirectory;

/**
 * The list of temporarily known hosts
 */
static HostEntry tempHosts[MAX_TEMP_HOSTS];

static GNUNET_PeerIdentity myIdentity;

static struct GNUNET_GE_Context *ectx;

static GNUNET_CoreAPIForPlugins *coreAPI;

/**
 * Get the filename under which we would store the GNUNET_MessageHello
 * for the given host and protocol.
 * @return filename of the form DIRECTORY/HOSTID.PROTOCOL
 */
static char *
getHostFileName (const GNUNET_PeerIdentity * id, unsigned short protocol)
{
  GNUNET_EncName fil;
  char *fn;
  size_t n;

  GNUNET_hash_to_enc (&id->hashPubKey, &fil);
  n = strlen (networkIdDirectory) + sizeof (GNUNET_EncName) + 1 + 5 + 1;
  fn = GNUNET_malloc (n);
  GNUNET_snprintf (fn, n, "%s%s.%u", networkIdDirectory, (char *) &fil,
                   protocol);
  return fn;
}

/**
 * Find the host entry for the given peer.  Call
 * only when synchronized!
 * @return NULL if not found
 */
static HostEntry *
findHost (const GNUNET_PeerIdentity * id)
{
  int i;

  GNUNET_GE_ASSERT (ectx, numberOfHosts_ <= sizeOfHosts_);
  for (i = 0; i < numberOfHosts_; i++)
    if ((0 ==
         memcmp (id, &hosts_[i]->identity, sizeof (GNUNET_PeerIdentity))))
      return hosts_[i];
  return NULL;
}

/**
 * Add a host to the list.
 *
 * @param identity the identity of the host
 * @param protocol the protocol for the host
 */
static void
addHostToKnown (const GNUNET_PeerIdentity * identity, unsigned short protocol)
{
  HostEntry *entry;
  int i;
  GNUNET_EncName fil;
  char *fn;
  unsigned int trust;

  GNUNET_GE_ASSERT (ectx, numberOfHosts_ <= sizeOfHosts_);
  GNUNET_mutex_lock (lock_);
  entry = findHost (identity);
  if (entry == NULL)
    {
      entry = GNUNET_malloc (sizeof (HostEntry));

      entry->identity = *identity;
      entry->until = 0;
      entry->delta = 30 * GNUNET_CRON_SECONDS;
      entry->protocols = NULL;
      entry->protocolCount = 0;
      entry->strict = GNUNET_NO;
      entry->hellos = NULL;
      entry->helloCount = 0;
      GNUNET_hash_to_enc (&identity->hashPubKey, &fil);
      fn =
        GNUNET_malloc (strlen (trustDirectory) + sizeof (GNUNET_EncName) + 1);
      strcpy (fn, trustDirectory);
      strcat (fn, (char *) &fil);
      if ((GNUNET_disk_file_test (ectx,
                                  fn) == GNUNET_YES) &&
          (sizeof (unsigned int) ==
           GNUNET_disk_file_read (ectx, fn, sizeof (unsigned int), &trust)))
        {
          entry->trust = ntohl (trust);
        }
      else
        {
          entry->trust = 0;
        }
      GNUNET_free (fn);

      if (numberOfHosts_ == sizeOfHosts_)
        GNUNET_array_grow (hosts_, sizeOfHosts_, sizeOfHosts_ + 32);
      hosts_[numberOfHosts_++] = entry;
    }
  for (i = 0; i < entry->protocolCount; i++)
    {
      if (entry->protocols[i] == protocol)
        {
          GNUNET_mutex_unlock (lock_);
          return;               /* already there */
        }
    }
  GNUNET_array_grow (entry->protocols, entry->protocolCount,
                     entry->protocolCount + 1);
  entry->protocols[entry->protocolCount - 1] = protocol;
  GNUNET_mutex_unlock (lock_);
}

/**
 * Increase the host credit by a value.
 *
 * @param hostId is the identity of the host
 * @param value is the int value by which the
 *  host credit is to be increased or decreased
 * @returns the actual change in trust (positive or negative)
 */
static int
changeHostTrust (const GNUNET_PeerIdentity * hostId, int value)
{
  HostEntry *host;

  if (value == 0)
    return 0;

  GNUNET_mutex_lock (lock_);
  host = findHost (hostId);
  if (host == NULL)
    {
      addHostToKnown (hostId, GNUNET_TRANSPORT_PROTOCOL_NUMBER_NAT);
      host = findHost (hostId);
      if (host == NULL)
        {
          GNUNET_GE_BREAK (ectx, 0);
          GNUNET_mutex_unlock (lock_);
          return 0;
        }
    }
  if (((int) (host->trust & TRUST_ACTUAL_MASK)) + value < 0)
    {
      value = -(host->trust & TRUST_ACTUAL_MASK);
      host->trust = 0 | TRUST_REFRESH_MASK;     /* 0 remaining */
    }
  else
    {
      host->trust = ((host->trust & TRUST_ACTUAL_MASK) + value)
        | TRUST_REFRESH_MASK;
    }
  GNUNET_mutex_unlock (lock_);
  return value;
}

/**
 * Obtain the trust record of a peer.
 *
 * @param hostId the identity of the peer
 * @return the amount of trust we currently have in that peer
 */
static unsigned int
getHostTrust (const GNUNET_PeerIdentity * hostId)
{
  HostEntry *host;
  unsigned int trust;

  GNUNET_mutex_lock (lock_);
  host = findHost (hostId);
  if (host == NULL)
    trust = 0;
  else
    trust = host->trust & TRUST_ACTUAL_MASK;
  GNUNET_mutex_unlock (lock_);
  return trust;
}


static int
cronHelper (const char *filename, const char *dirname, void *unused)
{
  GNUNET_PeerIdentity identity;
  GNUNET_EncName id;
  unsigned int protoNumber;
  char *fullname;

  GNUNET_GE_ASSERT (ectx, numberOfHosts_ <= sizeOfHosts_);
  GNUNET_GE_ASSERT (ectx, sizeof (GNUNET_EncName) == 104);
  if (2 == sscanf (filename, "%103c.%u", (char *) &id, &protoNumber))
    {
      id.encoding[sizeof (GNUNET_EncName) - 1] = '\0';
      if (GNUNET_OK ==
          GNUNET_enc_to_hash ((char *) &id, &identity.hashPubKey))
        {
          addHostToKnown (&identity, (unsigned short) protoNumber);
          return GNUNET_OK;
        }
    }

  fullname =
    GNUNET_malloc (strlen (filename) + strlen (networkIdDirectory) + 1);
  strcpy (fullname, networkIdDirectory);
  strcat (fullname, filename);
  if (GNUNET_disk_file_test (ectx, fullname) == GNUNET_YES)
    {
      if (0 == UNLINK (fullname))
        GNUNET_GE_LOG (ectx,
                       GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_ADMIN |
                       GNUNET_GE_BULK,
                       _
                       ("File `%s' in directory `%s' does not match naming convention. "
                        "Removed.\n"), filename, networkIdDirectory);
      else
        GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                     GNUNET_GE_ERROR | GNUNET_GE_USER |
                                     GNUNET_GE_BULK, "unlink", fullname);
    }
  else if (GNUNET_disk_directory_test (ectx, fullname) == GNUNET_YES)
    {
      if (0 == RMDIR (fullname))
        GNUNET_GE_LOG (ectx,
                       GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_ADMIN |
                       GNUNET_GE_BULK,
                       _
                       ("Directory `%s' in directory `%s' does not match naming convention. "
                        "Removed.\n"), filename, networkIdDirectory);
      else
        GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                     GNUNET_GE_ERROR | GNUNET_GE_USER |
                                     GNUNET_GE_BULK, "rmdir", fullname);
    }
  GNUNET_free (fullname);
  return GNUNET_OK;
}

/**
 * Call this method periodically to scan data/hosts for new hosts.
 */
static void
cronScanDirectoryDataHosts (void *unused)
{
  static GNUNET_CronTime lastRun;
  static int retries;
  int count;
  GNUNET_CronTime now;

  now = GNUNET_get_time ();
  if (lastRun + MAX_DATA_HOST_FREQ > now)
    return;                     /* prevent scanning more than
                                   once every 5 min */
  lastRun = now;
  count =
    GNUNET_disk_directory_scan (ectx, networkIdDirectory, &cronHelper, NULL);
  if (count <= 0)
    {
      retries++;
      if ((retries & 32) > 0)
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK,
                         _("Still no peers found in `%s'!\n"),
                         networkIdDirectory);
        }
    }
  GNUNET_GE_ASSERT (ectx, numberOfHosts_ <= sizeOfHosts_);
}


/**
 * Obtain identity from publicPrivateKey.
 * @param pubKey the public key of the host
 * @param result address where to write the identity of the node
 */
static void
getPeerIdentity (const GNUNET_RSA_PublicKey * pubKey,
                 GNUNET_PeerIdentity * result)
{
  if (pubKey == NULL)
    {
      memset (&result, 0, sizeof (GNUNET_PeerIdentity));
    }
  else
    {
      GNUNET_hash (pubKey, sizeof (GNUNET_RSA_PublicKey),
                   &result->hashPubKey);
    }
}

/**
 * Add a host to the temporary list.
 */
static void
addHostTemporarily (const GNUNET_MessageHello * tmp)
{
  static int tempHostsNextSlot;
  GNUNET_MessageHello *msg;
  HostEntry *entry;
  int i;
  int slot;
  GNUNET_PeerIdentity have;

  getPeerIdentity (&tmp->publicKey, &have);
  if (0 != memcmp (&have, &tmp->senderIdentity, sizeof (GNUNET_PeerIdentity)))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return;
    }
  GNUNET_mutex_lock (lock_);
  entry = findHost (&tmp->senderIdentity);
  if ((entry != NULL) && (entry->helloCount > 0))
    {
      GNUNET_mutex_unlock (lock_);
      return;
    }
  msg = GNUNET_malloc (GNUNET_sizeof_hello (tmp));
  memcpy (msg, tmp, GNUNET_sizeof_hello (tmp));
  slot = tempHostsNextSlot;
  for (i = 0; i < MAX_TEMP_HOSTS; i++)
    if (0 == memcmp (&tmp->senderIdentity,
                     &tempHosts[i].identity, sizeof (GNUNET_PeerIdentity)))
      slot = i;
  if (slot == tempHostsNextSlot)
    {
      tempHostsNextSlot++;
      if (tempHostsNextSlot >= MAX_TEMP_HOSTS)
        tempHostsNextSlot = 0;
    }
  entry = &tempHosts[slot];
  entry->identity = msg->senderIdentity;
  entry->until = 0;
  entry->delta = 0;
  for (i = 0; i < entry->helloCount; i++)
    GNUNET_free (entry->hellos[i]);
  GNUNET_array_grow (entry->hellos, entry->helloCount, 1);
  GNUNET_array_grow (entry->protocols, entry->protocolCount, 1);
  entry->hellos[0] = msg;
  entry->protocols[0] = ntohs (msg->protocol);
  entry->strict = GNUNET_NO;
  entry->trust = 0;
  GNUNET_mutex_unlock (lock_);
}

/**
 * Delete a host from the list.
 */
static void
delHostFromKnown (const GNUNET_PeerIdentity * identity,
                  unsigned short protocol)
{
  HostEntry *entry;
  char *fn;
  int i;
  int j;

  GNUNET_GE_ASSERT (ectx, numberOfHosts_ <= sizeOfHosts_);
  GNUNET_GE_ASSERT (ectx, protocol != GNUNET_TRANSPORT_PROTOCOL_NUMBER_ANY);
  GNUNET_mutex_lock (lock_);
  for (i = 0; i < numberOfHosts_; i++)
    {
      if ((0 == memcmp (identity,
                        &hosts_[i]->identity, sizeof (GNUNET_PeerIdentity))))
        {
          entry = hosts_[i];
          for (j = 0; j < entry->protocolCount; j++)
            {
              if (protocol == entry->protocols[j])
                {
                  entry->protocols[j]
                    = entry->protocols[entry->protocolCount - 1];
                  GNUNET_array_grow (entry->protocols,
                                     entry->protocolCount,
                                     entry->protocolCount - 1);
                }
            }
          for (j = 0; j < entry->helloCount; j++)
            {
              if (protocol == ntohs (entry->hellos[j]->protocol))
                {
                  GNUNET_free (entry->hellos[j]);
                  entry->hellos[j] = entry->hellos[entry->helloCount - 1];
                  GNUNET_array_grow (entry->hellos,
                                     entry->helloCount,
                                     entry->helloCount - 1);
                }
            }
          /* also remove hello file itself */
          fn = getHostFileName (identity, protocol);
          if (0 != UNLINK (fn))
            GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                         GNUNET_GE_WARNING | GNUNET_GE_USER |
                                         GNUNET_GE_BULK, "unlink", fn);
          GNUNET_free (fn);

          if (entry->protocolCount == 0)
            {
              if (entry->helloCount > 0)
                {
                  for (j = 0; j < entry->helloCount; j++)
                    GNUNET_free (entry->hellos[j]);
                  GNUNET_array_grow (entry->hellos, entry->helloCount, 0);
                }
              hosts_[i] = hosts_[--numberOfHosts_];
              GNUNET_free (entry);
            }
          GNUNET_mutex_unlock (lock_);
          GNUNET_GE_ASSERT (ectx, numberOfHosts_ <= sizeOfHosts_);
          return;               /* deleted */
        }
    }
  GNUNET_mutex_unlock (lock_);
}

/**
 * Bind a host address (hello) to a hostId.
 * @param msg the verified (!) hello message
 */
static void
bindAddress (const GNUNET_MessageHello * msg)
{
  char *fn;
  char *buffer;
  GNUNET_MessageHello *oldMsg;
  int size;
  HostEntry *host;
  int i;
  GNUNET_PeerIdentity have;

  getPeerIdentity (&msg->publicKey, &have);
  if (0 != memcmp (&have, &msg->senderIdentity, sizeof (GNUNET_PeerIdentity)))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return;
    }
  GNUNET_GE_ASSERT (ectx, numberOfHosts_ <= sizeOfHosts_);
  GNUNET_GE_ASSERT (ectx, msg != NULL);
  fn = getHostFileName (&msg->senderIdentity, ntohs (msg->protocol));
  buffer = GNUNET_malloc (GNUNET_MAX_BUFFER_SIZE);
  if (GNUNET_disk_file_test (ectx, fn) == GNUNET_YES)
    {
      size = GNUNET_disk_file_read (ectx, fn, GNUNET_MAX_BUFFER_SIZE, buffer);
      if (size >= sizeof (GNUNET_MessageHello))
        {
          oldMsg = (GNUNET_MessageHello *) buffer;
          if ((unsigned int) size == GNUNET_sizeof_hello (oldMsg))
            {
              if (ntohl (oldMsg->expirationTime) >
                  ntohl (msg->expirationTime))
                {
                  GNUNET_free (fn);
                  GNUNET_free (buffer);
                  return;       /* have more recent hello in stock */
                }
            }
        }
    }
  GNUNET_disk_file_write (ectx, fn, msg, GNUNET_sizeof_hello (msg), "644");
  GNUNET_free (fn);
  GNUNET_free (buffer);

  GNUNET_mutex_lock (lock_);
  addHostToKnown (&msg->senderIdentity, ntohs (msg->protocol));
  host = findHost (&msg->senderIdentity);
  GNUNET_GE_ASSERT (ectx, host != NULL);

  for (i = 0; i < host->helloCount; i++)
    {
      if (msg->protocol == host->hellos[i]->protocol)
        {
          GNUNET_free (host->hellos[i]);
          host->hellos[i] = NULL;
          break;
        }
    }
  if (i == host->helloCount)
    GNUNET_array_grow (host->hellos, host->helloCount, host->helloCount + 1);
  host->hellos[i] = GNUNET_malloc (GNUNET_sizeof_hello (msg));
  memcpy (host->hellos[i], msg, GNUNET_sizeof_hello (msg));
  GNUNET_mutex_unlock (lock_);
  GNUNET_GE_ASSERT (ectx, numberOfHosts_ <= sizeOfHosts_);
}

/**
 * Obtain the public key and address of a known host.  If no specific
 * protocol is specified (GNUNET_TRANSPORT_PROTOCOL_NUMBER_ANY), hellos for cheaper
 * protocols are returned with preference (randomness!).
 *
 * @param hostId the host id
 * @param protocol the protocol that we need,
 *        GNUNET_TRANSPORT_PROTOCOL_NUMBER_ANY if we do not care which protocol
 * @param tryTemporaryList is it ok to check the unverified hellos?
 * @param result where to store the result
 * @returns GNUNET_SYSERR on failure, GNUNET_OK on success
 */
static GNUNET_MessageHello *
identity2Hello (const GNUNET_PeerIdentity * hostId,
                unsigned short protocol, int tryTemporaryList)
{
  GNUNET_MessageHello *result;
  HostEntry *host;
  char *fn;
  GNUNET_MessageHello buffer;
  GNUNET_PeerIdentity have;
  int size;
  int i;
  int j;

  GNUNET_GE_ASSERT (ectx, numberOfHosts_ <= sizeOfHosts_);
  GNUNET_mutex_lock (lock_);
  if (GNUNET_YES == tryTemporaryList)
    {
      /* ok, then first try temporary hosts
         (in memory, cheapest!) */
      for (i = 0; i < MAX_TEMP_HOSTS; i++)
        {
          host = &tempHosts[i];
          if ((host->helloCount > 0) &&
              (0 ==
               memcmp (hostId, &host->identity,
                       sizeof (GNUNET_PeerIdentity))))
            {
              if (protocol == GNUNET_TRANSPORT_PROTOCOL_NUMBER_ANY)
                {
                  j =
                    GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                                       host->helloCount);
                }
              else
                {
                  j = 0;
                  while ((j < host->helloCount) &&
                         (host->protocols[j] != protocol))
                    j++;
                }
              if (j == host->helloCount)
                {
                  /* not found */
                  GNUNET_mutex_unlock (lock_);
                  return NULL;
                }
              result = GNUNET_malloc (GNUNET_sizeof_hello (host->hellos[j]));
              memcpy (result, host->hellos[j],
                      GNUNET_sizeof_hello (host->hellos[j]));
              GNUNET_mutex_unlock (lock_);
              return result;
            }
        }
    }

  host = findHost (hostId);
  if ((host == NULL) || (host->protocolCount == 0))
    {
      GNUNET_mutex_unlock (lock_);
      return NULL;
    }

  if (protocol == GNUNET_TRANSPORT_PROTOCOL_NUMBER_ANY)
    protocol =
      host->
      protocols[GNUNET_random_u32
                (GNUNET_RANDOM_QUALITY_WEAK, host->protocolCount)];

  for (i = 0; i < host->helloCount; i++)
    {
      if (ntohs (host->hellos[i]->protocol) == protocol)
        {
          result = GNUNET_malloc (GNUNET_sizeof_hello (host->hellos[i]));
          memcpy (result,
                  host->hellos[i], GNUNET_sizeof_hello (host->hellos[i]));
          GNUNET_mutex_unlock (lock_);
          return result;
        }
    }

  /* do direct read */
  fn = getHostFileName (hostId, protocol);
  if (1 != GNUNET_disk_file_test (ectx, fn))
    {
      GNUNET_free (fn);
      GNUNET_mutex_unlock (lock_);
      return NULL;
    }
  size =
    GNUNET_disk_file_read (ectx, fn, sizeof (GNUNET_MessageHello), &buffer);
  if (size != sizeof (GNUNET_MessageHello))
    {
      if (0 == UNLINK (fn))
        GNUNET_GE_LOG (ectx,
                       GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK,
                       _
                       ("Removed file `%s' containing invalid HELLO data.\n"),
                       fn);
      else
        GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                     GNUNET_GE_USER | GNUNET_GE_BULK,
                                     "unlink", fn);
      GNUNET_free (fn);
      GNUNET_mutex_unlock (lock_);
      return NULL;
    }
  result = GNUNET_malloc (GNUNET_sizeof_hello (&buffer));
  size =
    GNUNET_disk_file_read (ectx, fn, GNUNET_sizeof_hello (&buffer), result);
  getPeerIdentity (&result->publicKey, &have);
  if (((unsigned int) size != GNUNET_sizeof_hello (&buffer)) ||
      (0 != memcmp (&have,
                    hostId,
                    sizeof (GNUNET_PeerIdentity))) ||
      (0 !=
       memcmp (&have, &result->senderIdentity, sizeof (GNUNET_PeerIdentity))))
    {
      if (0 == UNLINK (fn))
        GNUNET_GE_LOG (ectx,
                       GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK,
                       _
                       ("Removed file `%s' containing invalid HELLO data.\n"),
                       fn);
      else
        GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                     GNUNET_GE_USER | GNUNET_GE_BULK,
                                     "unlink", fn);
      GNUNET_free (fn);
      GNUNET_free (result);
      GNUNET_mutex_unlock (lock_);
      return NULL;
    }
  GNUNET_free (fn);
  GNUNET_array_grow (host->hellos, host->helloCount, host->helloCount + 1);
  host->hellos[host->helloCount - 1]
    = GNUNET_malloc (GNUNET_sizeof_hello (&buffer));
  memcpy (host->hellos[host->helloCount - 1],
          result, GNUNET_sizeof_hello (&buffer));
  GNUNET_mutex_unlock (lock_);
  return result;
}


/**
 * @param signer the identity of the host that
 *        presumably signed the message
 * @param message the signed message
 * @param size the size of the message
 * @param sig the signature
 * @return GNUNET_OK on success, GNUNET_SYSERR on error (verification failed)
 */
static int
verifyPeerSignature (const GNUNET_PeerIdentity * signer,
                     const void *message, int size,
                     const GNUNET_RSA_Signature * sig)
{
  GNUNET_MessageHello *hello;
  int res;

  hello =
    identity2Hello (signer, GNUNET_TRANSPORT_PROTOCOL_NUMBER_ANY, GNUNET_YES);
  if (hello == NULL)
    {
#if DEBUG_IDENTITY
      GNUNET_EncName enc;

      IF_GELOG (ectx,
                GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_BULK,
                GNUNET_hash_to_enc (&signer->hashPubKey, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_BULK,
                     _
                     ("Signature failed verification: peer `%s' not known.\n"),
                     &enc);
#endif
      return GNUNET_SYSERR;
    }
  res = GNUNET_RSA_verify (message, size, sig, &hello->publicKey);
  if (res == GNUNET_SYSERR)
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_ERROR | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER |
                   GNUNET_GE_USER,
                   _("Signature failed verification: signature invalid.\n"));
  GNUNET_free (hello);
  return res;
}

/**
 * Blacklist a host. This method is called if a host
 * failed to respond to a connection attempt.
 *
 * @param identity the ID of the peer to blacklist
 * @param desperation how desperate are we to connect? [0,MAXHOSTS]
 * @param strict should we reject incoming connection attempts as well?
 * @return GNUNET_OK on success GNUNET_SYSERR on error
 */
static int
blacklistHost (const GNUNET_PeerIdentity * identity,
               unsigned int desperation, int strict)
{
  GNUNET_EncName hn;
  HostEntry *entry;
  int i;
  GNUNET_CronTime now;

  GNUNET_GE_ASSERT (ectx, numberOfHosts_ <= sizeOfHosts_);
  GNUNET_mutex_lock (lock_);
  entry = findHost (identity);
  if (entry == NULL)
    {
      for (i = 0; i < MAX_TEMP_HOSTS; i++)
        {
          if (0 == memcmp (identity,
                           &tempHosts[i].identity,
                           sizeof (GNUNET_PeerIdentity)))
            {
              entry = &tempHosts[i];
              break;
            }
        }
    }
  if (entry == NULL)
    {
      GNUNET_mutex_unlock (lock_);
      return GNUNET_SYSERR;
    }
  now = GNUNET_get_time ();
  if ((entry->strict == GNUNET_YES) && (strict == GNUNET_NO))
    {
      /* stronger blacklisting in place! */
      GNUNET_mutex_unlock (lock_);
      return GNUNET_OK;
    }
  if (strict)
    {
      entry->delta = desperation * GNUNET_CRON_SECONDS;
    }
  else
    {
      if (entry->until < now)
        entry->delta =
          GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                             1 + desperation * GNUNET_CRON_SECONDS);
      else
        entry->delta +=
          GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                             1 + desperation * GNUNET_CRON_SECONDS);
    }
  if (entry->delta > 4 * GNUNET_CRON_HOURS)
    entry->delta = 4 * GNUNET_CRON_HOURS;
  entry->until = now + entry->delta;
  entry->strict = strict;
  GNUNET_hash_to_enc (&identity->hashPubKey, &hn);
#if DEBUG_IDENTITY
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                 "Blacklisting host `%s' for %llu seconds"
                 " until %llu (strict=%d).\n",
                 &hn, entry->delta / GNUNET_CRON_SECONDS, entry->until,
                 strict);
#endif
  GNUNET_mutex_unlock (lock_);
  return GNUNET_OK;
}

/**
 * Is the host currently blacklisted (i.e. we refuse to talk)?
 *
 * @param identity host to check
 * @return GNUNET_YES if true, else GNUNET_NO
 */
static int
isBlacklisted (const GNUNET_PeerIdentity * identity, int strict)
{
  GNUNET_CronTime now;
  HostEntry *entry;

  GNUNET_GE_ASSERT (ectx, numberOfHosts_ <= sizeOfHosts_);
  GNUNET_mutex_lock (lock_);
  entry = findHost (identity);
  if (entry == NULL)
    {
      GNUNET_mutex_unlock (lock_);
      return GNUNET_NO;
    }
  now = GNUNET_get_time ();
  if ((now < entry->until)
      && ((entry->strict == GNUNET_YES) || (strict == GNUNET_NO)))
    {
#if DEBUG_IDENTITY
      GNUNET_EncName enc;

      IF_GELOG (ectx,
                GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_BULK,
                GNUNET_hash_to_enc (&identity->hashPubKey, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_BULK,
                     _
                     ("Peer `%s' is currently strictly blacklisted (for another %llums).\n"),
                     &enc, entry->until - now);
#endif
      GNUNET_mutex_unlock (lock_);
      return GNUNET_YES;
    }
  else
    {
      GNUNET_mutex_unlock (lock_);
      return GNUNET_NO;
    }
}

/**
 * Whitelist a host. This method is called if a host
 * successfully established a connection. It typically
 * resets the exponential backoff to the smallest value.
 * @return GNUNET_OK on success GNUNET_SYSERR on error
 */
static int
whitelistHost (const GNUNET_PeerIdentity * identity)
{
  HostEntry *entry;
  int i;

  GNUNET_GE_ASSERT (ectx, numberOfHosts_ <= sizeOfHosts_);
  GNUNET_mutex_lock (lock_);
  entry = findHost (identity);
  if (entry == NULL)
    {
      for (i = 0; i < MAX_TEMP_HOSTS; i++)
        {
          if (0 == memcmp (identity,
                           &tempHosts[i].identity,
                           sizeof (GNUNET_PeerIdentity)))
            {
              entry = &tempHosts[i];
              break;
            }
        }
    }
  if (entry == NULL)
    {
      GNUNET_mutex_unlock (lock_);
      return GNUNET_SYSERR;
    }
  entry->delta = 30 * GNUNET_CRON_SECONDS;
  entry->until = 0;
  entry->strict = GNUNET_NO;
  GNUNET_mutex_unlock (lock_);
  return GNUNET_OK;
}

/**
 * Call a method for each known host.
 *
 * @param callback the method to call for each host
 * @param now the time to use for excluding hosts
 *        due to blacklisting, use 0
 *        to go through all hosts.
 * @param data an argument to pass to the method
 * @return the number of hosts matching
 */
static int
forEachHost (GNUNET_CronTime now, GNUNET_HostProcessor callback, void *data)
{
  int i;
  int j;
  int count;
  GNUNET_PeerIdentity hi;
  unsigned short proto;
  HostEntry *entry;
  int ret;

  ret = GNUNET_OK;
  GNUNET_GE_ASSERT (ectx, numberOfHosts_ <= sizeOfHosts_);
  count = 0;
  GNUNET_mutex_lock (lock_);
  for (i = 0; i < numberOfHosts_; i++)
    {
      entry = hosts_[i];
      if (0 ==
          memcmp (&entry->identity, &myIdentity,
                  sizeof (GNUNET_PeerIdentity)))
        continue;
      if ((now == 0) || (now >= entry->until))
        {
          count++;
          if (callback != NULL)
            {
              hi = entry->identity;
              for (j = 0; j < entry->protocolCount; j++)
                {
                  proto = entry->protocols[j];
                  GNUNET_mutex_unlock (lock_);
                  ret = callback (&hi, proto, GNUNET_YES, data);
                  GNUNET_mutex_lock (lock_);
                  if (ret != GNUNET_OK)
                    break;
                  /* we gave up the lock,
                     need to re-acquire entry (if possible)! */
                  if (i >= numberOfHosts_)
                    break;
                  entry = hosts_[i];
                  if (0 == memcmp (&entry->identity,
                                   &myIdentity, sizeof (GNUNET_PeerIdentity)))
                    break;
                }
            }
        }
      else
        {
#if 0
#if DEBUG_IDENTITY
          GNUNET_EncName enc;

          IF_GELOG (ectx,
                    GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_BULK,
                    GNUNET_hash_to_enc (&entry->identity.hashPubKey, &enc));
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_BULK,
                         entry->strict ?
                         _
                         ("Peer `%s' is currently strictly blacklisted (for another %llums).\n")
                         :
                         _
                         ("Peer `%s' is currently blacklisted (for another %llums).\n"),
                         &enc, entry->until - now);
#endif
#endif
        }
      if (ret != GNUNET_OK)
        break;

    }
  for (i = 0; i < MAX_TEMP_HOSTS; i++)
    {
      if (ret != GNUNET_OK)
        break;
      entry = &tempHosts[i];
      if (entry->helloCount == 0)
        continue;
      if ((now == 0) || (now >= entry->until))
        {
          count++;
          if (callback != NULL)
            {
              hi = entry->identity;
              proto = entry->protocols[0];
              GNUNET_mutex_unlock (lock_);
              ret = callback (&hi, proto, GNUNET_YES, data);
              GNUNET_mutex_lock (lock_);
            }
        }
    }
  GNUNET_mutex_unlock (lock_);
  return count;
}

/**
 * Write host-trust information to a file - flush the buffer entry!
 * Assumes synchronized access.
 */
static void
flushHostCredit (HostEntry * host)
{
  GNUNET_EncName fil;
  char *fn;
  unsigned int trust;

  if ((host->trust & TRUST_REFRESH_MASK) == 0)
    return;                     /* unchanged */
  host->trust = host->trust & TRUST_ACTUAL_MASK;
  GNUNET_hash_to_enc (&host->identity.hashPubKey, &fil);
  fn = GNUNET_malloc (strlen (trustDirectory) + sizeof (GNUNET_EncName) + 1);
  strcpy (fn, trustDirectory);
  strcat (fn, (char *) &fil);
  if (host->trust == 0)
    {
      if ((0 != UNLINK (fn)) && (errno != ENOENT))
        GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                     GNUNET_GE_WARNING | GNUNET_GE_USER |
                                     GNUNET_GE_BULK, "unlink", fn);
    }
  else
    {
      trust = htonl (host->trust);
      GNUNET_disk_file_write (ectx, fn, &trust, sizeof (unsigned int), "644");
    }
  GNUNET_free (fn);
}

/**
 * Call once in a while to synchronize trust values with the disk.
 */
static void
cronFlushTrustBuffer (void *unused)
{
  int i;
  GNUNET_mutex_lock (lock_);
  for (i = 0; i < numberOfHosts_; i++)
    flushHostCredit (hosts_[i]);
  GNUNET_mutex_unlock (lock_);
}

/**
 * @brief delete expired HELLO entries in data/hosts/
 */
static int
discardHostsHelper (const char *filename, const char *dirname, void *now)
{
  char *fn;
  struct stat hostStat;
  int hostFile;

  fn = GNUNET_malloc (strlen (filename) + strlen (dirname) + 2);
  sprintf (fn, "%s%s%s", dirname, DIR_SEPARATOR_STR, filename);
  hostFile = GNUNET_disk_file_open (ectx, fn, O_WRONLY);
  if (hostFile != -1)
    {
      if (FSTAT (hostFile, &hostStat) == 0)
        {
          CLOSE (hostFile);

          if (hostStat.st_mtime +
              (CRON_DISCARDS_HOSTS_AFTER / GNUNET_CRON_SECONDS) <
              *((time_t *) now))
            UNLINK (fn);
        }
    }
  GNUNET_free (fn);

  return GNUNET_OK;
}

/**
 * @brief scan host directory for expired entries
 */
static void
cronDiscardHosts (void *unused)
{
  time_t timeNow;

  timeNow = time (NULL);
  GNUNET_disk_directory_scan (ectx,
                              networkIdDirectory,
                              &discardHostsHelper, (void *) &timeNow);
}


static int
identityRequestConnectHandler (struct GNUNET_ClientHandle *sock,
                               const GNUNET_MessageHeader * message)
{
  const CS_identity_connect_MESSAGE *msg;
  int ret;

  if (sizeof (CS_identity_connect_MESSAGE) != ntohs (message->size))
    return GNUNET_SYSERR;
  msg = (const CS_identity_connect_MESSAGE *) message;
  whitelistHost (&msg->other);
  coreAPI->unicast (&msg->other, NULL, 0, 0);
  ret = coreAPI->queryPeerStatus (&msg->other, NULL, NULL);
  return coreAPI->sendValueToClient (sock,
                                     ret !=
                                     GNUNET_OK ? GNUNET_NO : GNUNET_YES);
}

static int
identityHelloHandler (struct GNUNET_ClientHandle *sock,
                      const GNUNET_MessageHeader * message)
{
  const GNUNET_MessageHello *msg;
  GNUNET_MessageHello *hello;

  if (sizeof (GNUNET_MessageHello) > ntohs (message->size))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  msg = (const GNUNET_MessageHello *) message;
  if (GNUNET_sizeof_hello (msg) != ntohs (message->size))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  hello = GNUNET_malloc (ntohs (msg->header.size));
  memcpy (hello, msg, ntohs (msg->header.size));
  hello->header.type = htons (GNUNET_P2P_PROTO_HELLO);
  coreAPI->p2p_inject_message (NULL,
                               (const char *) hello,
                               ntohs (msg->header.size), GNUNET_NO, NULL);
  GNUNET_free (hello);
  return GNUNET_OK;
}

static int
identityRequestHelloHandler (struct GNUNET_ClientHandle *sock,
                             const GNUNET_MessageHeader * message)
{
  /* transport types in order of preference
     for location URIs (by best guess at what
     people are most likely to actually run) */
  static unsigned short types[] = {
    GNUNET_TRANSPORT_PROTOCOL_NUMBER_TCP,
    GNUNET_TRANSPORT_PROTOCOL_NUMBER_UDP,
    GNUNET_TRANSPORT_PROTOCOL_NUMBER_HTTP,
    GNUNET_TRANSPORT_PROTOCOL_NUMBER_TCP6,
    GNUNET_TRANSPORT_PROTOCOL_NUMBER_UDP6,
    GNUNET_TRANSPORT_PROTOCOL_NUMBER_SMTP,
    GNUNET_TRANSPORT_PROTOCOL_NUMBER_NAT,
    0,
  };
  GNUNET_Transport_ServiceAPI *tapi;
  GNUNET_MessageHello *hello;
  int pos;
  int ret;

  /* we cannot permanently load transport
     since that would cause a cyclic dependency;
     however, we can request it briefly here */
  tapi = coreAPI->request_service ("transport");
  if (tapi == NULL)
    return GNUNET_SYSERR;
  hello = NULL;
  pos = 0;
  while ((hello == NULL) && (types[pos] != 0))
    hello = tapi->createhello (types[pos++]);
  coreAPI->release_service (tapi);
  if (hello == NULL)
    return GNUNET_SYSERR;
  hello->header.type = htons (GNUNET_CS_PROTO_IDENTITY_HELLO);
  ret = coreAPI->cs_send_to_client (sock, &hello->header, GNUNET_YES);
  GNUNET_free (hello);
  return ret;
}

static int
identityRequestSignatureHandler (struct GNUNET_ClientHandle *sock,
                                 const GNUNET_MessageHeader * message)
{
  CS_identity_signature_MESSAGE reply;

  if (ntohs (message->size) <= sizeof (GNUNET_MessageHeader))
    return GNUNET_SYSERR;
  reply.header.size = htons (sizeof (CS_identity_signature_MESSAGE));
  reply.header.type = htons (GNUNET_CS_PROTO_IDENTITY_SIGNATURE);
  if (GNUNET_OK != signData (&message[1],
                             ntohs (message->size) -
                             sizeof (GNUNET_MessageHeader), &reply.sig))
    return GNUNET_SYSERR;
  return coreAPI->cs_send_to_client (sock, &reply.header, GNUNET_YES);
}

static int
hostInfoIterator (const GNUNET_PeerIdentity * identity,
                  unsigned short protocol, int confirmed, void *data)
{
  struct GNUNET_ClientHandle *sock = data;
  GNUNET_Transport_ServiceAPI *transport;
  CS_identity_peer_info_MESSAGE *reply;
  GNUNET_MessageHello *hello;
  void *address;
  int ret;
  unsigned int len;
  unsigned int bpm;
  GNUNET_CronTime last;

  if (confirmed == GNUNET_NO)
    return GNUNET_OK;
  hello = identity2Hello (identity, protocol, GNUNET_YES);
  if (hello == NULL)
    return GNUNET_OK;           /* ignore -- happens if HELLO just expired */
  transport = coreAPI->request_service ("transport");
  if (transport == NULL)
    {
      GNUNET_free (hello);
      return GNUNET_OK;
    }

  len = 0;
  address = NULL;
  transport->helloToAddress (hello, &address, &len);
  GNUNET_free (hello);
  coreAPI->release_service (transport);
  if (len >= GNUNET_MAX_BUFFER_SIZE - sizeof (CS_identity_peer_info_MESSAGE))
    {
      GNUNET_free (address);
      address = NULL;
      len = 0;
    }
  if (GNUNET_OK != coreAPI->queryPeerStatus (identity, &bpm, &last))
    {
      last = 0;
      bpm = 0;
    }
  reply = GNUNET_malloc (sizeof (CS_identity_peer_info_MESSAGE) + len);
  reply->header.size = htons (sizeof (CS_identity_peer_info_MESSAGE) + len);
  reply->header.type = htons (GNUNET_CS_PROTO_IDENTITY_INFO);
  reply->peer = *identity;
  reply->last_message = GNUNET_htonll (last);
  reply->trust = htonl (getHostTrust (identity));
  reply->bpm = htonl (bpm);
  memcpy (&reply[1], address, len);
  GNUNET_free_non_null (address);
  ret = coreAPI->cs_send_to_client (sock, &reply->header, GNUNET_YES);
  GNUNET_free (reply);
  return ret;
}

static int
identityRequestInfoHandler (struct GNUNET_ClientHandle *sock,
                            const GNUNET_MessageHeader * message)
{
  forEachHost (0, &hostInfoIterator, sock);
  return coreAPI->sendValueToClient (sock, GNUNET_OK);
}


/**
 * Provide the Identity service.
 *
 * @param capi the core API
 * @return NULL on errors, ID_API otherwise
 */
GNUNET_Identity_ServiceAPI *
provide_module_identity (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_Identity_ServiceAPI id;
  char *gnHome;
  char *tmp;
  int i;

  coreAPI = capi;
  ectx = coreAPI->ectx;
  id.getPublicPrivateKey = &getPublicPrivateKey;
  id.getPeerIdentity = &getPeerIdentity;
  id.signData = &signData;
  id.decryptData = &decryptData;
  id.delHostFromKnown = &delHostFromKnown;
  id.addHostTemporarily = &addHostTemporarily;
  id.addHost = &bindAddress;
  id.forEachHost = &forEachHost;
  id.identity2Hello = &identity2Hello;
  id.verifyPeerSignature = &verifyPeerSignature;
  id.blacklistHost = &blacklistHost;
  id.isBlacklisted = &isBlacklisted;
  id.whitelistHost = &whitelistHost;
  id.changeHostTrust = &changeHostTrust;
  id.getHostTrust = &getHostTrust;

  for (i = 0; i < MAX_TEMP_HOSTS; i++)
    memset (&tempHosts[i], 0, sizeof (HostEntry));
  numberOfHosts_ = 0;

  gnHome = NULL;
  GNUNET_GE_ASSERT (ectx,
                    -1 !=
                    GNUNET_GC_get_configuration_value_filename (coreAPI->cfg,
                                                                "GNUNETD",
                                                                "GNUNETD_HOME",
                                                                GNUNET_DEFAULT_DAEMON_VAR_DIRECTORY,
                                                                &gnHome));
  if (gnHome == NULL)
    return NULL;
  GNUNET_disk_directory_create (ectx, gnHome);
  tmp = GNUNET_malloc (strlen (gnHome) + strlen (HOST_DIR) + 2);
  strcpy (tmp, gnHome);
  strcat (tmp, DIR_SEPARATOR_STR);
  strcat (tmp, HOST_DIR);
  networkIdDirectory = NULL;
  GNUNET_GE_ASSERT (ectx,
                    -1 !=
                    GNUNET_GC_get_configuration_value_filename (coreAPI->cfg,
                                                                "GNUNETD",
                                                                "HOSTS", tmp,
                                                                &networkIdDirectory));
  GNUNET_free (tmp);
  GNUNET_disk_directory_create (ectx, networkIdDirectory);
  trustDirectory = GNUNET_malloc (strlen (gnHome) + strlen (TRUSTDIR) + 2);
  strcpy (trustDirectory, gnHome);
  strcat (trustDirectory, DIR_SEPARATOR_STR);
  strcat (trustDirectory, TRUSTDIR);
  GNUNET_disk_directory_create (ectx, trustDirectory);
  GNUNET_free (gnHome);

  lock_ = GNUNET_mutex_create (GNUNET_YES);
  initPrivateKey (capi->ectx, capi->cfg);
  getPeerIdentity (getPublicPrivateKey (), &myIdentity);
  cronScanDirectoryDataHosts (NULL);
  GNUNET_cron_add_job (coreAPI->cron,
                       &cronScanDirectoryDataHosts,
                       CRON_DATA_HOST_FREQ, CRON_DATA_HOST_FREQ, NULL);
  GNUNET_cron_add_job (coreAPI->cron,
                       &cronFlushTrustBuffer,
                       CRON_TRUST_FLUSH_FREQ, CRON_TRUST_FLUSH_FREQ, NULL);
  GNUNET_cron_add_job (coreAPI->cron,
                       &cronDiscardHosts, 0, CRON_DISCARD_HOSTS_INTERVAL,
                       NULL);
  coreAPI->registerClientHandler (GNUNET_CS_PROTO_IDENTITY_CONNECT,
                                  &identityRequestConnectHandler);
  coreAPI->registerClientHandler (GNUNET_CS_PROTO_IDENTITY_HELLO,
                                  &identityHelloHandler);
  coreAPI->registerClientHandler (GNUNET_CS_PROTO_IDENTITY_REQUEST_HELLO,
                                  &identityRequestHelloHandler);
  coreAPI->registerClientHandler (GNUNET_CS_PROTO_IDENTITY_REQUEST_SIGNATURE,
                                  &identityRequestSignatureHandler);
  coreAPI->registerClientHandler (GNUNET_CS_PROTO_IDENTITY_REQUEST_INFO,
                                  &identityRequestInfoHandler);
  return &id;
}

/**
 * Shutdown Identity service.
 */
void
release_module_identity ()
{
  int i;
  int j;
  HostEntry *entry;

  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_IDENTITY_CONNECT,
                                    &identityRequestConnectHandler);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_IDENTITY_HELLO,
                                    &identityHelloHandler);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_IDENTITY_REQUEST_HELLO,
                                    &identityRequestHelloHandler);
  coreAPI->
    unregisterClientHandler (GNUNET_CS_PROTO_IDENTITY_REQUEST_SIGNATURE,
                             &identityRequestSignatureHandler);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_IDENTITY_REQUEST_INFO,
                                    &identityRequestInfoHandler);
  for (i = 0; i < MAX_TEMP_HOSTS; i++)
    {
      entry = &tempHosts[i];
      for (j = 0; j < entry->helloCount; j++)
        GNUNET_free (entry->hellos[j]);
      GNUNET_array_grow (entry->hellos, entry->helloCount, 0);
      GNUNET_array_grow (entry->protocols, entry->protocolCount, 0);
    }
  GNUNET_cron_del_job (coreAPI->cron,
                       &cronScanDirectoryDataHosts, CRON_DATA_HOST_FREQ,
                       NULL);
  GNUNET_cron_del_job (coreAPI->cron, &cronFlushTrustBuffer,
                       CRON_TRUST_FLUSH_FREQ, NULL);
  GNUNET_cron_del_job (coreAPI->cron, &cronDiscardHosts,
                       CRON_DISCARD_HOSTS_INTERVAL, NULL);
  cronFlushTrustBuffer (NULL);
  GNUNET_mutex_destroy (lock_);
  lock_ = NULL;
  for (i = 0; i < numberOfHosts_; i++)
    {
      entry = hosts_[i];
      for (j = 0; j < entry->helloCount; j++)
        GNUNET_free (entry->hellos[j]);
      GNUNET_array_grow (entry->hellos, entry->helloCount, 0);
      GNUNET_array_grow (entry->protocols, entry->protocolCount, 0);
      GNUNET_free (entry);
    }
  GNUNET_array_grow (hosts_, sizeOfHosts_, 0);
  numberOfHosts_ = 0;

  GNUNET_free (networkIdDirectory);
  networkIdDirectory = NULL;
  GNUNET_free (trustDirectory);
  trustDirectory = NULL;
  donePrivateKey ();
}

/* end of identity.c */
