/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005 Christian Grothoff (and other contributing authors)

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
#include "gnunet_identity_service.h"

#include "hostkey.h"

#define DEBUG_IDENTITY NO

#define MAX_TEMP_HOSTS 32

#define TRUSTDIR "data/credit/"
#define HOST_DIR "data/hosts/"

/**
 * Masks to keep track when the trust has changed and
 * to get the real trust value.
 */
#define TRUST_REFRESH_MASK 0x80000000

#define TRUST_ACTUAL_MASK  0x7FFFFFFF

#define MAX_DATA_HOST_FREQ (5 * cronMINUTES)

#define CRON_DATA_HOST_FREQ (15 * cronMINUTES)

#define CRON_TRUST_FLUSH_FREQ (5 * cronMINUTES)

typedef struct {
  PeerIdentity identity;
  /**
   *how long is this host blacklisted? (if at all)
   */
  cron_t until;

  /**
   * what would be the next increment for blacklisting?
   */
  cron_t delta;

  /**
   * hellos for the peer (maybe NULL)!
   */
  P2P_hello_MESSAGE ** helos;

  unsigned int heloCount;

  /**
   * for which protocols is this host known?
   */
  unsigned short * protocols;

  unsigned int protocolCount;

  /**
   * should we also reject incoming messages? (YES/NO)
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
static HostEntry ** hosts_ = NULL;

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
static Mutex lock_;

/**
 * Directory where the hellos are stored in (data/hosts)
 */
static char * networkIdDirectory;

/**
 * Where do we store trust information?
 */
static char * trustDirectory;

/**
 * The list of temporarily known hosts
 */
static HostEntry tempHosts[MAX_TEMP_HOSTS];

static PeerIdentity myIdentity;

/**
 * Get the filename under which we would store the P2P_hello_MESSAGE
 * for the given host and protocol.
 * @return filename of the form DIRECTORY/HOSTID.PROTOCOL
 */
static char * getHostFileName(const PeerIdentity * id,
			      const unsigned short protocol) {
  EncName fil;
  char * fn;
  size_t n;

  hash2enc(&id->hashPubKey,
	   &fil);
  n = strlen(networkIdDirectory) + sizeof(EncName) + 1 + 5 + 1;
  fn = MALLOC(n);
  SNPRINTF(fn,
	   n,
	   "%s%s.%u",
	   networkIdDirectory,
	   (char*) &fil,
	   protocol);
  return fn;
}

/**
 * Find the host entry for the given peer.  Call
 * only when synchronized!
 * @return NULL if not found
 */
static HostEntry * findHost(const PeerIdentity * id) {
  int i;

  GNUNET_ASSERT(numberOfHosts_ <= sizeOfHosts_);
  for (i=0;i<numberOfHosts_;i++)
    if ( (hostIdentityEquals(id,
			     &hosts_[i]->identity)) )
      return hosts_[i];
  return NULL;
}

/**
 * Add a host to the list.
 *
 * @param identity the identity of the host
 * @param protocol the protocol for the host
 */
static void addHostToKnown(const PeerIdentity * identity,
			   unsigned short protocol) {
  HostEntry * entry;
  int i;
  EncName fil;
  char * fn;
  unsigned int trust;

  GNUNET_ASSERT(numberOfHosts_ <= sizeOfHosts_);
  MUTEX_LOCK(&lock_);
  entry = findHost(identity);
  if (entry == NULL) {
    entry = MALLOC(sizeof(HostEntry));

    entry->identity = *identity;
    entry->until    = 0;
    entry->delta    = 30 * cronSECONDS;
    entry->protocols = NULL;
    entry->protocolCount = 0;
    entry->strict    = NO;
    entry->helos     = NULL;
    entry->heloCount = 0;
    hash2enc(&identity->hashPubKey,
	     &fil);
    fn = MALLOC(strlen(trustDirectory)+sizeof(EncName)+1);
    strcpy(fn, trustDirectory);
    strcat(fn, (char*) &fil);
    if (sizeof(unsigned int) ==
	readFile(fn,
		 sizeof(unsigned int),
		 &trust)) {
      entry->trust = ntohl(trust);
    } else {
      entry->trust = 0;
    }
    FREE(fn);

    if (numberOfHosts_ == sizeOfHosts_)
      GROW(hosts_,
	   sizeOfHosts_,
	   sizeOfHosts_+32);
    hosts_[numberOfHosts_++] = entry;
  }
  for (i=0;i<entry->protocolCount;i++) {
    if (entry->protocols[i] == protocol) {
      MUTEX_UNLOCK(&lock_);
      return; /* already there */
    }
  }
  GROW(entry->protocols,
       entry->protocolCount,
       entry->protocolCount+1);
  entry->protocols[entry->protocolCount-1]
    = protocol;
  MUTEX_UNLOCK(&lock_);
}

/**
 * Increase the host credit by a value.
 *
 * @param hostId is the identity of the host
 * @param value is the int value by which the
 *  host credit is to be increased or decreased
 * @returns the actual change in trust (positive or negative)
 */
static int changeHostTrust(const PeerIdentity * hostId,
			   int value){
  HostEntry * host;

  if (value == 0)
    return 0;

  MUTEX_LOCK(&lock_);
  host = findHost(hostId);
  if (host == NULL) {
    addHostToKnown(hostId,
		   NAT_PROTOCOL_NUMBER);
    host = findHost(hostId);
    if (host == NULL) {
      BREAK();
      MUTEX_UNLOCK(&lock_);
      return 0;
    }
  }
  if ( ((int) (host->trust & TRUST_ACTUAL_MASK)) + value < 0) {
    value = - (host->trust & TRUST_ACTUAL_MASK);
    host->trust = 0
      | TRUST_REFRESH_MASK; /* 0 remaining */
  } else {
    host->trust = ( (host->trust & TRUST_ACTUAL_MASK) + value)
      | TRUST_REFRESH_MASK;
  }
  MUTEX_UNLOCK(&lock_);
  return value;
}

/**
 * Obtain the trust record of a peer.
 *
 * @param hostId the identity of the peer
 * @return the amount of trust we currently have in that peer
 */
static unsigned int getHostTrust(const PeerIdentity * hostId) {
  HostEntry * host;
  unsigned int trust;

  MUTEX_LOCK(&lock_);
  host = findHost(hostId);
  if (host == NULL)
    trust = 0;
  else
    trust = host->trust & TRUST_ACTUAL_MASK;
  MUTEX_UNLOCK(&lock_);
  return trust;
}


static int cronHelper(const char * filename,
		      const char * dirname,
		      void * unused) {
  PeerIdentity identity;
  EncName id;
  unsigned int protoNumber;
  char * fullname;

  GNUNET_ASSERT(numberOfHosts_ <= sizeOfHosts_);
  GNUNET_ASSERT(sizeof(EncName) == 104);
  if (2 == sscanf(filename,
		  "%103c.%u",
		  (char*)&id,
		  &protoNumber)) {
    id.encoding[sizeof(EncName)-1] = '\0';
    if (OK == enc2hash((char*)&id,
		       &identity.hashPubKey)) {
      addHostToKnown(&identity,
		     (unsigned short) protoNumber);
      return OK;
    }
  }

  fullname = MALLOC(strlen(filename) +
		    strlen(networkIdDirectory) + 1);
  strcpy(fullname, networkIdDirectory);
  strcat(fullname, filename);
  if (0 == UNLINK(fullname))
    LOG(LOG_WARNING,
	_("File `%s' in directory `%s' does not match naming convention. "
	  "Removed.\n"),
	filename,
	networkIdDirectory);
  else
    LOG_FILE_STRERROR(LOG_ERROR,
		      "unlink",
		      fullname);
  FREE(fullname);
  return OK;
}

/**
 * Call this method periodically to scan data/hosts for new hosts.
 */
static void cronScanDirectoryDataHosts(void * unused) {
  static cron_t lastRun;
  static int retries;
  int count;
  cron_t now;

  cronTime(&now);
  if (lastRun + MAX_DATA_HOST_FREQ > now)
    return; /* prevent scanning more than
	       once every 5 min */
  lastRun = now;
  count = scanDirectory(networkIdDirectory,
			&cronHelper,
			NULL);
  if (count <= 0) {
    retries++;
    if ((retries & 32) > 0) {
      LOG(LOG_WARNING,
	  _("%s `%s' returned no known hosts!\n"),
	  "scanDirectory",
	  networkIdDirectory);
    }
  }
  GNUNET_ASSERT(numberOfHosts_ <= sizeOfHosts_);
}

/**
 * Add a host to the temporary list.
 */
static void addHostTemporarily(const P2P_hello_MESSAGE * tmp) {
  static int tempHostsNextSlot;
  P2P_hello_MESSAGE * msg;
  HostEntry * entry;
  int i;
  int slot;

  msg = MALLOC(P2P_hello_MESSAGE_size(tmp));
  memcpy(msg,
	 tmp,
	 P2P_hello_MESSAGE_size(tmp));
  MUTEX_LOCK(&lock_);
  entry = findHost(&msg->senderIdentity);
  if (entry == NULL) {
    slot = tempHostsNextSlot;
    for (i=0;i<MAX_TEMP_HOSTS;i++)
      if (hostIdentityEquals(&tmp->senderIdentity,
			     &tempHosts[i].identity))
	slot = i;
    if (slot == tempHostsNextSlot) {
      tempHostsNextSlot++;
      if (tempHostsNextSlot >= MAX_TEMP_HOSTS)
	tempHostsNextSlot = 0;
    }
    entry = &tempHosts[slot];
    entry->identity = msg->senderIdentity;
    entry->until = 0;
    entry->delta = 0;
    for (i=0;i<entry->heloCount;i++)
      FREE(entry->helos[i]);
    GROW(entry->helos,
	 entry->heloCount,
	 1);
    GROW(entry->protocols,
	 entry->protocolCount,
	 1);
    entry->helos[0] = msg;
    entry->protocols[0] = ntohs(msg->protocol);
    entry->strict = NO;
    entry->trust = 0;
  } else {
    FREE(msg);
  }
  MUTEX_UNLOCK(&lock_);
}

/**
 * Delete a host from the list.
 */
static void delHostFromKnown(const PeerIdentity * identity,
			     const unsigned short protocol) {
  HostEntry * entry;
  char * fn;
  int i;
  int j;

  GNUNET_ASSERT(numberOfHosts_ <= sizeOfHosts_);
  GNUNET_ASSERT(protocol != ANY_PROTOCOL_NUMBER);
  MUTEX_LOCK(&lock_);
  for (i=0;i<numberOfHosts_;i++) {
    if ( (hostIdentityEquals(identity,
			     &hosts_[i]->identity)) ) {
      entry = hosts_[i];
      for (j=0;j<entry->protocolCount;j++) {
	if (protocol == entry->protocols[j]) {
	  entry->protocols[j]
	    = entry->protocols[entry->protocolCount-1];
	  GROW(entry->protocols,
	       entry->protocolCount,
	       entry->protocolCount-1);
	}
      }
      for (j=0;j<entry->heloCount;j++) {
	if (protocol == ntohs(entry->helos[j]->protocol)) {
	  FREE(entry->helos[j]);
	  entry->helos[j]
	    = entry->helos[entry->heloCount-1];
	  GROW(entry->helos,
	       entry->heloCount,
	       entry->heloCount-1);
	}
      }
      /* also remove hello file itself */
      fn = getHostFileName(identity,
			   protocol);
      if (0 != UNLINK(fn))
	LOG_FILE_STRERROR(LOG_WARNING,
			  "unlink",
			  fn);
      FREE(fn);

      if (entry->protocolCount == 0) {
	if (entry->heloCount > 0) {
	  for (j=0;j<entry->heloCount;j++)
	    FREE(entry->helos[j]);
	  GROW(entry->helos,
	       entry->heloCount,
	       0);
	}
	hosts_[i] = hosts_[--numberOfHosts_];
	FREE(entry);
      }
      MUTEX_UNLOCK(&lock_);
      GNUNET_ASSERT(numberOfHosts_ <= sizeOfHosts_);
      return; /* deleted */
    }
  }
  MUTEX_UNLOCK(&lock_);
}

/**
 * Bind a host address (helo) to a hostId.
 * @param msg the verified (!) hello message
 */
static void bindAddress(const P2P_hello_MESSAGE * msg) {
  char * fn;
  char * buffer;
  P2P_hello_MESSAGE * oldMsg;
  int size;
  EncName enc;
  HostEntry * host;
  int i;

  GNUNET_ASSERT(numberOfHosts_ <= sizeOfHosts_);
  GNUNET_ASSERT(msg != NULL);
  IFLOG(LOG_INFO,
	hash2enc(&msg->senderIdentity.hashPubKey,
		 &enc));
#if DEBUG_IDENTITY
  LOG(LOG_INFO,
      "Binding address of node %s.%d\n",
      &enc,
      ntohs(msg->protocol));
#endif
  fn = getHostFileName(&msg->senderIdentity,
		       ntohs(msg->protocol));
  buffer = MALLOC(MAX_BUFFER_SIZE);
  size = readFile(fn,
		  MAX_BUFFER_SIZE,
		  buffer);
  oldMsg = (P2P_hello_MESSAGE*) buffer;
  if ((unsigned int)size == P2P_hello_MESSAGE_size(oldMsg)) {
    if (ntohl(oldMsg->expirationTime) > ntohl(msg->expirationTime)) {
      FREE(fn);
      FREE(buffer);
      return; /* have more recent hello in stock */
    }
  }
  writeFile(fn,
	    msg,
	    P2P_hello_MESSAGE_size(msg),
	    "644");
  FREE(fn);
  FREE(buffer);

  MUTEX_LOCK(&lock_);
  addHostToKnown(&msg->senderIdentity,
		 ntohs(msg->protocol));
  host = findHost(&msg->senderIdentity);
  GNUNET_ASSERT(host != NULL);

  for (i=0;i<host->heloCount;i++) {
    if (msg->protocol == host->helos[i]->protocol) {
      FREE(host->helos[i]);
      host->helos[i] = NULL;
      break;
    }
  }
  if (i == host->heloCount)
    GROW(host->helos,
	 host->heloCount,
	 host->heloCount+1);
  host->helos[i]
    = MALLOC(P2P_hello_MESSAGE_size(msg));
  memcpy(host->helos[i],
	 msg,
	 P2P_hello_MESSAGE_size(msg));
  MUTEX_UNLOCK(&lock_);
  GNUNET_ASSERT(numberOfHosts_ <= sizeOfHosts_);
}

/**
 * Obtain the public key and address of a known host.  If no specific
 * protocol is specified (ANY_PROTOCOL_NUMBER), hellos for cheaper
 * protocols are returned with preference (randomness!).
 *
 * @param hostId the host id
 * @param protocol the protocol that we need,
 *        ANY_PROTOCOL_NUMBER if we do not care which protocol
 * @param tryTemporaryList is it ok to check the unverified hellos?
 * @param result where to store the result
 * @returns SYSERR on failure, OK on success
 */
static P2P_hello_MESSAGE * identity2Helo(const PeerIdentity *  hostId,
				    unsigned short protocol,
				    int tryTemporaryList) {
  P2P_hello_MESSAGE * result;
  HostEntry * host;
  char * fn;
  P2P_hello_MESSAGE buffer;
  int size;
  int i;
  int j;
  int * perm;

  GNUNET_ASSERT(numberOfHosts_ <= sizeOfHosts_);
  MUTEX_LOCK(&lock_);
  if (YES == tryTemporaryList) {
    if (protocol == ANY_PROTOCOL_NUMBER)
      perm = permute(WEAK, MAX_TEMP_HOSTS);
    else
      perm = NULL;
    /* ok, then first try temporary hosts
       (in memory, cheapest!) */
    for (i=0;i<MAX_TEMP_HOSTS;i++) {
      if (perm == NULL)
	j = i;
      else
	j = perm[i];
      if ( (tempHosts[j].heloCount > 0) &&
	   hostIdentityEquals(hostId,
			      &tempHosts[j].identity) &&
	   ( (tempHosts[j].protocols[0] == protocol) ||
	     (protocol == ANY_PROTOCOL_NUMBER) ) ) {
	result = MALLOC(P2P_hello_MESSAGE_size(tempHosts[j].helos[0]));
	memcpy(result,
	       tempHosts[j].helos[0],
	       P2P_hello_MESSAGE_size(tempHosts[j].helos[0]));	
	MUTEX_UNLOCK(&lock_);
	FREENONNULL(perm);
	return result;
      }
    }
    FREENONNULL(perm);
  }

  host = findHost(hostId);
  if ( (host == NULL) ||
       (host->protocolCount == 0) ) {
    MUTEX_UNLOCK(&lock_);
    return NULL;
  }

  if (protocol == ANY_PROTOCOL_NUMBER)
    protocol = host->protocols[weak_randomi(host->protocolCount)];

  for (i=0;i<host->heloCount;i++) {
    if (ntohs(host->helos[i]->protocol) == protocol) {
      result
	= MALLOC(P2P_hello_MESSAGE_size(host->helos[i]));
      memcpy(result,
	     host->helos[i],
	     P2P_hello_MESSAGE_size(host->helos[i]));
      MUTEX_UNLOCK(&lock_);
      return result;
    }
  }

  /* do direct read */
  fn = getHostFileName(hostId,
		       protocol);
  size = readFile(fn,
		  sizeof(P2P_hello_MESSAGE),
		  &buffer);
  if (size != sizeof(P2P_hello_MESSAGE)) {
    struct stat buf;

    if (0 == STAT(fn,
		  &buf)) {
      if (0 == UNLINK(fn))
	LOG(LOG_WARNING,
	    _("Removed file `%s' containing invalid hello data.\n"),
	    fn);
      else
	LOG_FILE_STRERROR(LOG_ERROR,
			  "unlink",
			  fn);
    }
    FREE(fn);
    MUTEX_UNLOCK(&lock_);
    return NULL;
  }
  result = MALLOC(P2P_hello_MESSAGE_size(&buffer));
  size = readFile(fn,
		  P2P_hello_MESSAGE_size(&buffer),
		  result);
  if ((unsigned int)size != P2P_hello_MESSAGE_size(&buffer)) {
    if (0 == UNLINK(fn))
      LOG(LOG_WARNING,
	  _("Removed file `%s' containing invalid hello data.\n"),
	  fn);
    else
      LOG_FILE_STRERROR(LOG_ERROR,
			"unlink",
			fn);
    FREE(fn);
    FREE(result);
    MUTEX_UNLOCK(&lock_);
    return NULL;
  }
  FREE(fn);
  GROW(host->helos,
       host->heloCount,
       host->heloCount+1);
  host->helos[host->heloCount-1]
    = MALLOC(P2P_hello_MESSAGE_size(&buffer));
  memcpy(host->helos[host->heloCount-1],
	 result,
	 P2P_hello_MESSAGE_size(&buffer));
  MUTEX_UNLOCK(&lock_);
  return result;
}


/**
 * @param signer the identity of the host that
 *        presumably signed the message
 * @param message the signed message
 * @param size the size of the message
 * @param sig the signature
 * @return OK on success, SYSERR on error (verification failed)
 */
static int verifyPeerSignature(const PeerIdentity * signer,
			       const void * message,
			       int size,
			       const Signature * sig) {
  P2P_hello_MESSAGE * helo;
  int res;

  helo = identity2Helo(signer,
		       ANY_PROTOCOL_NUMBER,
		       YES);
  if (helo == NULL) {
    LOG(LOG_ERROR, _("Signature failed verification: other peer not known.\n"));
    return SYSERR;
  }
  res = verifySig(message, size, sig,
		  &helo->publicKey);
  if (res == SYSERR)
    LOG(LOG_ERROR, _("Signature failed verification: signature invalid.\n"));

  FREE(helo);
  return res;
}

/**
 * Blacklist a host. This method is called if a host
 * failed to respond to a connection attempt.
 *
 * @param identity the ID of the peer to blacklist
 * @param desperation how desperate are we to connect? [0,MAXHOSTS]
 * @param strict should we reject incoming connection attempts as well?
 * @return OK on success SYSERR on error
 */
static int blacklistHost(const PeerIdentity * identity,
			 unsigned int desperation,
			 int strict) {
  EncName hn;
  HostEntry * entry;
  int i;

  GNUNET_ASSERT(numberOfHosts_ <= sizeOfHosts_);
  MUTEX_LOCK(&lock_);
  entry = findHost(identity);
  if (entry == NULL) {
    for (i=0;i<MAX_TEMP_HOSTS;i++) {
      if (hostIdentityEquals(identity,
			     &tempHosts[i].identity)) {
	entry = &tempHosts[i];
	break;
      }
    }
  }
  if (entry == NULL) {
    MUTEX_UNLOCK(&lock_);
    return SYSERR;
  }
  if (strict == YES) {
    /* Presumably runs a broken version of GNUnet;
       blacklist for 1 day (we hope the other peer
       updates the software eventually...) */
    entry->delta = 1 * cronDAYS;
  } else {
    entry->delta
      = entry->delta * 2 + weak_randomi((desperation+1)*cronSECONDS);
    if (entry->delta > 4 * cronHOURS)
      entry->delta = 4 *  weak_randomi(cronHOURS * (desperation+1));
  }
  cronTime(&entry->until);
  entry->until += entry->delta;
  entry->strict = strict;
  hash2enc(&identity->hashPubKey,
	   &hn);
#if DEBUG_IDENTITY
  LOG(LOG_INFO,
      "Blacklisting host `%s' for %llu seconds"
      " until %llu (strict=%d).\n",
      &hn,
      entry->delta / cronSECONDS,
      entry->until,
      strict);
#endif
  MUTEX_UNLOCK(&lock_);
  return OK;
}

/**
 * Is the host currently 'strictly' blacklisted (i.e. we refuse to talk)?
 *
 * @param identity host to check
 * @return YES if true, else NO
 */
static int isBlacklistedStrict(const PeerIdentity * identity) {
  cron_t now;
  HostEntry * entry;

  GNUNET_ASSERT(numberOfHosts_ <= sizeOfHosts_);
  MUTEX_LOCK(&lock_);
  entry = findHost(identity);
  if (entry == NULL) {
    MUTEX_UNLOCK(&lock_);
    return NO;
  }
  cronTime(&now);			
  if ( (now < entry->until) &&
       (entry->strict == YES) ) {
    MUTEX_UNLOCK(&lock_);
    return YES;
  } else {
    MUTEX_UNLOCK(&lock_);
    return NO;
  }
}

/**
 * Whitelist a host. This method is called if a host
 * successfully established a connection. It typically
 * resets the exponential backoff to the smallest value.
 * @return OK on success SYSERR on error
 */
static int whitelistHost(const PeerIdentity * identity) {
  HostEntry * entry;
  int i;
#if DEBUG_IDENTITY
  EncName enc;
#endif

  GNUNET_ASSERT(numberOfHosts_ <= sizeOfHosts_);
  MUTEX_LOCK(&lock_);
  entry = findHost(identity);
  if (entry == NULL) {
    for (i=0;i<MAX_TEMP_HOSTS;i++) {
      if (hostIdentityEquals(identity,
			     &tempHosts[i].identity)) {
	entry = &tempHosts[i];
	break;
      }
    }
  }
  if (entry == NULL) {
    MUTEX_UNLOCK(&lock_);
    return SYSERR;
  }
#if DEBUG_IDENTITY
  IFLOG(LOG_INFO,
	hash2enc(&identity->hashPubKey,
		 &enc));
  LOG(LOG_INFO,
      "Whitelisting host `%s'\n",
      &enc);
#endif
  entry->delta = 30 * cronSECONDS;
  entry->until = 0;
  entry->strict = NO;
  MUTEX_UNLOCK(&lock_);
  return OK;
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
static int forEachHost(cron_t now,
		       HostIterator callback,
		       void * data) {
  int i;
  int j;
  int count;
  PeerIdentity hi;
  unsigned short proto;
  HostEntry * entry;

  GNUNET_ASSERT(numberOfHosts_ <= sizeOfHosts_);
  count = 0;
  MUTEX_LOCK(&lock_);
  for (i=0;i<numberOfHosts_;i++) {
    entry = hosts_[i];
    if (hostIdentityEquals(&entry->identity,
			   &myIdentity))
      continue;
    if ( (now == 0) ||
	 (now >= entry->until) ) {
      count++;
      if (callback != NULL) {
	hi = entry->identity;
	for (j=0;j<entry->protocolCount;j++) {
	  proto = entry->protocols[j];
	  MUTEX_UNLOCK(&lock_);
	  callback(&hi,
		   proto,
		   YES,
		   data);
	  MUTEX_LOCK(&lock_);
	  /* we gave up the lock,
	     need to re-aquire entry (if possible)! */
	  if (i >= numberOfHosts_)
	    break;
	  entry = hosts_[i];
	  if (hostIdentityEquals(&entry->identity,
				 &myIdentity))
	    break;
	}
      }
    }
  }
  for (i=0;i<MAX_TEMP_HOSTS;i++) {
    entry = &tempHosts[i];
    if (entry->heloCount == 0)
      continue;
    if ( (now == 0) ||
	 (now >= entry->until) ) {
      count++;
      if (callback != NULL) {
	hi = entry->identity;
	proto = entry->protocols[0];
	MUTEX_UNLOCK(&lock_);
	callback(&hi,
		 proto,
		 YES,
		 data);
	MUTEX_LOCK(&lock_);
      }
    }
  }
  MUTEX_UNLOCK(&lock_);
  return count;
}

/**
 * Write host-trust information to a file - flush the buffer entry!
 * Assumes synchronized access.
 */
static void flushHostCredit(HostEntry * host) {
  EncName fil;
  char * fn;
  unsigned int trust;

  if ((host->trust & TRUST_REFRESH_MASK) == 0)
    return; /* unchanged */
  host->trust = host->trust & TRUST_ACTUAL_MASK;
  hash2enc(&host->identity.hashPubKey,
	   &fil);
  fn = MALLOC(strlen(trustDirectory)+sizeof(EncName)+1);
  strcpy(fn, trustDirectory);
  strcat(fn, (char*) &fil);
  if (host->trust == 0) {
    if (0 != UNLINK(fn)) {
      if (errno != ENOENT)
	LOG(LOG_INFO,
	    "`%s' of file `%s' at %s:%d failed: %s\n",
	    "unlink",
	    fn,
	    __FILE__, __LINE__,
	    STRERROR(errno));
    }
  } else {
    trust = htonl(host->trust);
    writeFile(fn,
	      &trust,
	      sizeof(unsigned int),
	      "644");
  }
  FREE(fn);
}

/**
 * Call once in a while to synchronize trust values with the disk.
 */
static void cronFlushTrustBuffer(void * unused) {
  int i;
  MUTEX_LOCK(&lock_);
  for (i=0;i<numberOfHosts_;i++)
    flushHostCredit(hosts_[i]);
  MUTEX_UNLOCK(&lock_);
}

/**
 * Obtain identity from publicPrivateKey.
 * @param pubKey the public key of the host
 * @param result address where to write the identity of the node
 */
static void getPeerIdentity(const PublicKey * pubKey,
			    PeerIdentity * result) {
  if (pubKey == NULL) {
    memset(&result,
	   0,
	   sizeof(PeerIdentity));
  } else {
    hash(pubKey,
	 sizeof(PublicKey),
	 &result->hashPubKey);
  }
}


/**
 * Provide the Identity service.
 *
 * @param capi the core API
 * @return NULL on errors, ID_API otherwise
 */
Identity_ServiceAPI *
provide_module_identity(CoreAPIForApplication * capi) {
  static Identity_ServiceAPI id;
  char * gnHome;
  char * tmp;
  int i;

  id.getPublicPrivateKey = &getPublicPrivateKey;
  id.getPeerIdentity     = &getPeerIdentity;
  id.signData            = &signData;
  id.decryptData         = &decryptData;
  id.delHostFromKnown    = &delHostFromKnown;
  id.addHostTemporarily  = &addHostTemporarily;
  id.addHost             = &bindAddress;
  id.forEachHost         = &forEachHost;
  id.identity2Helo       = &identity2Helo;
  id.verifyPeerSignature = &verifyPeerSignature;
  id.blacklistHost       = &blacklistHost;
  id.isBlacklistedStrict = &isBlacklistedStrict;
  id.whitelistHost       = &whitelistHost;
  id.changeHostTrust     = &changeHostTrust;
  id.getHostTrust        = &getHostTrust;

  for (i=0;i<MAX_TEMP_HOSTS;i++)
    memset(&tempHosts[i],
	   0,
	   sizeof(HostEntry));
  numberOfHosts_ = 0;

  initPrivateKey();
  getPeerIdentity(getPublicPrivateKey(),
		  &myIdentity);

  MUTEX_CREATE_RECURSIVE(&lock_);
  gnHome = getFileName("GNUNETD",
		       "GNUNETD_HOME",
		       _("Configuration file must specify a "
			 "directory for GNUnet to store "
			 "per-peer data under %s%s\n"));
  networkIdDirectory
    = getConfigurationString("GNUNETD",
			     "HOSTS");
  if (networkIdDirectory == NULL) {
    networkIdDirectory
      = MALLOC(strlen(gnHome) + strlen(HOST_DIR) + 2);
    strcpy(networkIdDirectory, gnHome);
    strcat(networkIdDirectory, DIR_SEPARATOR_STR);
    strcat(networkIdDirectory, HOST_DIR);
  } else {
    tmp =
      expandFileName(networkIdDirectory);
    FREE(networkIdDirectory);
    networkIdDirectory = tmp;
  }
  mkdirp(networkIdDirectory);
  trustDirectory = MALLOC(strlen(gnHome) +
			  strlen(TRUSTDIR)+2);
  strcpy(trustDirectory, gnHome);
  strcat(trustDirectory, DIR_SEPARATOR_STR);
  strcat(trustDirectory, TRUSTDIR);
  mkdirp(trustDirectory);
  FREE(gnHome);

  cronScanDirectoryDataHosts(NULL);
  addCronJob(&cronScanDirectoryDataHosts,
	     CRON_DATA_HOST_FREQ,
	     CRON_DATA_HOST_FREQ,
	     NULL);
  addCronJob(&cronFlushTrustBuffer,
	     CRON_TRUST_FLUSH_FREQ,
	     CRON_TRUST_FLUSH_FREQ,
	     NULL);
  return &id;
}

/**
 * Shutdown Identity service.
 */
void release_module_identity() {
  int i;
  int j;
  HostEntry * entry;

  for (i=0;i<MAX_TEMP_HOSTS;i++) {
    entry = &tempHosts[i];
    for (j=0;j<entry->heloCount;j++)
      FREE(entry->helos[j]);
    GROW(entry->helos,
	 entry->heloCount,
	 0);
    GROW(entry->protocols,
	 entry->protocolCount,
	 0);
  }
  delCronJob(&cronScanDirectoryDataHosts,
	     CRON_DATA_HOST_FREQ,
	     NULL);
  delCronJob(&cronFlushTrustBuffer,
	     CRON_TRUST_FLUSH_FREQ,
	     NULL);
  cronFlushTrustBuffer(NULL);
  MUTEX_DESTROY(&lock_);
  for (i=0;i<numberOfHosts_;i++) {
    entry = hosts_[i];
    for (j=0;j<entry->heloCount;j++)
      FREE(entry->helos[j]);
    GROW(entry->helos,
	 entry->heloCount,
	 0);
    GROW(entry->protocols,
	 entry->protocolCount,
	 0);
    FREE(entry);
  }
  GROW(hosts_,
       sizeOfHosts_,
       0);
  numberOfHosts_ = 0;

  FREE(networkIdDirectory);
  networkIdDirectory = NULL;
  FREE(trustDirectory);
  trustDirectory = NULL;
  donePrivateKey();
}

/* end of identity.c */
