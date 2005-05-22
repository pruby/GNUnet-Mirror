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
 * @file identity/identity.c
 * @brief maintains list of known peers
 *
 * Code to maintain the list of currently known hosts (in memory
 * structure of data/hosts) and (temporary) blacklisting information
 * and a list of HELOs that are temporary unless confirmed via PONG
 * (used to give the transport module the required information for the
 * PING).
 *
 * Todo:
 * - we may want to cache more HELOs in memory
 * - make sure that the first trust value in hosts_
 *   for each host is the one holding the trust
 *   value and that this one is always used
 *   consistently!
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

/**
 * Masks to keep track when the trust has changed and
 * to get the real trust value.
 */
#define TRUST_REFRESH_MASK 0x80000000

#define TRUST_ACTUAL_MASK  0x7FFFFFFF


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
   * for which protocol is this host known?
   */
  unsigned short protocol;
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
static HostEntry * hosts_ = NULL;

/**
 * The current (allocated) size of knownHosts
 */
static int max_ = 0;

/**
 * The number of actual entries in knownHosts
 */
static int count_;

/**
 * A lock for accessing knownHosts
 */
static Mutex lock_;

/**
 * Directory where the HELOs are stored in (data/hosts)
 */
static char * networkIdDirectory;

/**
 * Where do we store trust information?
 */
static char * trustDirectory;

/**
 * The list of temporarily known hosts
 */
static HELO_Message * tempHosts[MAX_TEMP_HOSTS];

/**
 * tempHosts is a ringbuffer, this is the current
 * index into it.
 */
static int tempHostsNextSlot;

static PeerIdentity myIdentity;

/**
 * Get the filename under which we would store the HELO_Message
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
static HostEntry * findHost(const PeerIdentity * id,
			    unsigned short proto) {
  int i;

  for (i=0;i<count_;i++)
    if ( (hostIdentityEquals(id,
			     &hosts_[i].identity)) &&
	 ( (proto == ANY_PROTOCOL_NUMBER) ||
	   (proto == hosts_[i].protocol) ) ) {
      return &hosts_[i];
    }
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
  EncName fil;
  char * fn;
  unsigned int trust;

  MUTEX_LOCK(&lock_);
  if (NULL != findHost(identity, protocol)) {
    MUTEX_UNLOCK(&lock_);
    return; /* already there */
  }
  if (count_ == max_)
    GROW(hosts_,
	 max_,
	 max_+32);
  hosts_[count_].identity = *identity;
  hosts_[count_].until    = 0;
  hosts_[count_].delta    = 30 * cronSECONDS;
  hosts_[count_].protocol = protocol;
  hosts_[count_].strict   = NO;
  hash2enc(&identity->hashPubKey,
	   &fil);
  fn = MALLOC(strlen((char*)trustDirectory)+sizeof(EncName)+1);
  buildFileName(trustDirectory, &fil, fn);
  if (sizeof(unsigned int) ==
      readFile(fn,
	       sizeof(unsigned int),
	       &trust)) {
    hosts_[count_].trust = ntohl(trust);
  } else {
    hosts_[count_].trust = 0;
  }
  FREE(fn);
  count_++;
  MUTEX_UNLOCK(&lock_);
}

/**
 * Increase the host credit by a value.
 *
 * @param hostId is the identity of the host
 * @param value is the int value by which the host credit is to be increased or
 *        decreased
 * @returns the actual change in trust (positive or negative)
 */
static int changeHostTrust(const PeerIdentity * hostId,
			   int value){
  HostEntry * host;

  if (value == 0)
    return 0;

  MUTEX_LOCK(&lock_);
  host = findHost(hostId, ANY_PROTOCOL_NUMBER);
  if (host == NULL) {
    BREAK();
    MUTEX_UNLOCK(&lock_);
    return 0;
  }
  if ( ((int) (host->trust & TRUST_ACTUAL_MASK)) + value < 0) {
    value = - (host->trust & TRUST_ACTUAL_MASK);
    host->trust = 0 | TRUST_REFRESH_MASK; /* 0 remaining */
  } else {
    host->trust = ( (host->trust & TRUST_ACTUAL_MASK) + value) | TRUST_REFRESH_MASK;
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
  host = findHost(hostId, ANY_PROTOCOL_NUMBER);
  if (host == NULL)
    trust = 0;
  else
    trust = host->trust & TRUST_ACTUAL_MASK;
  MUTEX_UNLOCK(&lock_);
  return trust;
}


static void cronHelper(const char * filename,
		       const char * dirname,
		       void * unused) {
  PeerIdentity identity;
  EncName id;
  unsigned int protoNumber;
  char * fullname;

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
      return;
    }
  }

  fullname = MALLOC(strlen(filename) + strlen(networkIdDirectory) + 1);
  strcpy(fullname, networkIdDirectory);
  strcat(fullname, filename);
  if (0 == UNLINK(fullname))
    LOG(LOG_WARNING,
	_("File '%s' in directory '%s' does not match naming convention. Removed.\n"),
	filename,
	networkIdDirectory);
  else
    LOG_FILE_STRERROR(LOG_ERROR, "unlink", fullname);
  FREE(fullname);
}

/**
 * Call this method periodically to scan data/hosts for new hosts.
 */
static void cronScanDirectoryDataHosts(void * unused) {
  static int retries;
  int count;

  count = scanDirectory(networkIdDirectory,
			&cronHelper,
			NULL);
  if (count <= 0) {
    retries++;
    if (retries > 32) {
      LOG(LOG_WARNING,
	  _("%s '%s' returned no known hosts!\n"),
	  "scanDirectory",
	  networkIdDirectory);
    }
  }
}

/**
 * Add a host to the temporary list.
 */
static void addHostTemporarily(const HELO_Message * tmp) {
  HELO_Message * msg;

  msg = MALLOC(HELO_Message_size(tmp));
  memcpy(msg, tmp, HELO_Message_size(tmp));
  MUTEX_LOCK(&lock_);
  FREENONNULL(tempHosts[tempHostsNextSlot]);
  tempHosts[tempHostsNextSlot++] = msg;
  if (tempHostsNextSlot >= MAX_TEMP_HOSTS)
    tempHostsNextSlot = 0;
  MUTEX_UNLOCK(&lock_);
}

/**
 * Delete a host from the list.
 */
static void delHostFromKnown(const PeerIdentity * identity,
			     const unsigned short protocol) {
  char * fn;
  int i;

  MUTEX_LOCK(&lock_);
  for (i=0;i<count_;i++)
    if ( (hostIdentityEquals(identity,
			     &hosts_[i].identity)) &&
	 (protocol == hosts_[i].protocol) ) {
      hosts_[i] = hosts_[count_-1];
      count_--;
      /* now remove the file */
      fn = getHostFileName(identity, protocol);
      if (0 != UNLINK(fn))
	LOG_FILE_STRERROR(LOG_WARNING, "unlink", fn);
      FREE(fn);
      MUTEX_UNLOCK(&lock_);
      return; /* deleted */
    }
  MUTEX_UNLOCK(&lock_);
}

/**
 * Bind a host address (helo) to a hostId.
 * @param msg the verified (!) HELO message
 */
static void bindAddress(const HELO_Message * msg) {
  char * fn;
  char * buffer;
  HELO_Message * oldMsg;
  int size;
  EncName enc;

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
  oldMsg = (HELO_Message*) buffer;
  if ((unsigned int)size == HELO_Message_size(oldMsg)) {
    if (ntohl(oldMsg->expirationTime) > ntohl(msg->expirationTime)) {
      FREE(fn);
      FREE(buffer);
      return; /* have more recent HELO in stock */
    }
  }
  writeFile(fn,
	    msg,
	    HELO_Message_size(msg),
	    "644");
  FREE(fn);
  FREE(buffer);
  addHostToKnown(&msg->senderIdentity,
		 ntohs(msg->protocol));
}

struct TempStorage_ {
  EncName enc;
  HELO_Message * helo;
  int result;
};

/**
 * Check if the filename matches the identity that we are searching
 * for. If yes, fill it in.
 */
static void identity2HeloHelper(const char * fn,
				const char * dirName,
				struct TempStorage_ * res) {
  if (strstr(fn, (char*)&res->enc) != NULL) {
    char * fileName;
    HELO_Message buffer;
    int size;
    size_t n;

    n = strlen(networkIdDirectory) + strlen(fn) + 1;
    fileName = MALLOC(n);
    SNPRINTF(fileName,
	     n,
	     "%s%s",
	     networkIdDirectory,
	     fn);
    size = readFile(fileName,
		    sizeof(HELO_Message),
		    &buffer);
    if (size == sizeof(HELO_Message)) {
      HELO_Message * tmp;
      tmp = MALLOC(HELO_Message_size(&buffer));
      size = readFile(fileName,
		      HELO_Message_size(&buffer),
		      tmp);
      if ((unsigned int)size != HELO_Message_size(&buffer)) {
	if (0 == UNLINK(fileName))	
	  LOG(LOG_WARNING,
	      _("Removed file '%s' containing invalid peer advertisement.\n"),
	      fileName);
	else
	  LOG_FILE_STRERROR(LOG_ERROR, "unlink", fileName);
	FREE(tmp);
      } else {
	if (res->result == SYSERR) {
	  res->result = OK;
	  res->helo = tmp;
	} else {
	  if (randomi(4) > 2) {
	    FREE(res->helo);
	    res->helo = tmp;
	  } else {
	    FREE(tmp);
	  }
	}
      }
    } else {
      if (0 == UNLINK(fileName)) {
	LOG(LOG_WARNING,
	    _("Removed file '%s' containing invalid peer advertisement.\n"),
	    fileName);
      } else {
	LOG_FILE_STRERROR(LOG_ERROR, "unlink", fileName);
      }
    }
    FREE(fileName);
  }
}

/**
 * Obtain the public key and address of a known host.  If no specific
 * protocol is specified (ANY_PROTOCOL_NUMBER), HELOs for cheaper
 * protocols are returned with preference (randomness!).
 *
 * @param hostId the host id
 * @param protocol the protocol that we need,
 *        ANY_PROTOCOL_NUMBER if we do not care which protocol
 * @param tryTemporaryList is it ok to check the unverified HELOs?
 * @param result where to store the result
 * @returns SYSERR on failure, OK on success
 */
static int identity2Helo(const PeerIdentity *  hostId,
			 const unsigned short protocol,
			 int tryTemporaryList,
			 HELO_Message ** result) {
  struct TempStorage_ tempStorage;
  char * fn;
  HELO_Message buffer;
  int size;
  int i;

  *result = NULL;
  fn = getHostFileName(hostId, protocol);
  size = readFile(fn,
		  sizeof(HELO_Message),
		  &buffer);
  if (size == sizeof(HELO_Message)) {
    *result = MALLOC(HELO_Message_size(&buffer));
    size = readFile(fn,
		    HELO_Message_size(&buffer),
		    *result);
    if ((unsigned int)size != HELO_Message_size(&buffer)) {
      if (0 == UNLINK(fn))
	LOG(LOG_WARNING,
	    _("Removed file '%s' containing invalid HELO data.\n"),
	    fn);
      else
	LOG_FILE_STRERROR(LOG_ERROR, "unlink", fn);
      FREE(fn);
      FREE(*result);
      *result = NULL;
      return SYSERR;
    }
    FREE(fn);
    return OK;
  } else if (size != -1) {
    if (0 == UNLINK(fn))
      LOG(LOG_WARNING,
	  _("Removed invalid HELO file '%s'\n"),
	  fn);
    else
      LOG_FILE_STRERROR(LOG_ERROR, "unlink", fn);
  }
  FREE(fn);

  if (YES == tryTemporaryList) {
    /* ok, then try temporary hosts */
    MUTEX_LOCK(&lock_);
    for (i=0;i<MAX_TEMP_HOSTS;i++) {
      if ( (tempHosts[i] != NULL) &&
	   hostIdentityEquals(hostId,
			      &tempHosts[i]->senderIdentity) &&
	   ( (ntohs(tempHosts[i]->protocol) == protocol) ||
	     (protocol == ANY_PROTOCOL_NUMBER) ) ) {
	*result = MALLOC(HELO_Message_size(tempHosts[i]));
	memcpy(*result,
	       tempHosts[i],
	       HELO_Message_size(tempHosts[i]));	
	MUTEX_UNLOCK(&lock_);
	return OK;
      }
    }
    MUTEX_UNLOCK(&lock_);
  }
  if (protocol != ANY_PROTOCOL_NUMBER)
    return SYSERR; /* nothing found */
  /* ok, last chance, scan directory! */
  hash2enc(&hostId->hashPubKey,
	   &tempStorage.enc);

  tempStorage.result = SYSERR;
  tempStorage.helo = NULL;
#if DEBUG_IDENTITY
  LOG(LOG_DEBUG,
      "scanning directory %s for peer identity, proto %d\n",
      networkIdDirectory,
      protocol);
#endif
  scanDirectory(networkIdDirectory,
		(DirectoryEntryCallback)&identity2HeloHelper,
		&tempStorage);
  *result = tempStorage.helo;
  return tempStorage.result;
}


/**
 * @param signer the identity of the host that presumably signed the message
 * @param message the signed message
 * @param size the size of the message
 * @param sig the signature
 * @return OK on success, SYSERR on error (verification failed)
 */
static int verifyPeerSignature(const PeerIdentity * signer,
			       const void * message,
			       int size,
			       const Signature * sig) {
  HELO_Message * helo;
  int res;

  if (SYSERR == identity2Helo(signer,
			      ANY_PROTOCOL_NUMBER,
			      YES,
			      &helo))
    return SYSERR;
  res = verifySig(message, size, sig,
		  &helo->publicKey);
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
			 int desperation,
			 int strict) {
  int i;
  EncName hn;
  int ret;

  if (desperation < 0)
    desperation = 0;
  ret = SYSERR;
  MUTEX_LOCK(&lock_);
  for (i=0;i<count_;i++) {
    if (hostIdentityEquals(identity,
			   &hosts_[i].identity)) {
      if (strict == YES) {
	/* Presumably runs a broken version of GNUnet;
	   blacklist for 1 day (we hope the other peer
	   updates the software eventually...) */
	hosts_[i].delta = 1 * cronDAYS;
      } else {
	hosts_[i].delta
	  = hosts_[i].delta * 2 + randomi((desperation+1)*cronSECONDS);
	if (hosts_[i].delta > 4 * cronHOURS)
	  hosts_[i].delta = 4 *  cronHOURS+randomi(desperation+1);
      }
      cronTime(&hosts_[i].until);
      hosts_[i].until += hosts_[i].delta;
      hosts_[i].strict = strict;
      hash2enc(&identity->hashPubKey,
	       &hn);
#if DEBUG_IDENTITY
      LOG(LOG_INFO,
	  "Blacklisting host '%s' (%d) for %llu seconds until %llu (strict=%d).\n",
	  &hn,
	  i,
	  hosts_[i].delta / cronSECONDS,
	  hosts_[i].until,
	  strict);
#endif
      ret = OK;
    }
  }
  MUTEX_UNLOCK(&lock_);
  return ret;
}

/**
 * Is the host currently 'strictly' blacklisted (i.e. we refuse to talk)?
 *
 * @param identity host to check
 * @return YES if true, else NO
 */
static int isBlacklistedStrict(const PeerIdentity * identity) {
  int i;
  cron_t now;

  MUTEX_LOCK(&lock_);
  for (i=0;i<count_;i++) {
    if (hostIdentityEquals(identity,
			   &hosts_[i].identity)) {
      cronTime(&now);			
      if ( (now < hosts_[i].until) && (hosts_[i].strict == YES) ) {
        MUTEX_UNLOCK(&lock_);
        return YES;
      } else {
        MUTEX_UNLOCK(&lock_);
        return NO;
      }
    }
  }
  MUTEX_UNLOCK(&lock_);
  return NO;
}

/**
 * Whitelist a host. This method is called if a host
 * successfully established a connection. It typically
 * resets the exponential backoff to the smallest value.
 * @return OK on success SYSERR on error
 */
static int whitelistHost(const PeerIdentity * identity) {
  int i;

  MUTEX_LOCK(&lock_);
  for (i=0;i<count_;i++) {
    if (hostIdentityEquals(identity,
			   &hosts_[i].identity)) {
      hosts_[i].delta = 30 * cronSECONDS;
      hosts_[i].until = 0;
      hosts_[i].strict = NO;
      MUTEX_UNLOCK(&lock_);
      return OK;
    }
  }
  MUTEX_UNLOCK(&lock_);
  return SYSERR;
}

/**
 * Call a method for each known host.
 *
 * @param callback the method to call for each host
 * @param now the time to use for excluding hosts due to blacklisting, use 0
 *        to go through all hosts.
 * @param data an argument to pass to the method
 * @return the number of hosts matching
 */
static int forEachHost(cron_t now,
		       HostIterator callback,
		       void * data) {
  int i;
  int count = 0;

  MUTEX_LOCK(&lock_);
  for (i=0;i<count_;i++) {
    if (hostIdentityEquals(&hosts_[i].identity,
			   &myIdentity))
      continue;
    if ( (now == 0) ||
	 (now >= hosts_[i].until) ) {
      count++;
      if (callback != NULL) {
	PeerIdentity hi;
	unsigned short proto;

	hi = hosts_[i].identity;
	proto = hosts_[i].protocol;
	MUTEX_UNLOCK(&lock_);
	callback(&hi,
		 proto,
		 YES,
		 data);
	MUTEX_LOCK(&lock_);
      }
    }
  }
  /* FIXME: also iterate over temporary list */
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
  fn = MALLOC(strlen((char*)trustDirectory)+sizeof(EncName)+1);
  buildFileName(trustDirectory,
		&fil,
		fn);
  if (host->trust == 0) {
    if (0 != UNLINK(fn)) {
      if (errno != ENOENT)
	LOG(LOG_INFO,
	    "'%s' of file '%s' at %s:%d failed: %s\n",
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
  for (i=0;i<count_;i++)
    flushHostCredit(&hosts_[i]);
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
Identity_ServiceAPI * provide_module_identity(CoreAPIForApplication * capi) {
  static Identity_ServiceAPI id;
  char * gnHome;
  int i;

  id.getPublicPrivateKey = &getPublicPrivateKey;
  id.getPeerIdentity = &getPeerIdentity;
  id.signData = &signData;
  id.decryptData = &decryptData;
  id.delHostFromKnown = &delHostFromKnown;
  id.addHostTemporarily = &addHostTemporarily;
  id.addHost = &bindAddress;
  id.forEachHost = &forEachHost;
  id.identity2Helo = &identity2Helo;
  id.verifyPeerSignature = &verifyPeerSignature;
  id.blacklistHost = &blacklistHost;
  id.isBlacklistedStrict = &isBlacklistedStrict;
  id.whitelistHost = &whitelistHost;
  id.changeHostTrust = &changeHostTrust;
  id.getHostTrust = &getHostTrust;

  for (i=0;i<MAX_TEMP_HOSTS;i++)
    tempHosts[i] = NULL;
  tempHostsNextSlot = 0;
  count_ = 0;

  initPrivateKey();
  getPeerIdentity(getPublicPrivateKey(),
		  &myIdentity);

  MUTEX_CREATE_RECURSIVE(&lock_);
  networkIdDirectory = getFileName("GNUNETD",
				   "HOSTS",
				   _("Configuration file must specify directory for "
				     "network identities in section %s under %s.\n"));
  mkdirp(networkIdDirectory);
  gnHome = getFileName("",
		       "GNUNETD_HOME",
		       _("Configuration file must specify a "
			 "directory for GNUnet to store "
			 "per-peer data under %s%s\n"));
  trustDirectory = MALLOC(strlen(gnHome) +
			  strlen(TRUSTDIR)+2);
  strcpy(trustDirectory, gnHome);
  strcat(trustDirectory, "/");
  strcat(trustDirectory, TRUSTDIR);
  mkdirp(trustDirectory);
  FREE(gnHome);

  cronScanDirectoryDataHosts(NULL);
  addCronJob(&cronScanDirectoryDataHosts,
	     15 * cronMINUTES,
	     15 * cronMINUTES,
	     NULL);
  addCronJob(&cronFlushTrustBuffer,
	     5 * cronMINUTES,
	     5 * cronMINUTES,
	     NULL);
  return &id;
}

/**
 * Shutdown Identity service.
 */
void release_module_identity() {
  int i;

  delCronJob(&cronScanDirectoryDataHosts,
	     15 * cronMINUTES,
	     NULL);
  delCronJob(&cronFlushTrustBuffer,
	     5 * cronMINUTES,
	     NULL);
  cronFlushTrustBuffer(NULL);
  for (i=0;i<MAX_TEMP_HOSTS;i++)
    FREENONNULL(tempHosts[i]);
  MUTEX_DESTROY(&lock_);
  GROW(hosts_,
       max_,
       0);
  count_ = 0;

  FREE(networkIdDirectory);
  networkIdDirectory = NULL;
  FREE(trustDirectory);
  trustDirectory = NULL;
  donePrivateKey();
}

/* end of identity.c */
