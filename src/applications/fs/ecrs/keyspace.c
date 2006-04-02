/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/upload.c
 * @brief publish a URI in the keyword space
 * @see http://gnunet.org/encoding.php3
 * @author Krista Bennett
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_fs_lib.h"
#include "gnunet_protocols.h"
#include "ecrs.h"

#define DEBUG_KEYSPACE NO

/**
 * What is the maximum size that we allow for a kblock
 * before we start dropping meta-data?
 */
#define MAX_KBLOCK_SIZE 32000

#if EXTRA_CHECKS

/**
 * Process replies received in response to our
 * queries.  Verifies, decrypts and passes valid
 * replies to the callback.
 *
 * @return SYSERR if the entry is malformed
 */
static int verifyKBlock(const HashCode512 * key,
			Datastore_Value * value) {
  unsigned int type;
  ECRS_FileInfo fi;
  unsigned int size;
  HashCode512 query;
  KBlock * kb;
  const char * dstURI;
  EncName enc;
  int j;

  type = ntohl(value->type);
  size = ntohl(value->size) - sizeof(Datastore_Value);
  if (OK != getQueryFor(size,
			(DBlock*) &value[1],
			&query))
    return SYSERR;
  GNUNET_ASSERT(type == K_BLOCK);

  if (size < sizeof(KBlock))
    return SYSERR;
  kb = (KBlock*) &value[1];
  IFLOG(LOG_DEBUG,
	hash2enc(key,
		 &enc));
  ECRS_decryptInPlace(key,
		      &kb[1],
		      size - sizeof(KBlock));
  j = sizeof(KBlock);
  while ( (j < size) &&
	  (((const char*)kb)[j] != '\0') )
    j++;
  if (j == size) {
    BREAK(); /* kblock malformed */
    return SYSERR;
  }
  dstURI = (const char*) &kb[1];
  j++;
  fi.meta = ECRS_deserializeMetaData(&((const char*)kb)[j],
				     size - j);
  if (fi.meta == NULL) {
    BREAK(); /* kblock malformed */
    return SYSERR;
  }
  fi.uri = ECRS_stringToUri(dstURI);
  if (fi.uri == NULL) {
    BREAK(); /* kblock malformed */
    ECRS_freeMetaData(fi.meta);
    return SYSERR;
  }
  ECRS_freeUri(fi.uri);
  ECRS_freeMetaData(fi.meta);
  return OK;
}

#endif


/**
 * Add an entry into the K-space (keyword space).
 *
 * @param uri what is the URI under which the entry
 *        should be published (must be a keyword URI)
 * @param dst to which URI should the entry refer?
 * @param md what meta-data should be associated with the
 *        entry?
 */
int ECRS_addToKeyspace(const struct ECRS_URI * uri,
		       unsigned int anonymityLevel,
		       unsigned int priority,
		       cron_t expirationTime,
		       const struct ECRS_URI * dst,
		       const struct ECRS_MetaData * md) {
  GNUNET_TCP_SOCKET * sock;
  Datastore_Value * value;
  int ret;
  unsigned int size;
  unsigned int mdsize;
  struct PrivateKey * pk;
  HashCode512 hc;
  char * dstURI;
  KBlock * kb;
  char ** keywords;
  unsigned int keywordCount;
  int i;
#if DEBUG_KEYSPACE
  EncName enc;
#endif
  HashCode512 key;
  char * cpy; /* copy of the encrypted portion */
  struct ECRS_URI * xuri;

  if (! ECRS_isKeywordUri(uri)) {
    BREAK();
    return SYSERR;
  }

  mdsize = ECRS_sizeofMetaData(md,
			       ECRS_SERIALIZE_PART);
  dstURI = ECRS_uriToString(dst);
  size = mdsize + sizeof(KBlock) + strlen(dstURI) + 1;
  if (size > MAX_KBLOCK_SIZE) {
    size = MAX_KBLOCK_SIZE;
    value = MALLOC(sizeof(Datastore_Value) +
		   size);
    kb = (KBlock*) &value[1];
    kb->type = htonl(K_BLOCK);
    memcpy(&kb[1],
	   dstURI,
	   strlen(dstURI)+1);
    mdsize = size - sizeof(KBlock) - strlen(dstURI) - 1;
    mdsize = ECRS_serializeMetaData(md,
				    &((char*)&kb[1])[strlen(dstURI)+1],
				    mdsize,
				    ECRS_SERIALIZE_PART);
    if (mdsize == -1) {
      BREAK();
      FREE(dstURI);
      return SYSERR;
    }
    size = sizeof(KBlock) + strlen(dstURI) + 1 + mdsize;
  } else {
    value = MALLOC(sizeof(Datastore_Value) +
		   size);
    kb = (KBlock*) &value[1];
    kb->type = htonl(K_BLOCK);
    memcpy(&kb[1],
	   dstURI,
	   strlen(dstURI)+1);
    GNUNET_ASSERT(mdsize ==
		  ECRS_serializeMetaData(md,
					 &((char*)&kb[1])[strlen(dstURI)+1],
					 mdsize,
					 ECRS_SERIALIZE_FULL));
  }
  value->size = htonl(sizeof(Datastore_Value) + size);
  value->type = htonl(K_BLOCK);
  value->prio = htonl(priority);
  value->anonymityLevel = htonl(anonymityLevel);
  value->expirationTime = htonll(expirationTime);
  sock = getClientSocket();
  ret = OK;

  if (testConfigurationString("FS",
			      "DISABLE-CREATION-TIME",
			      "YES"))
    xuri = ECRS_dupUri(uri);
  else
    xuri = ECRS_dateExpandKeywordUri(uri);
  keywords = xuri->data.ksk.keywords;
  keywordCount = xuri->data.ksk.keywordCount;
  cpy = MALLOC(mdsize + strlen(dstURI) + 1);
  memcpy(cpy,
	 &kb[1],
	 mdsize + strlen(dstURI) + 1);
  for (i=0;i<keywordCount;i++) {
    memcpy(&kb[1], cpy, mdsize + strlen(dstURI) + 1);
    hash(keywords[i],
	 strlen(keywords[i]),
	 &key);
#if DEBUG_KEYSPACE
    IFLOG(LOG_DEBUG,
	  hash2enc(&key,
		   &enc));
    LOG(LOG_DEBUG,
	"Encrypting KBlock with key %s.\n",
	&enc);
#endif
    ECRS_encryptInPlace(&key,
			&kb[1],
			mdsize + strlen(dstURI) + 1);
    pk = makeKblockKey(&key);
    getPublicKey(pk,
		 &kb->keyspace);
    GNUNET_ASSERT(OK == sign(pk,
			     mdsize + strlen(dstURI) + 1,
			     &kb[1],
			     &kb->signature));
#if EXTRA_CHECKS
    /* extra check: verify sig */
    GNUNET_ASSERT(OK == getQueryFor(size,
				    (DBlock*) kb,
				    &hc));
#endif
    freePrivateKey(pk);
    if (OK != FS_insert(sock, value))
      ret = SYSERR;
#if EXTRA_CHECKS
    GNUNET_ASSERT(OK == verifyKBlock(&key, value))
#endif
  }
  ECRS_freeUri(xuri);
  FREE(cpy);
  FREE(dstURI);
  releaseClientSocket(sock);
  FREE(value);
  return ret;
}

/* end of keyspace.c */
