/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @see http://www.ovmj.org/GNUnet/encoding.php3
 * @author Krista Bennett
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_fs_lib.h"
#include "gnunet_protocols.h"
#include "ecrs.h"

/**
 * What is the maximum size that we allow for a kblock
 * before we start dropping meta-data?
 */
#define MAX_KBLOCK_SIZE 32000


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
  PrivateKey pk;
  HashCode160 hc;
  char * dstURI;
  KBlock * kb;
  char ** keywords;
  unsigned int keywordCount;
  int i;

  if (! ECRS_isKeywordURI(uri)) {
    BREAK();
    return SYSERR;
  }

  mdsize = ECRS_sizeofMetaData(md);
  dstURI = ECRS_uriToString(dst);
  size = mdsize + sizeof(KBlock) + strlen(dstURI) + 1;
  if (size > MAX_KBLOCK_SIZE) {
    size = MAX_KBLOCK_SIZE;
    value = MALLOC(sizeof(Datastore_Value) + 
		   size);
    kb = (KBlock*) &value[1];
    memcpy(&kb[1],
	   dstURI,
	   strlen(dstURI)+1);
    mdsize = size - sizeof(KBlock) - strlen(dstURI) - 1;
    mdsize = ECRS_serializeMetaData(md,
				    &((char*)&kb[1])[strlen(dstURI)+1],
				    mdsize,
				    YES);
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
    memcpy(&kb[1],
	   dstURI,
	   strlen(dstURI)+1);
    ECRS_serializeMetaData(md,
			   &((char*)&kb[1])[strlen(dstURI)+1],
			   mdsize,
			   NO);
  }  
  value->size = htonl(sizeof(Datastore_Value) + size);
  value->type = htonl(K_BLOCK);
  value->prio = htonl(priority);
  value->anonymityLevel = htonl(anonymityLevel);
  value->expirationTime = htonll(expirationTime);
  sock = getClientSocket();
  ret = OK;
  
  keywords = uri->data.ksk.keywords;
  keywordCount = uri->data.ksk.keywordCount;
  for (i=0;i<keywordCount;i++) {
    hash(keywords[i],
	 strlen(keywords[i]),
	 &hc);
    ECRS_encryptInPlace(&hc,
			&kb[1],
			mdsize + strlen(dstURI) + 1);
    pk = makeKblockKey(&hc);
    getPublicKey(pk,
		 &kb->keyspace);
    GNUNET_ASSERT(OK == sign(pk,
			     mdsize + strlen(dstURI) + 1,
			     &kb[1],
			     &kb->signature));
    /* extra check: verify sig */
    freePrivateKey(pk);
    if (OK != FS_insert(sock, value))
      ret = SYSERR;
    FREE(keywords[i]);
  }
  GROW(keywords, keywordCount, 0);  

  FREE(dstURI);
  releaseClientSocket(sock);
  FREE(value);
  return ret;
}

/* end of keyspace.c */
