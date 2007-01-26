/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/uri.c
 * @brief Parses and produces uri strings.
 * @author Igor Wronsky, Christian Grothoff
 *
 * GNUnet URIs are of the general form "gnunet://MODULE/IDENTIFIER".
 * The specific structure of "IDENTIFIER" depends on the module and
 * maybe differenciated into additional subcategories if applicable.
 * This module only deals with ecrs identifiers (MODULE = "ecrs").
 * <p>
 *
 * This module only parses URIs for the AFS module.  The ECRS URIs fall
 * into four categories, "chk", "sks", "ksk" and "loc".  The first three
 * categories were named in analogy (!) to Freenet, but they do NOT
 * work in exactly the same way.  They are very similar from the user's
 * point of view (unique file identifier, subspace, keyword), but the
 * implementation is rather different in pretty much every detail.
 * The concrete URI formats are:
 *
 * <ul><li>
 *
 * First, there are URIs that identify a file.  They have the format
 * "gnunet://ecrs/chk/HEX1.HEX2.SIZE".  These URIs can be used to
 * download the file.  The description, filename, mime-type and other
 * meta-data is NOT part of the file-URI since a URI uniquely
 * identifies a resource (and the contents of the file would be the
 * same even if it had a different description).
 *
 * </li><li>
 *
 * The second category identifies entries in a namespace.  The format
 * is "gnunet://ecrs/sks/NAMESPACE/IDENTIFIER" where the namespace
 * should be given in HEX.  Applications may allow using a nickname
 * for the namespace if the nickname is not ambiguous.  The identifier
 * can be either an ASCII sequence or a HEX-encoding.  If the
 * identifier is in ASCII but the format is ambiguous and could denote
 * a HEX-string a "/" is appended to indicate ASCII encoding.
 *
 * </li> <li>
 *
 * The third category identifies ordinary searches.  The format is
 * "gnunet://ecrs/ksk/KEYWORD[+KEYWORD]*".  Using the "+" syntax
 * it is possible to encode searches with the boolean "AND" operator.
 * "+" is used since it indicates a commutative 'and' operation and
 * is unlikely to be used in a keyword by itself.
 *
 * </li><li>
 *
 * The last category identifies a datum on a specific machine.  The
 * format is "gnunet://ecrs/loc/HEX1.HEX2.SIZE.PEER.SIG1.SIG2.PROTO.SAS.MTU.EXPTIME.ADDR".  PEER is
 * the BinName of the public key of the peer storing the datum, SIG1 certifies
 * that this peer has this content; SIG2 is a signature for a HELLO
 * about peer, which is encoded in PROTO, SAS, MTU, EXPTIME and ADDR.
 * HEX1, HEX2 and SIZE correspond to a 'chk' URI.
 *
 * </li></ul>
 *
 * The encoding for hexadecimal values is defined in the hashing.c
 * module (EncName) in the gnunet-util library and discussed there.
 * <p>
 */

#include "platform.h"
#include "ecrs.h"
#include "gnunet_protocols.h"
#include "gnunet_ecrs_lib.h"

/**
 * Generate a keyword URI.
 * @return NULL on error (i.e. keywordCount == 0)
 */
static char * 
createKeywordURI(char ** keywords,
		 unsigned int keywordCount) {
  size_t n;
  char * ret;
  unsigned int i;

  n = keywordCount + strlen(ECRS_URI_PREFIX) + strlen(ECRS_SEARCH_INFIX) + 1;
  for (i=0;i<keywordCount;i++)
    n += strlen(keywords[i]);
  ret = MALLOC(n);
  strcpy(ret, ECRS_URI_PREFIX);
  strcat(ret, ECRS_SEARCH_INFIX);
  for (i=0;i<keywordCount;i++) {
    strcat(ret, keywords[i]);
    if (i != keywordCount-1)
      strcat(ret, "+");
  }
  return ret;
}

/**
 * Generate a subspace URI.
 */
static char * 
createSubspaceURI(const HashCode512 * namespace,
		  const HashCode512 * identifier) {
  size_t n;
  char * ret;
  EncName ns;
  EncName id;

  n = sizeof(EncName) * 2 + strlen(ECRS_URI_PREFIX) + strlen(ECRS_SUBSPACE_INFIX) + 1;
  ret = MALLOC(n);
  hash2enc(namespace, &ns);
  hash2enc(identifier, &id);
  SNPRINTF(ret, n,
	   "%s%s%s/%s",
	   ECRS_URI_PREFIX,
	   ECRS_SUBSPACE_INFIX,
	   (char*) &ns,
	   (char*) &id);
  return ret;
}

/**
 * Generate a file URI.
 */
static char * 
createFileURI(const FileIdentifier * fi) {
  char * ret;
  EncName keyhash;
  EncName queryhash;
  size_t n;

  hash2enc(&fi->chk.key,
           &keyhash);
  hash2enc(&fi->chk.query,
           &queryhash);

  n = strlen(ECRS_URI_PREFIX)+2*sizeof(EncName)+8+16+32+strlen(ECRS_FILE_INFIX);
  ret = MALLOC(n);
  SNPRINTF(ret,
	   n,
	   "%s%s%s.%s.%llu",
	   ECRS_URI_PREFIX,
	   ECRS_FILE_INFIX,
	   (char*)&keyhash,
	   (char*)&queryhash,
	   ntohll(fi->file_length));	
  return ret;
}

#include "bincoder.c"

/**
 * Create a (string) location URI from a Location.
 */
static char * 
createLocURI(const Location * loc) {
  size_t n;
  char * ret;
  EncName keyhash;
  EncName queryhash;
  char * peerId;
  char * peerSig;
  char * peerHSig;
  char * peerAddr;

  hash2enc(&loc->fi.chk.key,
           &keyhash);
  hash2enc(&loc->fi.chk.query,
           &queryhash);
  n = 2148 + ntohs(loc->sas) * 2;
  peerId = bin2enc(&loc->peer,
		   sizeof(PublicKey));
  peerSig = bin2enc(&loc->contentSignature,
		    sizeof(Signature));
  peerHSig = bin2enc(&loc->helloSignature,
		     sizeof(Signature));
  peerAddr = bin2enc(loc->address,
		     loc->sas);
  ret = MALLOC(n);
  SNPRINTF(ret,
	   n,
	   "%s%s%s.%s.%llu.%s.%s.%s.%u.%u.%u.%u.%s",
	   ECRS_URI_PREFIX,
	   ECRS_LOCATION_INFIX,
	   (char*)&keyhash,
	   (char*)&queryhash,
	   ntohll(loc->fi.file_length),
	   peerId,
	   peerSig,
	   peerHSig,
	   loc->proto,
	   loc->sas,
	   loc->mtu,
	   loc->expirationTime,
	   peerAddr);
  FREE(peerId);
  FREE(peerSig);
  FREE(peerHSig);
  FREE(peerAddr);
  return ret;
}

/**
 * Convert a URI to a UTF-8 String.
 */
char * ECRS_uriToString(const struct ECRS_URI * uri) {
  if (uri == NULL) {
    GE_BREAK(NULL, 0);
    return NULL;
  }
  switch (uri->type) {
  case ksk:
    return createKeywordURI(uri->data.ksk.keywords,
			    uri->data.ksk.keywordCount);
  case sks:
    return createSubspaceURI(&uri->data.sks.namespace,
			     &uri->data.sks.identifier);
  case chk:
    return createFileURI(&uri->data.fi);
  case loc:
    return createLocURI(&uri->data.loc);
  default:
    GE_BREAK(NULL, 0);
    return NULL;
  }
}

/**
 * Parses an AFS search URI.
 *
 * @param uri an uri string
 * @param keyword will be set to an array with the keywords
 * @return SYSERR if this is not a search URI, otherwise
 *  the number of keywords placed in the array
 */
static int parseKeywordURI(struct GE_Context * ectx,
			   const char * uri,
			   char *** keywords) {
  unsigned int pos;
  int ret;
  int iret;
  int i;
  size_t slen;
  char * dup;

  GE_ASSERT(ectx, uri != NULL);

  slen = strlen(uri);
  pos = strlen(ECRS_URI_PREFIX);

  if (0 != strncmp(uri,
		   ECRS_URI_PREFIX,
		   pos))
    return SYSERR;
  if (0 != strncmp(&uri[pos],
		   ECRS_SEARCH_INFIX,
		   strlen(ECRS_SEARCH_INFIX)))
    return SYSERR;
  pos += strlen(ECRS_SEARCH_INFIX);
  if (slen == pos) {
    /* no keywords */
    (*keywords) = NULL;
    return 0;
  }
  if ( (uri[slen-1] == '+') ||
       (uri[pos] == '+') )
    return SYSERR; /* no keywords / malformed */

  ret = 1;
  for (i=pos;i<slen;i++) {
    if (uri[i] == '+') {
      ret++;
      if (uri[i-1] == '+')
	return SYSERR; /* "++" not allowed */
    }
  }
  iret = ret;
  dup = STRDUP(uri);
  (*keywords) = MALLOC(ret * sizeof(char*));
  for (i=slen-1;i>=pos;i--) {
    if (dup[i] == '+') {
      (*keywords)[--ret] = STRDUP(&dup[i+1]);
      dup[i] = '\0';
    }
  }
  (*keywords)[--ret] = STRDUP(&dup[pos]);
  GE_ASSERT(ectx, ret == 0);
  FREE(dup);
  return iret;
}

/**
 * Parses an AFS namespace / subspace identifier URI.
 *
 * @param uri an uri string
 * @param namespace set to the namespace ID
 * @param identifier set to the ID in the namespace
 * @return OK on success, SYSERR if this is not a namespace URI
 */
static int parseSubspaceURI(struct GE_Context * ectx,
			    const char * uri,
			    HashCode512 * namespace,
			    HashCode512 * identifier) {
  unsigned int pos;
  size_t slen;
  char * up;

  GE_ASSERT(ectx, uri != NULL);

  slen = strlen(uri);
  pos = strlen(ECRS_URI_PREFIX);

  if (0 != strncmp(uri,
		   ECRS_URI_PREFIX,
		   pos))
    return SYSERR;
  if (0 != strncmp(&uri[pos],
		   ECRS_SUBSPACE_INFIX,
		   strlen(ECRS_SUBSPACE_INFIX)))
    return SYSERR;
  pos += strlen(ECRS_SUBSPACE_INFIX);
  if ( (slen < pos+sizeof(EncName)+1) ||
       (!(uri[pos+sizeof(EncName)-1] == '/') || (uri[pos+sizeof(EncName)-1] == '\\')) )
    return SYSERR;

  up = STRDUP(uri);
  up[pos+sizeof(EncName)-1] = '\0';
  if ( (OK != enc2hash(&up[pos],
		       namespace)) ) {
    FREE(up);
    return SYSERR;
  }
  if ( (slen != pos+2*sizeof(EncName)-1) ||
       (OK == enc2hash(&up[pos+sizeof(EncName)],
		       identifier)) ) {
    if (up[slen-1] == '\\')
      up[--slen] = '\0';
    hash(&up[pos+sizeof(EncName)],
	 slen - (pos+sizeof(EncName)),
	 identifier);
  }
  FREE(up);
  return OK;
}

/**
 * Parses an URI that identifies a file
 *
 * @param uri an uri string
 * @param fi the file identifier
 * @return OK on success, SYSERR if this is not a file URI
 */
static int parseFileURI(struct GE_Context * ectx,
			const char * uri,
			FileIdentifier * fi) {
  unsigned int pos;
  size_t slen;
  char * dup;

  GE_ASSERT(ectx, uri != NULL);

  slen = strlen(uri);
  pos = strlen(ECRS_URI_PREFIX);

  if (0 != strncmp(uri,
		   ECRS_URI_PREFIX,
		   pos))
    return SYSERR;
  if (0 != strncmp(&uri[pos],
		   ECRS_FILE_INFIX,
		   strlen(ECRS_FILE_INFIX)))
    return SYSERR;
  pos += strlen(ECRS_FILE_INFIX);
  if ( (slen < pos+2*sizeof(EncName)+1) ||
       (uri[pos+sizeof(EncName)-1] != '.') ||
       (uri[pos+sizeof(EncName)*2-1] != '.') )
    return SYSERR;

  dup = STRDUP(uri);
  dup[pos+sizeof(EncName)-1]   = '\0';
  dup[pos+sizeof(EncName)*2-1] = '\0';
  if ( (OK != enc2hash(&dup[pos],
		       &fi->chk.key)) ||
       (OK != enc2hash(&dup[pos+sizeof(EncName)],
		       &fi->chk.query)) ||
       (1 != SSCANF(&dup[pos+sizeof(EncName)*2],
		    "%llu",
		    &fi->file_length)) ) {
    FREE(dup);
    return SYSERR;
  }
  FREE(dup);
  fi->file_length = htonll(fi->file_length);
  return OK;
}

/**
 * (re)construct the HELLO message of the peer offering the data
 *
 * @return HELLO message
 */
static P2P_hello_MESSAGE *
getHelloFromLoc(const Location * loc) {
  P2P_hello_MESSAGE * hello;

  hello = MALLOC(sizeof(P2P_hello_MESSAGE) + loc->sas);
  hello->header.size = htons(sizeof(P2P_hello_MESSAGE) + loc->sas);
  hello->header.type = htons(p2p_PROTO_hello);
  hello->MTU = htonl(loc->mtu);
  hello->senderAddressSize = htons(loc->sas);
  hello->protocol = htons(loc->proto);
  hello->expirationTime = htonl(loc->expirationTime);
  hello->publicKey = loc->peer;
  hash(&hello->publicKey,
       sizeof(PublicKey),
       &hello->senderIdentity.hashPubKey);
  hello->signature = loc->helloSignature;
  memcpy(&hello[1],
	 loc->address,
	 loc->sas);
  return hello;
}

/**
 * Parses an URI that identifies a location (and file).
 * Also verifies validity of the location URI.
 *
 * @param uri an uri string
 * @param loc where to store the location
 * @return OK on success, SYSERR if this is not a file URI
 */
static int parseLocationURI(struct GE_Context * ectx,
			    const char * uri,
			    Location * loc) {
  unsigned int pos;
  unsigned int npos;
  unsigned int proto;
  unsigned int sas;
  int ret;
  size_t slen;
  char * dup;
  char * addr;
  P2P_hello_MESSAGE * hello;
 
  GE_ASSERT(ectx, uri != NULL);
  addr = NULL;
  slen = strlen(uri);
  pos = strlen(ECRS_URI_PREFIX);

  if (0 != strncmp(uri,
		   ECRS_URI_PREFIX,
		   pos))
    return SYSERR;
  if (0 != strncmp(&uri[pos],
		   ECRS_LOCATION_INFIX,
		   strlen(ECRS_LOCATION_INFIX)))
    return SYSERR;
  pos += strlen(ECRS_LOCATION_INFIX);
  if ( (slen < pos+2*sizeof(EncName)+1) ||
       (uri[pos+sizeof(EncName)-1] != '.') ||
       (uri[pos+sizeof(EncName)*2-1] != '.') )
    return SYSERR;

  dup = STRDUP(uri);
  dup[pos+sizeof(EncName)-1]   = '\0';
  dup[pos+sizeof(EncName)*2-1] = '\0';
  npos = pos +sizeof(EncName)*2;
  while ( (uri[npos] != '\0') &&
	  (uri[npos] != '.') )
    npos++;
  if (dup[npos] == '\0') 
    goto ERR;
  dup[npos++] = '\0';
  if ( (OK != enc2hash(&dup[pos],
		       &loc->fi.chk.key)) ||
       (OK != enc2hash(&dup[pos+sizeof(EncName)],
		       &loc->fi.chk.query)) ||
       (1 != SSCANF(&dup[pos+sizeof(EncName)*2],
		    "%llu",
		    &loc->fi.file_length)) ) 
    goto ERR;
  ret = enc2bin(&dup[npos],
		&loc->peer,
		sizeof(PublicKey));
  if (ret == -1) 
    goto ERR;
  npos += ret;
  if (dup[npos++] != '.')
    goto ERR;
  ret = enc2bin(&dup[npos],
		&loc->contentSignature,
		sizeof(Signature));
  if (ret == -1) 
    goto ERR;
  npos += ret;
  if (dup[npos++] != '.')
    goto ERR;
  ret = enc2bin(&dup[npos],
		&loc->helloSignature,
		sizeof(Signature));
  if (ret == -1) 
    goto ERR;
  npos += ret;
  if (dup[npos++] != '.')
    goto ERR;
  ret = 4;
  pos = npos;
  while ( (dup[npos] != '\0') &&
	  (ret > 0) ) {
    if (dup[npos] == '.')
      ret--;    
    npos++;
  }
  if (ret != 0)
    goto ERR;
  dup[npos-1] = '\0';
  if (4 != SSCANF(&dup[pos],
		  "%u.%u.%u.%u",
		  &proto,
		  &sas,
		  &loc->mtu,
		  &loc->expirationTime))
    goto ERR;
  if ( (proto >= 65536) ||
       (sas >= 65536) )
    goto ERR;
  loc->proto = (unsigned short) proto;
  loc->sas = (unsigned short) sas;
  addr = MALLOC(sas);
  loc->address = addr;
  ret = enc2bin(&dup[npos],
		addr,
		sas);
  if (ret == -1)
    goto ERR;
  npos += ret;
  if (dup[npos] != '\0')
    goto ERR;
  loc->fi.file_length = htonll(loc->fi.file_length);
  
  /* Finally: verify sigs! */
  if (OK != verifySig(&loc->fi,
		      sizeof(FileIdentifier) + 
		      sizeof(PublicKey) +
		      sizeof(TIME_T),
		      &loc->contentSignature,
		      &loc->peer)) 
    goto ERR;
  hello = getHelloFromLoc(loc);
  if (hello == NULL) 
    goto ERR;
  if (OK != verifySig(&hello->senderIdentity,
		      P2P_hello_MESSAGE_size(hello) -
		      sizeof(MESSAGE_HEADER) -
		      sizeof(Signature) -
		      sizeof(PublicKey),
		      &loc->helloSignature,
		      &hello->publicKey)) { 
    FREE(hello);
    goto ERR;
  }
  FREE(hello);
  FREE(dup);
  return OK;
 ERR:
  FREE(dup);
  FREENONNULL(addr);
  return SYSERR;
}

/**
 * Convert a UTF-8 String to a URI.
 */
URI * ECRS_stringToUri(struct GE_Context * ectx,
		       const char * uri) {
  URI * ret;
  int len;

  ret = MALLOC(sizeof(URI));
  if (OK == parseFileURI(ectx,
			 uri,
			 &ret->data.fi)) {
    ret->type = chk;
    return ret;
  }
  if (OK == parseSubspaceURI(ectx,
			     uri,
			     &ret->data.sks.namespace,
			     &ret->data.sks.identifier)) {
    ret->type = sks;
    return ret;
  }
  if (OK == parseLocationURI(ectx,
			     uri,
			     &ret->data.loc)) {
    ret->type = loc;
    return ret;
  }
  len = parseKeywordURI(ectx,
			uri,
			&ret->data.ksk.keywords);
  if (len < 0) {
    FREE(ret);
    return NULL;
  }
  ret->type = ksk;
  ret->data.ksk.keywordCount
    = len;
  return ret;
}

/**
 * Free URI.
 */
void ECRS_freeUri(struct ECRS_URI * uri) {
  int i;

  GE_ASSERT(NULL, uri != NULL);
  if (uri->type == ksk) {
    for (i=0;i<uri->data.ksk.keywordCount;i++)
      FREE(uri->data.ksk.keywords[i]);
    GROW(uri->data.ksk.keywords,
	 uri->data.ksk.keywordCount,
	 0);
  }
  if (uri->type == loc)
    FREENONNULL(uri->data.loc.address);
  FREE(uri);
}

/**
 * Is this a namespace URI?
 */
int ECRS_isNamespaceUri(const struct ECRS_URI * uri) {
  return uri->type == sks;
}

/**
 * Get the (globally unique) name for the given namespace.
 *
 * @return the name (hash) of the namespace, caller
 *  must free it.
 */
char * ECRS_getNamespaceName(const HashCode512 * id) {
  char * ret;

  ret = MALLOC(sizeof(EncName));
  hash2enc(id,
	   (EncName*)ret);
  return ret;
}

/**
 * Get the (globally unique) ID of the namespace
 * from the given namespace URI.
 *
 * @return OK on success
 */
int ECRS_getNamespaceId(const struct ECRS_URI * uri,
			HashCode512 * id) {
  if (! ECRS_isNamespaceUri(uri)) {
    GE_BREAK(NULL, 0);
    return SYSERR;
  }
  *id = uri->data.sks.namespace;
  return OK;
}

/**
 * Get the content ID of an SKS URI.
 *
 * @return OK on success
 */
int ECRS_getSKSContentHash(const struct ECRS_URI * uri,
			   HashCode512 * id) {
  if (! ECRS_isNamespaceUri(uri)) {
    GE_BREAK(NULL, 0);
    return SYSERR;
  }
  *id = uri->data.sks.identifier;
  return OK;
}

/**
 * Is this a keyword URI?
 */
int ECRS_isKeywordUri(const struct ECRS_URI * uri) {
#if EXTRA_CHECKS
  int i;

  if (uri->type == ksk) {
    for (i=uri->data.ksk.keywordCount-1;i>=0;i--)
      GE_ASSERT(NULL, uri->data.ksk.keywords[i] != NULL);
  }
#endif
  return uri->type == ksk;
}


/**
 * How many keywords are ANDed in this keyword URI?
 * @return 0 if this is not a keyword URI
 */
unsigned int ECRS_countKeywordsOfUri(const struct ECRS_URI * uri) {
  if (uri->type != ksk)
    return 0;
  return uri->data.ksk.keywordCount;
}

/**
 * Iterate over all keywords in this keyword URI?
 * @return -1 if this is not a keyword URI, otherwise number of
 *   keywords iterated over until iterator aborted
 */
int ECRS_getKeywordsFromUri(const struct ECRS_URI * uri,
			    ECRS_KeywordIterator iterator,
			    void * cls) {
  int i;
  if (uri->type != ksk) {
    return -1;
  } else {
    for (i=0;i<uri->data.ksk.keywordCount;i++)
      if (iterator != NULL)
	if (OK != iterator(uri->data.ksk.keywords[i],
			   cls))
	  return i;
    return i;
  }
}


/**
 * Is this a file (or directory) URI?
 */
int ECRS_isFileUri(const struct ECRS_URI * uri) {
  return uri->type == chk;
}

/**
 * Is this a location URI? (DHT specific!)
 */
int ECRS_isLocationUri(const struct ECRS_URI * uri) {
  return uri->type == loc;
}


/**
 * What is the size of the file that this URI
 * refers to?
 */
unsigned long long ECRS_fileSize(const struct ECRS_URI * uri) {
  switch (uri->type) {
  case chk:
    return ntohll(uri->data.fi.file_length);
  case loc:
    return ntohll(uri->data.loc.fi.file_length);
  default:
    GE_ASSERT(NULL, 0);
  }
  return 0; /* unreachable */
}


/**
 * Duplicate URI.
 */
URI * ECRS_dupUri(const URI * uri) {
  struct ECRS_URI * ret;
  int i;

  ret = MALLOC(sizeof(URI));
  memcpy(ret,
	 uri,
	 sizeof(URI));
  switch (ret->type) {
  case ksk:
    if (ret->data.ksk.keywordCount > 0) {
      ret->data.ksk.keywords
	= MALLOC(ret->data.ksk.keywordCount * sizeof(char*));
      for (i=0;i<ret->data.ksk.keywordCount;i++)
	ret->data.ksk.keywords[i]
	  = STRDUP(uri->data.ksk.keywords[i]);
    }
    break;
  default:
    break;
  }
  return ret;
}

/**
 * Expand a keyword-URI by duplicating all keywords,
 * adding the current date (YYYY-MM-DD) after each
 * keyword.
 */
URI * ECRS_dateExpandKeywordUri(const URI * uri) {
  URI * ret;
  int i;
  char * key;
  char * kd;
  struct tm t;
  time_t now;
  unsigned int keywordCount;

  GE_ASSERT(NULL, uri->type == ksk);
  time(&now);
#ifdef HAVE_GMTIME_R
  gmtime_r(&now, &t);
#else
  t = *gmtime(&now);
#endif

  ret = MALLOC(sizeof(URI));
  ret->type = ksk;
  keywordCount = uri->data.ksk.keywordCount;
  ret->data.ksk.keywordCount = 2 * keywordCount;
  if (keywordCount > 0) {
    ret->data.ksk.keywords = MALLOC(sizeof(char*) * keywordCount * 2);
    for (i=0;i<keywordCount;i++) {
      key = uri->data.ksk.keywords[i];
      GE_ASSERT(NULL, key != NULL);
      ret->data.ksk.keywords[2*i]
	= STRDUP(key);
      kd = MALLOC(strlen(key) + 13);
      memset(kd, 0, strlen(key) + 13);
      strcpy(kd, key);
      strftime(&kd[strlen(key)],
	       13,
	       "-%Y-%m-%d",
	       &t);
      ret->data.ksk.keywords[2*i+1]
	= kd;
    }
  } else
    ret->data.ksk.keywords = NULL;

  return ret;
}


/**
 * Construct a keyword-URI from meta-data (take all entries
 * in the meta-data and construct one large keyword URI
 * that lists all keywords that can be found in the meta-data).
 */
URI * ECRS_metaDataToUri(const MetaData * md) {
  URI * ret;
  int i;
  int j;
  int havePreview;
  int add;

  if (md == NULL)
    return NULL;
  ret = MALLOC(sizeof(URI));
  ret->type = ksk;
  ret->data.ksk.keywordCount = 0;
  ret->data.ksk.keywords = NULL;
  havePreview = 0;
  for (i=md->itemCount-1;i>=0;i--) {
    if (md->items[i].type == EXTRACTOR_THUMBNAIL_DATA) {
      havePreview++;
    } else {
      for (j=md->itemCount-1;j>i;j--) {
	if (0 == strcmp(md->items[i].data,
			md->items[j].data)) {
	  havePreview++; /* duplicate! */
	  break;
	}
      }
    }
  }
  GROW(ret->data.ksk.keywords,
       ret->data.ksk.keywordCount,
       md->itemCount - havePreview);
  for (i=md->itemCount-1;i>=0;i--) {
    if (md->items[i].type == EXTRACTOR_THUMBNAIL_DATA) {
      havePreview--;
    } else {
      add = 1;
      for (j=md->itemCount-1;j>i;j--) {
	if (0 == strcmp(md->items[i].data,
			md->items[j].data)) {
	  havePreview--;
	  add = 0;
	  break;
	}
      }
      if (add == 1) {
	GE_ASSERT(NULL, md->items[i].data != NULL);
	ret->data.ksk.keywords[i-havePreview]
	  = STRDUP(md->items[i].data);
      }
    }
  }
  return ret;
}

/**
 * Convert a NULL-terminated array of keywords
 * to an ECRS URI.
 */
struct ECRS_URI * ECRS_keywordsToUri(const char * keyword[]) {
  unsigned int count;
  URI * ret;
  unsigned int i;

  count = 0;
  while (keyword[count] != NULL)
    count++;

  ret = MALLOC(sizeof(URI));
  ret->type = ksk;
  ret->data.ksk.keywordCount = 0;
  ret->data.ksk.keywords = NULL;
  GROW(ret->data.ksk.keywords,
       ret->data.ksk.keywordCount,
       count);
  for (i=0;i<count;i++)
    ret->data.ksk.keywords[i] = STRDUP(keyword[i]);
  return ret;
}



/**
 * Are these two URIs equal?
 */
int ECRS_equalsUri(const struct ECRS_URI * uri1,
		   const struct ECRS_URI * uri2) {
  int ret;
  int i;
  int j;

  GE_ASSERT(NULL, uri1 != NULL);
  GE_ASSERT(NULL, uri2 != NULL);
  if (uri1->type != uri2->type)
    return NO;
  switch(uri1->type) {
  case chk:
    if (0 == memcmp(&uri1->data.fi,
		    &uri2->data.fi,
		    sizeof(FileIdentifier)))
      return YES;
    return NO;
  case sks:
    if (equalsHashCode512(&uri1->data.sks.namespace,
			  &uri2->data.sks.namespace) &&
	equalsHashCode512(&uri1->data.sks.identifier,
			  &uri2->data.sks.identifier) )
	
      return YES;
    return NO;
  case ksk:
    if (uri1->data.ksk.keywordCount !=
	uri2->data.ksk.keywordCount)
      return NO;
    for (i=0;i<uri1->data.ksk.keywordCount;i++) {
      ret = NO;
      for (j=0;j<uri2->data.ksk.keywordCount;j++) {
	if (0 == strcmp(uri1->data.ksk.keywords[i],
			uri2->data.ksk.keywords[j])) {
	  ret = YES;
	  break;
	}
      }
      if (ret == NO)
	return NO;			
    }
    return YES;
  case loc:
    if (memcmp(&uri1->data.loc,
	       &uri2->data.loc,
	       sizeof(FileIdentifier) +
	       sizeof(PublicKey) + 
	       sizeof(TIME_T) +
	       sizeof(unsigned short) +
	       sizeof(unsigned short)) != 0)
      return NO;
    if (memcmp(&uri1->data.loc.helloSignature,
	       &uri2->data.loc.helloSignature,
	       sizeof(Signature) * 2) != 0)
      return NO;
    if (memcmp(uri1->data.loc.address,
	       uri2->data.loc.address,
	       uri1->data.loc.sas) != 0)
      return NO;
    return YES;	       
  default:
    return NO;
  }
}

/**
 * Obtain the identity of the peer offering the data
 * @return -1 if this is not a location URI, otherwise OK
 */
int ECRS_getPeerFromUri(const struct ECRS_URI * uri,
			PeerIdentity * peer) {
  if (uri->type != loc)
    return -1;
  hash(&uri->data.loc.peer,
       sizeof(PublicKey),
       &peer->hashPubKey);
  return OK;
}

/**
 * (re)construct the HELLO message of the peer offering the data
 *
 * @return NULL if this is not a location URI
 */
P2P_hello_MESSAGE *
ECRS_getHelloFromUri(const struct ECRS_URI * uri) {
  if (uri->type != loc)
    return NULL;
  return getHelloFromLoc(&uri->data.loc);
}

/**
 * Obtain the URI of the content itself.
 *
 * @return NULL if argument is not a location URI
 */
struct ECRS_URI *
ECRS_getContentUri(const struct ECRS_URI * uri) {
  struct ECRS_URI * ret;

  if (uri->type != loc)
    return NULL;
   ret = MALLOC(sizeof(struct ECRS_URI));
  ret->type = chk;
  ret->data.fi = uri->data.loc.fi;
  return ret;
}

/**
 * Construct a location URI.
 *
 * @param baseURI content offered by the sender
 * @param sender identity of the peer with the content
 * @param expirationTime how long will the content be offered?
 * @param proto transport protocol to reach the peer
 * @param sas sender address size (for HELLO)
 * @param address sas bytes of address information
 * @param signer function to call for obtaining 
 *        RSA signatures for "sender".
 * @return the location URI
 */
struct ECRS_URI *
ECRS_uriFromLocation(const struct ECRS_URI * baseUri,
		     const PublicKey * sender,
		     TIME_T expirationTime,
		     unsigned short proto,
		     unsigned short sas,
		     unsigned int mtu,
		     const char * address,
		     ECRS_SignFunction signer,
		     void * signer_cls) {
  struct ECRS_URI * uri;
  P2P_hello_MESSAGE * hello;
  

  if (baseUri->type != chk)
    return NULL;

  uri = MALLOC(sizeof(struct ECRS_URI));
  uri->type = loc;
  uri->data.loc.fi = baseUri->data.fi;
  uri->data.loc.peer = *sender;
  uri->data.loc.expirationTime = expirationTime;
  uri->data.loc.proto = proto;
  uri->data.loc.sas = sas;
  uri->data.loc.mtu = mtu;
  if (sas > 0) {
    uri->data.loc.address = MALLOC(sas);
    memcpy(uri->data.loc.address,
	   address,
	   sas);
  } else {
    uri->data.loc.address = NULL;
  }
  hello = ECRS_getHelloFromUri(uri);
  if (hello == NULL) {
    GE_BREAK(NULL, 0);
    FREENONNULL(uri->data.loc.address);
    FREE(uri);
    return NULL;
  }
  signer(signer_cls,
	 P2P_hello_MESSAGE_size(hello)
	 - sizeof(Signature)
	 - sizeof(PublicKey)
	 - sizeof(MESSAGE_HEADER), 
	 &hello->senderIdentity,
	 &uri->data.loc.helloSignature);
  FREE(hello);
  signer(signer_cls,
	 sizeof(FileIdentifier) + 
	 sizeof(PublicKey) +
	 sizeof(TIME_T),
	 &uri->data.loc.fi,
	 &uri->data.loc.contentSignature);
  return uri;
}


/* end of uri.c */
