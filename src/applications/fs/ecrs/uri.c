/*
     This file is part of GNUnet.
     (C) 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * format is "gnunet://ecrs/loc/PEER/QUERY.TYPE.KEY.SIZE".  MACHINE is
 * the EncName of the peer storing the datum, TYPE is the (block) type
 * of the datum and SIZE is the number of bytes.  KEY is used to decrypt
 * the data whereas QUERY is the request that should be transmitted to
 * the PEER.
 *
 * </li></ul>
 *
 * The encoding for hexadecimal values is defined in the hashing.c
 * module (EncName) in the gnunet-util library and discussed there.
 * <p>
 *
 */

#include "platform.h"
#include "ecrs.h"
#include "gnunet_ecrs_lib.h"



/**
 * Generate a keyword URI.
 * @return NULL on error (i.e. keywordCount == 0)
 */
static char * createKeywordURI(char ** keywords,
			       unsigned int keywordCount) {
  size_t n;
  char * ret;
  unsigned int i;

  n = keywordCount + strlen(ECRS_URI_PREFIX) + strlen(ECRS_SEARCH_INFIX);
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
static char * createSubspaceURI(const HashCode160 * namespace,
				const HashCode160 * identifier) {
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
char * createFileURI(const FileIdentifier * fi) {
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

/**
 * Convert a URI to a UTF-8 String.
 */
char * ECRS_uriToString(const struct ECRS_URI * uri) {
  if (uri == NULL) {
    BREAK();
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
    return createFileURI(&uri->data.chk);
  case loc:
    return "FIXME";
  default:
    BREAK();
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
static int parseKeywordURI(const char * uri,
			   char *** keywords) {
  unsigned int pos;
  int ret;
  int iret;
  int i;
  size_t slen;
  char * dup;
  
  GNUNET_ASSERT(uri != NULL);
  
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
  if ( (slen == pos) ||
       (uri[slen-1] == '+') || 
       (uri[pos] == '+') )
    return SYSERR; /* no keywords / malformed */
  
  ret = 1;
  for (i=pos;i<slen;i++) {
    if (uri[i] == '+') {
      ret++;
      if (uri[i-1] == '+')
	return SYSERR; /* ++ not allowed */
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
static int parseSubspaceURI(const char * uri,
			    HashCode160 * namespace,
			    HashCode160 * identifier) {
  unsigned int pos;
  size_t slen;
  char * up;
  
  GNUNET_ASSERT(uri != NULL);
  
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
       (uri[pos+sizeof(EncName)-1] != '/') )
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
static int parseFileURI(const char * uri,
			FileIdentifier * fi) {
  unsigned int pos;
  size_t slen;
  char * dup;
  
  GNUNET_ASSERT(uri != NULL);
  
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
       (1 != sscanf(&dup[pos+sizeof(EncName)*2],
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
 * Convert a UTF-8 String to a URI.
 */
URI * ECRS_stringToUri(const char * uri) {
  URI * ret;
  int len;

  ret = MALLOC(sizeof(URI));
  if (OK == parseFileURI(uri,
			 &ret->data.chk)) {
    ret->type = chk;
    return ret;
  }
  if (OK == parseSubspaceURI(uri,
			     &ret->data.sks.namespace,
			     &ret->data.sks.identifier)) {
    ret->type = sks;
    return ret;
  }
  /* FIXME: parse location! */
  len = parseKeywordURI(uri,
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
  GNUNET_ASSERT(uri != NULL);
  if (uri->type == ksk) {
    for (i=0;i<uri->data.ksk.keywordCount;i++)
      FREE(uri->data.ksk.keywords[i]);
    GROW(uri->data.ksk.keywords,
	 uri->data.ksk.keywordCount,
	 0);
  }
   
  FREE(uri);
}

/**
 * Is this a namespace URI?
 */
int ECRS_isNamespaceURI(const struct ECRS_URI * uri) {
  return uri->type == sks;
}

/**
 * Get the (globally unique) name for the given
 * namespace.
 * @return the name (hash) of the namespace, caller
 *  must free it.
 */
char * ECRS_getNamespaceName(const struct ECRS_URI * uri) {
  char * ret;
  
  if (! ECRS_isNamespaceURI(uri)) {
    BREAK();
    return NULL;
  }  
  ret = MALLOC(sizeof(EncName));
  hash2enc(&uri->data.sks.namespace,
	   (EncName*)ret);
  return ret;
}

/**
 * Is this a keyword URI?
 */
int ECRS_isKeywordURI(const struct ECRS_URI * uri) {
  return uri->type == ksk;
}

/**
 * Is this a file (or directory) URI?
 */
int ECRS_isFileURI(const struct ECRS_URI * uri) {
  return uri->type == chk;
}

/**
 * Is this a location URI? (DHT specific!)
 */
int ECRS_isLocationURI(const struct ECRS_URI * uri) {
  return uri->type == loc;
}


/**
 * What is the size of the file that this URI
 * refers to?
 */
unsigned long long ECRS_fileSize(const struct ECRS_URI * uri) {
  switch (uri->type) {
  case chk:
    return uri->data.chk.file_length;
  case loc:
    return uri->data.loc.size;
  default:
    GNUNET_ASSERT(0);
  }
  return 0; /* unreachable */
}


/**
 * Duplicate URI.  FIXME: this is the QnD, costly
 * implementation.
 */
struct ECRS_URI * ECRS_dupUri(const struct ECRS_URI * uri) {
  char * tmp;
  struct ECRS_URI * ret;

  tmp = ECRS_uriToString(uri);
  ret = ECRS_stringToUri(tmp);
  FREE(tmp);
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

  if (md == NULL)
    return NULL;
  ret = MALLOC(sizeof(URI));
  ret->type = ksk;
  ret->data.ksk.keywordCount = 0;
  ret->data.ksk.keywords = NULL;
  GROW(ret->data.ksk.keywords,
       ret->data.ksk.keywordCount,
       md->itemCount);
  for (i=0;i<md->itemCount;i++)
    ret->data.ksk.keywords[i] = STRDUP(md->items[i].data);
  return ret;
}


/**
 * Are these two URIs equal?  FIXME: not very efficient
 * implementation.  Also, for keyword URIs, we might
 * want to allow permuations.
 */
int ECRS_equalsUri(const struct ECRS_URI * uri1,
		   const struct ECRS_URI * uri2) {
  char * u1;
  char * u2;
  int ret;
  u1 = ECRS_uriToString(uri1);
  u2 = ECRS_uriToString(uri1);
  ret = strcmp(u1, u2);
  FREE(u1);
  FREE(u2);
  if (ret == 0)
    return YES;
  else
    return NO;
}


/* end of uri.c */
