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
 * @file applications/afs/module/uri.c 
 * @brief Parses and produces uri strings.
 * @author Igor Wronsky, Christian Grothoff
 *
 * GNUnet URIs are of the general form "gnunet://MODULE/IDENTIFIER".
 * The specific structure of "IDENTIFIER" depends on the module and
 * maybe differenciated into additional subcategories if applicable.
 * <p>
 * This module only parses URIs for the AFS module.  The AFS URIs fall
 * into three categories.  Note that the IDENTIFIER format of the
 * three categories is sufficiently different to not require an explicit
 * sub-module structure; nevertheless, an optional explicit qualifier
 * is supported.  The concrete categories are the following:
 *
 * <ul>
 * <li>
 * First, there are URIs that identify a file.
 * They have the format "gnunet://afs/[file/]HEX1.HEX2.CRC.SIZE".  These URIs
 * can be used to download or delete files.  URIs do not specify the
 * specific action that is to be taken, the action always comes from
 * the specific command that is being executed, such as
 * "gnunet-delete" or "gnunet-download".  The URI that identifies a
 * file is also NOT used for insertion, in fact it is the RESULT of an
 * insertion operation.  Furthermore, the description, filename,
 * mime-type and other meta-data is NOT part of the file-URI since a
 * URI uniquely identifies a resource (and the contents of the file
 * would be the same if it had a different description).</li>
 * <li>
 * The second category identifies entries in the namespace.  The
 * format is "gnunet://afs/[subspace/]NAMESPACE/IDENTIFIER" where the
 * namespace must be given in HEX and the identifier can be 
 * either an ASCII sequence or a HEX-encoding.  If the
 * identifier is in ASCII but the format is ambiguous and
 * could denote a HEX-string a "/" is appended to indicate
 * ASCII encoding.  
 * </li>
 * <li>
 * The third category identifies ordinary searches.  The format
 * is "gnunet://afs/[search/]KEYWORD[+KEYWORD]*".  Using the "+" syntax
 * it is possible to encode searches with the boolean "AND"
 * operator.  "+" is used since it both indicates a commutative
 * operation and helps disambiguate the query from the
 * namespace-search.
 * </li>
 * </ul>
 *
 * The encoding for hexadecimal values is defined in the hashing.c
 * module (EncName) in the gnunet-util library and discussed there.
 * <p>
 *
 */

#include "gnunet_afs_esed2.h"
#include "platform.h"

#define SEARCH_INFIX "search/"
#define SUBSPACE_INFIX "subspace/"
#define FILE_INFIX "file/"


/**
 * Do the create functions generate the short URI form by default? 
 * (otherwise the URI type is included in the URI,
 * i.e. "gnunet://afs/search/foo").  Assuming that users want
 * URIs that are as short as possible YES is the right choice.
 * NO results in more verbose output.
 */
#define CREATE_SHORT_URIS YES



/** 
 * Parses an AFS search URI.
 *
 * @param uri an uri string
 * @param keyword will be set to an array with the keywords
 * @return SYSERR if this is not a search URI, otherwise
 *  the number of keywords placed in the array
 */
int parseKeywordURI(const char * uri,
		    char *** keywords) {
  unsigned int pos;
  int ret;
  int iret;
  int i;
  size_t slen;
  char * dup;
  
  GNUNET_ASSERT(uri != NULL);
  
  slen = strlen(uri);
  pos = strlen(AFS_URI_PREFIX);
 
  if (0 != strncmp(uri, 
		   AFS_URI_PREFIX,
		   pos)) 
    return SYSERR;
  if (0 == strncmp(&uri[pos],
		   SEARCH_INFIX,
		   strlen(SEARCH_INFIX)))
    pos += strlen(SEARCH_INFIX);
  if ( (slen == pos) || (uri[slen-1] == '+') || (uri[pos] == '+') )
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
int parseSubspaceURI(const char * uri,
		     HashCode160 * namespace,
		     HashCode160 * identifier) {
  unsigned int pos;
  size_t slen;
  char * up;
  
  GNUNET_ASSERT(uri != NULL);
  
  slen = strlen(uri);
  pos = strlen(AFS_URI_PREFIX);
 
  if (0 != strncmp(uri, 
		   AFS_URI_PREFIX,
		   pos)) 
    return SYSERR;
  if (0 == strncmp(&uri[pos],
		   SUBSPACE_INFIX,
		   strlen(SUBSPACE_INFIX)))
    pos += strlen(SUBSPACE_INFIX);
  if ( (slen != pos+2*sizeof(EncName)-1) ||
       (uri[pos+sizeof(EncName)-1] != '/') )
    return SYSERR;

  up = STRDUP(uri);
  up[pos+sizeof(EncName)-1] = '\0';
  if ( (OK != enc2hash(&up[pos],
		       namespace)) ||
       (OK != enc2hash(&up[pos+sizeof(EncName)],
		       identifier)) ) {
    FREE(up);
    return SYSERR;
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
int parseFileURI(const char * uri,
		 FileIdentifier * fi) {
  unsigned int pos;
  size_t slen;
  char * dup;
  
  GNUNET_ASSERT(uri != NULL);
  
  slen = strlen(uri);
  pos = strlen(AFS_URI_PREFIX);
 
  if (0 != strncmp(uri, 
		   AFS_URI_PREFIX,
		   pos)) 
    return SYSERR;
  if (0 == strncmp(&uri[pos],
		   FILE_INFIX,
		   strlen(FILE_INFIX)))
    pos += strlen(FILE_INFIX);
  if ( (slen < pos+2*sizeof(EncName)+2) ||
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
       (2 != sscanf(&dup[pos+sizeof(EncName)*2],
		    "%X.%u",
		    &fi->crc,
		    &fi->file_length)) ) {
    FREE(dup);
    return SYSERR;  
  }
  FREE(dup);
  fi->crc = htonl(fi->crc);
  fi->file_length = htonl(fi->file_length);
  return OK;
}

/**
 * Generate a keyword URI.
 * @return NULL on error (i.e. keywordCount == 0)
 */
char * createKeywordURI(char ** keywords,
			unsigned int keywordCount) {
  size_t n;
  char * ret;
  unsigned int i;

#if CREATE_SHORT_URIS
  n = keywordCount + strlen(AFS_URI_PREFIX);
#else
  n = keywordCount + strlen(AFS_URI_PREFIX) + strlen(SEARCH_INFIX);
#endif
  for (i=0;i<keywordCount;i++)
    n += strlen(keywords[i]);
  ret = MALLOC(n);
  strcpy(ret, AFS_URI_PREFIX);
#if CREATE_SHORT_URIS
#else
  strcat(ret, SEARCH_INFIX);
#endif
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
char * createSubspaceURI(const HashCode160 * namespace,
			 const HashCode160 * identifier) {
  size_t n;
  char * ret;
  EncName ns;
  EncName id;

#if CREATE_SHORT_URIS
  n = sizeof(EncName) * 2 + strlen(AFS_URI_PREFIX) + 1; 
#else
  n = sizeof(EncName) * 2 + strlen(AFS_URI_PREFIX) + strlen(SUBSPACE_INFIX) + 1;
#endif
  ret = MALLOC(n);
  hash2enc(namespace, &ns);
  hash2enc(identifier, &id);  
#if CREATE_SHORT_URIS
  SNPRINTF(ret, n,
	   "%s%s/%s",
	   AFS_URI_PREFIX,
	   (char*) &ns,
	   (char*) &id);
#else
  SNPRINTF(ret, n,
	   "%s%s%s/%s",
	   AFS_URI_PREFIX,
	   SUBSPACE_INFIX,
	   (char*) &ns,
	   (char*) &id);
#endif
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

#if CREATE_SHORT_URIS
  n = strlen(AFS_URI_PREFIX)+2*sizeof(EncName)+8+16+32;
#else
  n = strlen(AFS_URI_PREFIX)+2*sizeof(EncName)+8+16+32+strlen(FILE_INFIX);
#endif
  ret = MALLOC(n);
#if CREATE_SHORT_URIS
  SNPRINTF(ret, 
	   n,
	   "%s%s.%s.%08X.%u",
	   AFS_URI_PREFIX,
	   (char*)&keyhash,
	   (char*)&queryhash,
	   ntohl(fi->crc),
	   ntohl(fi->file_length));	     
#else
  SNPRINTF(ret, 
	   n,
	   "%s%s%s.%s.%08X.%u",
	   AFS_URI_PREFIX,
	   FILE_INFIX,
	   (char*)&keyhash,
	   (char*)&queryhash,
	   ntohl(fi->crc),
	   ntohl(fi->file_length));	     
#endif
  return ret;
}




/* end of uri.c */

