/*
     This file is part of GNUnet

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
 * @file applications/afs/esed2/nblock.c
 * @brief data structure Nblock
 * @author Christian Grothoff
 */

#include "gnunet_afs_esed2.h"
#include "platform.h"

#define DEBUG_NBLOCK NO


/* identical to SBlock, hence copied from there, even
   if the actual data portion looks slightly different... */
#define ENCRYPTED_SIZE \
		   (sizeof(unsigned short) + \
		   sizeof(unsigned short) + \
		   sizeof(FileIdentifier)+ \
		   MAX_DESC_LEN +  \
		   MAX_FILENAME_LEN/2 + \
		   MAX_MIMETYPE_LEN/2 +\
		   sizeof(TIME_T) +\
		   sizeof(TIME_T) + \
		   sizeof(HashCode160) +\
		   sizeof(HashCode160) )

#define SIGNED_SIZE \
		   (ENCRYPTED_SIZE + \
 		   sizeof(HashCode160))




#define NS_HANDLE "namespaces"

/**
 * Build a list of all known namespaces.
 *
 * @param list where to store the names of the namespaces
 * @return SYSERR on error, otherwise the number of known namespaces
 */
int listNamespaces(NBlock ** list) {
  int ret;

  *list = NULL;
  ret = stateReadContent(NS_HANDLE,
			 (void**)list);
  if (ret <= 0)
    return SYSERR;
  if ( (ret % sizeof(NBlock)) != 0) {
    FREE(*list);
    *list = NULL;
    stateUnlinkFromDB(NS_HANDLE);
    return SYSERR;
  }
  return ret / sizeof(NBlock);
}

void decryptNBlock(NBlock * sb) {
  HashCode160 k;
  NBlock tmp;

  memset(&k, 0, sizeof(HashCode160));
  decryptSBlock(&k, (const SBlock*)sb, (SBlock*) &tmp);
  *sb = tmp;
}

/**
 * Get the nickname of the given namespace.  If the
 * nickname is not unique within our database, append
 * the namespace identifier to make it unique.
 */
char * getUniqueNickname(const HashCode160 * ns) {
  NBlock * list;
  int ret;
  EncName enc;
  char * nick;
  int unique;
  int i;

  ret = listNamespaces(&list);
  if (ret > 0) {
    nick = NULL;
    for (i=0;i<ret;i++) {
      if (equalsHashCode160(&list[i].namespace,
			    ns)) {
	nick = STRNDUP(list[i].nickname,
		       MAX_NAME_LEN-8);
	break;
      }	
    }
    if (nick == NULL) {
      hash2enc(ns, &enc);
      return STRDUP((char*) &enc);
    }
    unique = YES;
    for (i=0;i<ret;i++)
      if (0 == strncmp(nick,
		       list[i].nickname,
		       MAX_NAME_LEN-8))
	if (! equalsHashCode160(&list[i].namespace,
				ns))
	  unique = NO;
  } else
    unique = NO;

  if (unique) {
    return nick;
  } else {
    char * ret;
    size_t n;

    hash2enc(ns, &enc);
    n = strlen(nick) + 40;
    ret = MALLOC(n);
    SNPRINTF(ret, n, "%s-%s", nick, &enc);
    FREE(nick);
    return ret;    
  } 
}

/**
 * Change our evaluation of a namespace.
 * @param delta by how much should the evaluation be changed?
 * @return the new ranking for this namespace
 */
int evaluateNamespace(const HashCode160 * ns,
		      int delta) {
  int * eval;
  int value;
  int ret;
  char * name;
  EncName ename;

  hash2enc(ns, &ename);
  name = MALLOC(256);
  SNPRINTF(name, 256, "%s-%s", NS_HANDLE, (char*) &ename);
  eval = NULL;
  ret = stateReadContent(name, (void**) &eval);
  if (ret == -1) {
    eval = MALLOC(sizeof(int));
    *eval = htonl(0);
  }
  value = ntohl(*eval);
  value += delta;
  if (value == 0) {
    stateUnlinkFromDB(name);
  } else if (delta != 0) {
    *eval = ntohl(value);
    stateWriteContent(name, sizeof(int), eval);
  }
  FREE(eval);
  FREE(name);
  return value;
}

/**
 * Add a namespace to the set of known namespaces.
 * 
 * @param ns the namespace identifier
 */
void addNamespace(const NBlock * ns) {
  NBlock * list;
  int ret;
  unsigned int i;

  if (ntohs(ns->major_formatVersion) != NBLOCK_MAJOR_VERSION) {
    BREAK();
    return;
  }
  list = NULL;
  ret = stateReadContent(NS_HANDLE,
			 (void**)&list);
  if (ret > 0) {
    if ( (ret % sizeof(NBlock)) != 0) {
      FREE(list);
      LOG(LOG_WARNING,
	  _("State DB file '%s' corrupt, deleting contents.\n"),
	  NS_HANDLE);
      stateUnlinkFromDB(NS_HANDLE);
    } else {
      for (i=0;i<ret/sizeof(NBlock);i++) {
	if (0 == memcmp(ns,
			&list[i],
			sizeof(NBlock))) {
	  FREE(list);
	  return; /* seen before */
	}
      }
      FREE(list);
    }
  }
  stateAppendContent(NS_HANDLE,
		     sizeof(NBlock),
		     ns);
}



/**
 * Verify that a given NBlock is well-formed.
 * @param sb the nblock
 */
int verifyNBlock(const NBlock * sb) {
  HashCode160 S;
  HashCode160 Z;
  int ret;

  hash(&sb->subspace,
       sizeof(PublicKey),
       &S);
  if (equalsHashCode160(&sb->namespace,
                        &S)) {
    NBlock * tmp;
    SESSIONKEY skey;
    unsigned char iv[BLOWFISH_BLOCK_LENGTH];

    memset(&Z, 0, sizeof(HashCode160));
    tmp = MALLOC(sizeof(NBlock));
    hashToKey(&Z, &skey, &iv[0]);
    memcpy(tmp, sb, sizeof(NBlock));
    encryptBlock(sb,
                 ENCRYPTED_SIZE,
                 &skey,
                 &iv[0],
                 tmp);
    ret = verifySig(tmp,
                    SIGNED_SIZE,
                    &sb->signature,
                    &sb->subspace);
    FREE(tmp);
  } else {
    ret = verifySig(sb,
                    SIGNED_SIZE,
                    &sb->signature,
                    &sb->subspace);
  }
  if (OK == ret)
    addNamespace(sb);
  return ret;
}

#define MIN(a,b) ( ((a) < (b)) ? (a) : (b) )

/**
 * Build an (encrypted) NBlock.
 */
NBlock * buildNBlock(const PrivateKey pseudonym,
		     const char * nickname,
		     const char * description,
		     const char * realname,
		     const char * mimetype,
		     const char * uri,
		     const char * contact,
		     const HashCode160 * rootEntry) {
  NBlock * result;
  void * tmp;
  SESSIONKEY skey;
  unsigned char iv[BLOWFISH_BLOCK_LENGTH];  
  
  LOG(LOG_DEBUG,
      "Building NBlock %s: %s -- %s\n",
      (nickname != NULL) ? nickname : "",
      (description != NULL) ? description : "",
      (mimetype != NULL) ? mimetype : "");

  result = MALLOC(sizeof(NBlock));
  memset(result, 0, sizeof(NBlock));
  result->major_formatVersion 
    = htons(NBLOCK_MAJOR_VERSION);
  result->minor_formatVersion 
    = htons(NBLOCK_MINOR_VERSION);
  if (rootEntry != NULL)
    result->rootEntry = *rootEntry;
  if (description != NULL)
    memcpy(&result->description[0],
	   description,
	   MIN(strlen(description), MAX_DESC_LEN/2));
  if (nickname != NULL)
    memcpy(&result->nickname[0],
	   nickname,
	   MIN(strlen(nickname), MAX_NAME_LEN-8));
  if (mimetype != NULL)
    memcpy(&result->mimetype[0],
	   mimetype,
	   MIN(strlen(mimetype), MAX_MIMETYPE_LEN/2));
  if (realname != NULL)
    memcpy(&result->realname[0],
	   realname,
	   MIN(strlen(realname), MAX_NAME_LEN));
  if (uri != NULL)
    memcpy(&result->uri[0],
	   uri,
	   MIN(strlen(uri), MAX_CONTACT_LEN));
  if (contact != NULL)
    memcpy(&result->contact[0],
	   contact,
	   MIN(strlen(contact), MAX_CONTACT_LEN));
  getPublicKey(pseudonym,
	       &result->subspace);
  hash(&result->subspace,
       sizeof(PublicKey),
       &result->namespace);

  hashToKey(&result->identifier, &skey, &iv[0]);
  tmp = MALLOC(ENCRYPTED_SIZE);
  encryptBlock(result,
	       ENCRYPTED_SIZE,
	       &skey,
	       &iv[0],
	       tmp);
  memcpy(result,
	 tmp, 
	 ENCRYPTED_SIZE);
  FREE(tmp);
  if (OK != sign(pseudonym,
		 SIGNED_SIZE,
		 result,
		 &result->signature)) {
    FREE(result);
    return NULL;
  }  
  return result;
}

/**
 * Print the information contained in an NBlock.
 * 
 * @param stream where to print the information to
 * @param sb the NBlock -- in plaintext.
 */
void printNBlock(void * swrap,
		 const NBlock * sb) {
  FILE * stream;
  char * s;

  stream = (FILE*) swrap;
  s = rootNodeToString((const RootNode*) sb);
  fprintf(stream,
	  "%s\n",
	  s);
  FREE(s);
}


/* end of nblock.c */
