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
 * @file applications/afs/esed2/pseudonym.c
 * @brief functions for handling pseudonyms
 * @author Christian Grothoff
 */

#include "gnunet_afs_esed2.h"
#include "platform.h"

#define PSEUDODIR "data/pseudonyms/"

static char * getPseudonymFileName(const char * name) {
  char * gnHome;
  char * fileName;
  
  gnHome = getFileName("",
                       "GNUNET_HOME",
                       _("Configuration file must specify a directory for GNUnet to store per-peer data under %s%s.\n"));
  fileName = MALLOC(strlen(gnHome) + strlen(PSEUDODIR) + strlen(name) + 2);
  strcpy(fileName, gnHome);
  FREE(gnHome);
  strcat(fileName, "/");
  strcat(fileName, PSEUDODIR);
  mkdirp(fileName);
  strcat(fileName, name);
  return fileName;
}

/**
 * Create a new pseudonym. 
 *
 * @param name the name of the pseudonym
 * @param password passphrase to encrypt the pseudonym on disk (may be NULL)
 * @return NULL on error (e.g. pseudonym exists), otherwise the secret key
 */
PrivateKey createPseudonym(const char * name,
			const char * password) {
  char * fileName;
  char tmp;
  PrivateKey hk;
  PrivateKeyEncoded * hke;
  char * dst;
  unsigned short len;

  fileName = getPseudonymFileName(name);
  if (1 == readFile(fileName, 1, &tmp)) {
    LOG(LOG_WARNING,
	_("Cannot create pseudonym '%s', file '%s' exists.\n"),
	name,
	fileName);
    FREE(fileName);
    return NULL;
  }
  hk = makePrivateKey();
  hke = encodePrivateKey(hk);
  len = ntohs(hke->len);
  if (password != NULL) {
    SESSIONKEY key;
    HashCode160 hc;
    char iv[BLOWFISH_BLOCK_LENGTH];
    memcpy(&iv[0],
	   INITVALUE,
	   BLOWFISH_BLOCK_LENGTH);
    hash(password,
	 strlen(password),
	 &hc);
    memcpy(&key,
	   &hc,
	   sizeof(SESSIONKEY));
    dst = MALLOC(len);
    if (len != encryptBlock(hke,
			    len,
			    &key,
			    &iv[0],
			    dst)) {
      FREE(dst);
      freePrivateKey(hk);
      FREE(fileName);
      return NULL;
    }
    FREE(hke);
  } else
    dst = (char*) hke;
  writeFile(fileName,
	    dst,
	    len,
	    "600");
  FREE(fileName);
  FREE(dst);  

  return hk;
}

/**
 * Delete a pseudonym.
 * 
 * @param name the name of the pseudonym
 * @return OK on success, SYSERR on error
 */
int deletePseudonym(const char * name) {
  char * fileName;

  fileName = getPseudonymFileName(name);
  if (0 != UNLINK(fileName)) {
    LOG_FILE_STRERROR(LOG_WARNING, "unlink", fileName);
    FREE(fileName);
    return SYSERR;
  } else {
    FREE(fileName);
    return OK;
  }
}

/**
 * Read pseudonym.
 * 
 * @param name the name of the pseudonym
 * @param password passphrase to encrypt the pseudonym on disk (may be NULL)
 * @return NULL on error (e.g. password invalid, pseudonym does not exist), otherwise the secret key
 */
PrivateKey readPseudonym(const char * name,
		      const char * password) {
  char * fileName;
  PrivateKey hk;
  PrivateKeyEncoded * hke;
  char * dst;
  unsigned short len;

  fileName = getPseudonymFileName(name);
  len = getFileSize(fileName);
  if (len < 2) {
    LOG(LOG_WARNING,
	_("File '%s' does not contain a pseudonym.\n"),
	fileName);
    FREE(fileName);
    return NULL;
  }
  dst = MALLOC(len);
  len = readFile(fileName, len, dst);
  FREE(fileName);
  if (password != NULL) {
    SESSIONKEY key;
    HashCode160 hc;
    char iv[BLOWFISH_BLOCK_LENGTH];
    memcpy(&iv[0],
	   INITVALUE,
	   BLOWFISH_BLOCK_LENGTH);
    hash(password,
	 strlen(password),
	 &hc);
    memcpy(&key,
	   &hc,
	   sizeof(SESSIONKEY));
    hke = MALLOC(len);
    if (len != decryptBlock(&key,
			    dst,
			    len,
			    &iv[0],
			    hke)) {
      FREE(dst);
      LOG(LOG_WARNING,
	  _("Decrypting pseudonym failed.\n"));
      return NULL;
    }
    FREE(dst);
  } else
    hke = (PrivateKeyEncoded*) dst;
  if ( ntohs(hke->len) != len ) {
    /* wrong PW happens A LOT, thus don't always
       print this warning! */
    LOG(LOG_INFO,
	_("Format of pseudonym '%s' is invalid. Wrong password?\n"),
	name);
    FREE(hke);
    return NULL;
  }
  hk = decodePrivateKey(hke);
  FREE(hke);
  return hk;
}


typedef struct {
  int pos;
  int size;
  char ** list;
} PList_;

static void addFile_(char * filename,
		     char * dirName,
		     PList_ * theList) {
  if (theList->pos == theList->size) {
    GROW(theList->list,
	 theList->size,
	 theList->size*2);
  }
  theList->list[theList->pos++] = STRDUP(filename);
}

/**
 * Test if we have any pseudonyms.
 *
 * @return YES if we do have pseudonyms, otherwise NO.
 */
int havePseudonyms() {
  int ret;
  char * dirName;

  dirName = getPseudonymFileName("");
  ret = scanDirectory(dirName,
		      NULL,
		      NULL);
  FREE(dirName);
  if (ret > 0)
    return YES;
  else
    return NO;
}

/**
 * Build a list of all available pseudonyms.
 *
 * @param list where to store the pseudonyms (is allocated, caller frees)
 * @return SYSERR on error, otherwise the number of pseudonyms in list
 */
int listPseudonyms(char *** list) {
  int cnt;
  PList_ myList;
  char * dirName;

  myList.list = NULL;
  myList.size = 0;
  myList.pos = 0;
  GROW(myList.list,
       myList.size,
       8);
  dirName = getPseudonymFileName("");
  cnt = scanDirectory(dirName,
		      (DirectoryEntryCallback)&addFile_,
		      &myList);
  FREE(dirName);
  if (cnt != myList.pos) {
    GROW(myList.list,
	 myList.size,
	 0);
    return SYSERR;
  }
  GROW(myList.list,
       myList.size,
       myList.pos);
  *list = myList.list;
  return myList.pos;
}

/* end of pseudonym.c */
