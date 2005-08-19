/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2005 Christian Grothoff (and other contributing authors)

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
 * @file identity/hostkey.c
 * @brief module encapsulating our secret key for the peer
 *
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "hostkey.h"

/**
 * Name of the file in which we store the hostkey.
 */
#define HOSTKEYFILE ".hostkey"

/**
 * The SECRET hostkey.  Keep local, never export outside of this
 * module!
 */
static struct PrivateKey * hostkey;

/**
 * The public hostkey
 */
static PublicKey * publicKey;

/**
 * Get the public key of the host
 *
 * @return reference to the public key. Do not free it!
 */
const PublicKey * getPublicPrivateKey() {
  return publicKey;
}

/**
 * Sign arbitrary data. ALWAYS use only on data we generated
 * entirely!
 * @return SYSERR on error, OK on success
 */
int signData(const void * data,
	     unsigned short size,
	     Signature * result) {
  return sign(hostkey,
	      size,
	      data,
	      result);
}

/**
 * Decrypt a given block with the hostkey.
 *
 * @param block the data to decrypt, encoded as returned by encrypt, not consumed
 * @param result pointer to a location where the result can be stored
 * @param max the maximum number of bits to store for the result, if
 *        the decrypted block is bigger, an error is returned
 * @returns the size of the decrypted block, -1 on error
 */
int decryptData(const RSAEncryptedData * block,
		void * result,
		unsigned int max) {
  return decryptPrivateKey(hostkey,
			   block,
			   result,
			   max);
}

void initPrivateKey() {
  char * gnHome;
  char * hostkeyfile;
  PrivateKeyEncoded * encPrivateKey;
  unsigned short len;
  int res;

  gnHome = getFileName("GNUNETD",
		       "GNUNETD_HOME",
		       _("Configuration file must specify a "
			 "directory for GNUnet to store "
			 "per-peer data under %s%s\n"));

  /* read or create public key */
  hostkeyfile = MALLOC(strlen(gnHome) + strlen(HOSTKEYFILE)+2);
  strcpy(hostkeyfile, gnHome);
  FREE(gnHome);
  strcat(hostkeyfile, "/");
  strcat(hostkeyfile, HOSTKEYFILE);
  res = readFile(hostkeyfile,
		 sizeof(unsigned short),
		 &len);
  if (res == sizeof(unsigned short)) {
    encPrivateKey = (PrivateKeyEncoded*) MALLOC(ntohs(len));
    if (ntohs(len) !=
	readFile(hostkeyfile,
		 ntohs(len),
		 encPrivateKey)) {
      FREE(encPrivateKey);
      LOG(LOG_WARNING,
	  _("Existing hostkey in file `%s' failed format check, creating new hostkey.\n"),
	  hostkeyfile);
      encPrivateKey = NULL;
    }
  } else
    encPrivateKey = NULL;
  if (encPrivateKey == NULL) { /* make new hostkey */
    LOG(LOG_MESSAGE,
	_("Creating new hostkey (this may take a while).\n"));
    hostkey = makePrivateKey();
    if (hostkey == NULL)
      errexit(_("Could not create hostkey!\n"));
    encPrivateKey = encodePrivateKey(hostkey);
    GNUNET_ASSERT(encPrivateKey != NULL);
    writeFile(hostkeyfile,
	      encPrivateKey,
	      ntohs(encPrivateKey->len),
	      "600");
    FREE(encPrivateKey);
    LOG(LOG_MESSAGE,
	_("Done creating hostkey.\n"));
  } else {
    hostkey = decodePrivateKey(encPrivateKey);
    FREE(encPrivateKey);
  }
  FREE(hostkeyfile);
  if (hostkey != NULL) {
    publicKey = MALLOC(sizeof(PublicKey));
    getPublicKey(hostkey,
		 publicKey);
  } else {
    publicKey = NULL;
  }
}


void donePrivateKey() {
  FREENONNULL(publicKey);
  if (hostkey != NULL)
    freePrivateKey(hostkey);
}

/* end of hostkey.c */
