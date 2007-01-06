/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2005, 2006 Christian Grothoff (and other contributing authors)

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

#include "hostkey.h"
#include "gnunet_directories.h"
#include "platform.h"

#define EXTRA_CHECKS ALLOW_EXTRA_CHECKS

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
static PublicKey publicKey;

/**
 * Get the public key of the host
 *
 * @return reference to the public key. Do not free it!
 */
const PublicKey * getPublicPrivateKey() {
  return &publicKey;
}

/**
 * Sign arbitrary data. ALWAYS use only on data we generated
 * entirely!
 * @return SYSERR on error, OK on success
 */
int signData(const void * data,
	     unsigned short size,
	     Signature * result) {
  int ret;

  ret = sign(hostkey,
	     size,
	     data,
	     result);
#if EXTRA_CHECKS
  if (ret == OK) {
    GE_ASSERT(NULL,
	      OK == verifySig(data,
			      size,
			      result,
			      &publicKey));
  }
#endif
  return ret;
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

void initPrivateKey(struct GE_Context * ectx,
		    struct GC_Configuration * cfg) {
  char * gnHome;
  char * hostkeyfile;
  PrivateKeyEncoded * encPrivateKey;
  unsigned short len;
  int res;

  GE_ASSERT(ectx,
	    -1 != GC_get_configuration_value_filename(cfg,
						      "GNUNETD",
						      "GNUNETD_HOME",
						      VAR_DAEMON_DIRECTORY,
						      &gnHome));
  disk_directory_create(ectx,
			gnHome);
  if (YES != disk_directory_test(ectx,
				 gnHome)) {
    GE_LOG(ectx,
	   GE_FATAL | GE_ADMIN | GE_USER | GE_IMMEDIATE,
	   _("Failed to access GNUnet home directory `%s'\n"),
	   gnHome);
    abort();
  }

  /* read or create public key */
  hostkeyfile = MALLOC(strlen(gnHome) + strlen(HOSTKEYFILE)+2);
  strcpy(hostkeyfile, gnHome);
  FREE(gnHome);
  if (hostkeyfile[strlen(hostkeyfile)-1] != DIR_SEPARATOR)
    strcat(hostkeyfile, DIR_SEPARATOR_STR);
  strcat(hostkeyfile, HOSTKEYFILE);
  res = 0;
  if (YES == disk_file_test(ectx,
			    hostkeyfile)) {
    res = disk_file_read(ectx,
			 hostkeyfile,
			 sizeof(unsigned short),
			 &len);
  } else {
    printf("Could not read host key at `%s', generating fresh key.\n",
	   hostkeyfile);
  }
  encPrivateKey = NULL;
  if (res == sizeof(unsigned short)) {
    encPrivateKey = (PrivateKeyEncoded*) MALLOC(ntohs(len));
    if (ntohs(len) !=
	disk_file_read(ectx,
		       hostkeyfile,
		       ntohs(len),
		       encPrivateKey)) {
      FREE(encPrivateKey);
      GE_LOG(ectx,
	     GE_WARNING | GE_USER | GE_IMMEDIATE | GE_ADMIN,
	     _("Existing hostkey in file `%s' failed format check, creating new hostkey.\n"),
	     hostkeyfile);
      encPrivateKey = NULL;
    }
  }
  if (encPrivateKey == NULL) { /* make new hostkey */
    GE_LOG(ectx,
	   GE_INFO | GE_USER | GE_BULK,
	   _("Creating new hostkey (this may take a while).\n"));
    hostkey = makePrivateKey();
    GE_ASSERT(ectx, hostkey != NULL);
    encPrivateKey = encodePrivateKey(hostkey);
    GE_ASSERT(ectx, encPrivateKey != NULL);
    disk_file_write(ectx,
		    hostkeyfile,
		    encPrivateKey,
		    ntohs(encPrivateKey->len),
		    "600");
    FREE(encPrivateKey);
    GE_LOG(ectx,
	   GE_INFO | GE_USER | GE_BULK,
	   _("Done creating hostkey.\n"));
  } else {
    hostkey = decodePrivateKey(encPrivateKey);
    FREE(encPrivateKey);
  }
  FREE(hostkeyfile);
  GE_ASSERT(ectx, hostkey != NULL);
  getPublicKey(hostkey,
	       &publicKey);
}


void donePrivateKey() {
  GE_ASSERT(NULL, hostkey != NULL);
  freePrivateKey(hostkey);
  hostkey = NULL;
}

/* end of hostkey.c */
