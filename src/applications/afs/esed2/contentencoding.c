/*
     This file is part of GNUnet.
     (C) 2001, 2002 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/esed2/contentencoding.c
 * @author Christian Grothoff
 * @author Ioana Patrascu
 * 
 * Encryption and decryption of blocks for deniability.
 */

#include "gnunet_afs_esed2.h"
#include "platform.h"

/**
 * Encrypts a given data block
 *
 * @param data represents the data block
 * @param hashcode represents the key concatenated with the initial
 *        value used in the alg
 * @param result where to store the result (encrypted block)
 * @returns OK on success, SYSERR on error
 */
int encryptContent(const CONTENT_Block * data,
		   const HashCode160 * hashcode,
		   CONTENT_Block * result){
  SESSIONKEY skey;
  unsigned char iv[BLOWFISH_BLOCK_LENGTH];  /* initial value */

  GNUNET_ASSERT((data!=NULL) && (hashcode != NULL) && (result != NULL));
  /* get key and init value from the hash code */
  hashToKey(hashcode,
	    &skey,
	    &iv[0]);
  return encryptBlock(data,
		      sizeof(CONTENT_Block),
		      &skey,
		      iv,
		      result);
}

/**
 * Decrypts a given data block
 *
 * @param data represents the data block
 * @param hashcode represents the key concatenated with the initial
 *        value used in the alg
 * @param result where to store the result (encrypted block)
 * @returns OK on success, SYSERR on error
 */
int decryptContent(const CONTENT_Block * data,
		   const HashCode160 * hashcode,
		   CONTENT_Block * result){
  unsigned char iv[BLOWFISH_BLOCK_LENGTH]; /* initial value */
  SESSIONKEY skey;

  GNUNET_ASSERT((data!=NULL) && (hashcode != NULL) && (result != NULL));
  /* get key and init value from the hash code */
  hashToKey(hashcode,
	    &skey,
	    &iv[0]);

  return decryptBlock(&skey,
		      data,
		      sizeof(CONTENT_Block),
		      iv,
		      result);
}

/* end of contentencoding.c */
