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
 * @file identity/hostkey.h
 * @brief module encapsulating our secret key for the peer
 *
 * @author Christian Grothoff
 */

#ifndef HOSTKEY_H
#define HOSTKEY_H

#include "gnunet_util.h"

/**
 * Get the public key of the host
 * @return reference to the public key. Do not free it!
 */
const PublicKey * getPublicPrivateKey();

/**
 * Sign arbitrary data. ALWAYS use only on data we generated
 * entirely!
 * @return SYSERR on error, OK on success
 */
int signData(const void * data,
	     unsigned short size,
	     Signature * result);

/**
 * Decrypt a given block with the hostkey.
 * @param block the data to decrypt, encoded as returned by encrypt, not consumed
 * @param result pointer to a location where the result can be stored
 * @param max the maximum number of bits to store for the result, if
 *        the decrypted block is bigger, an error is returned
 * @returns the size of the decrypted block, -1 on error
 */
int decryptData(const RSAEncryptedData * block,
		void * result,
		unsigned int max);




void initPrivateKey();

void donePrivateKey();

#endif
