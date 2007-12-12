/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/symcipher_gcrypt.c
 * @brief Symmetric encryption services.
 * @author Christian Grothoff
 * @author Ioana Patrascu
 *
 * Note that the code locks often needlessly on the gcrypt-locking api.
 * One would think that simple MPI operations should not require locking
 * (since only global operations on the random pool must be locked,
 * strictly speaking).  But libgcrypt does sometimes require locking in
 * unexpected places, so the safe solution is to always lock even if it
 * is not required.  The performance impact is minimal anyway.
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_util_crypto.h"
#include "locking_gcrypt.h"
#include <gcrypt.h>

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by gcry_strerror(rc).
 */
#define LOG_GCRY(ectx, level, cmd, rc) do { GNUNET_GE_LOG(ectx, level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, gcry_strerror(rc)); } while(0);

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' with the message given
 * by gcry_strerror(rc).
 */
#define DIE_GCRY(ectx, cmd, rc) do { GNUNET_GE_LOG(ectx, GNUNET_GE_FATAL | GNUNET_GE_USER | GNUNET_GE_DEVELOPER | GNUNET_GE_IMMEDIATE, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, gcry_strerror(rc)); abort(); } while(0);


/**
 * Create a new SessionKey (for AES-256).
 */
void
GNUNET_AES_create_session_key (GNUNET_AES_SessionKey * key)
{
  GNUNET_lock_gcrypt_ ();
  gcry_randomize (&key->key[0], GNUNET_SESSIONKEY_LEN, GCRY_STRONG_RANDOM);
  GNUNET_unlock_gcrypt_ ();
  key->crc32 = htonl (GNUNET_crc32_n (key, GNUNET_SESSIONKEY_LEN));
}

/**
 * Encrypt a block with the public key of another
 * host that uses the same cyper.
 * @param block the block to encrypt
 * @param len the size of the block
 * @param sessionkey the key used to encrypt
 * @param iv the initialization vector to use, use INITVALUE
 *        for streams.
 * @param result the output parameter in which to store the encrypted result
 * @returns the size of the encrypted block, -1 for errors
 */
int
GNUNET_AES_encrypt (const void *block,
                    unsigned short len,
                    const GNUNET_AES_SessionKey * sessionkey,
                    const GNUNET_AES_InitializationVector * iv, void *result)
{
  gcry_cipher_hd_t handle;
  int rc;

  if (sessionkey->crc32 !=
      htonl (GNUNET_crc32_n (sessionkey, GNUNET_SESSIONKEY_LEN)))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  GNUNET_lock_gcrypt_ ();
  rc = gcry_cipher_open (&handle,
                         GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB, 0);
  if (rc)
    {
      LOG_GCRY (NULL,
                GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_DEVELOPER |
                GNUNET_GE_BULK, "gcry_cipher_open", rc);
      GNUNET_unlock_gcrypt_ ();
      return -1;
    }
  rc = gcry_cipher_setkey (handle, sessionkey, GNUNET_SESSIONKEY_LEN);

  if (rc && ((char) rc != GPG_ERR_WEAK_KEY))
    {
      LOG_GCRY (NULL,
                GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_DEVELOPER |
                GNUNET_GE_BULK, "gcry_cipher_setkey", rc);
      gcry_cipher_close (handle);
      GNUNET_unlock_gcrypt_ ();
      return -1;
    }
  rc =
    gcry_cipher_setiv (handle, iv, sizeof (GNUNET_AES_InitializationVector));
  if (rc && ((char) rc != GPG_ERR_WEAK_KEY))
    {
      LOG_GCRY (NULL,
                GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_DEVELOPER |
                GNUNET_GE_BULK, "gcry_cipher_setiv", rc);
      gcry_cipher_close (handle);
      GNUNET_unlock_gcrypt_ ();
      return -1;
    }

  rc = gcry_cipher_encrypt (handle, result, len, block, len);
  if (rc)
    {
      LOG_GCRY (NULL,
                GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_DEVELOPER |
                GNUNET_GE_BULK, "gcry_cipher_encrypt", rc);
      gcry_cipher_close (handle);
      GNUNET_unlock_gcrypt_ ();
      return -1;
    }
  gcry_cipher_close (handle);
  GNUNET_unlock_gcrypt_ ();
  return len;
}

/**
 * Decrypt a given block with the sessionkey.
 * @param sessionkey the key used to decrypt
 * @param block the data to decrypt, encoded as returned by encrypt
 * @param size the size of the block to decrypt
 * @param iv the initialization vector to use, use INITVALUE
 *        for streams.
 * @param result address to store the result at
 * @return -1 on failure, size of decrypted block on success
 */
int
GNUNET_AES_decrypt (const GNUNET_AES_SessionKey * sessionkey,
                    const void *block,
                    unsigned short size,
                    const GNUNET_AES_InitializationVector * iv, void *result)
{
  gcry_cipher_hd_t handle;
  int rc;

  if (sessionkey->crc32 !=
      htonl (GNUNET_crc32_n (sessionkey, GNUNET_SESSIONKEY_LEN)))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  GNUNET_lock_gcrypt_ ();
  rc = gcry_cipher_open (&handle,
                         GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB, 0);
  if (rc)
    {
      LOG_GCRY (NULL,
                GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_DEVELOPER |
                GNUNET_GE_BULK, "gcry_cipher_open", rc);
      GNUNET_unlock_gcrypt_ ();
      return -1;
    }
  rc = gcry_cipher_setkey (handle, sessionkey, GNUNET_SESSIONKEY_LEN);

  if (rc && ((char) rc != GPG_ERR_WEAK_KEY))
    {
      LOG_GCRY (NULL,
                GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_DEVELOPER |
                GNUNET_GE_BULK, "gcry_cipher_setkey", rc);
      gcry_cipher_close (handle);
      GNUNET_unlock_gcrypt_ ();
      return -1;
    }
  rc =
    gcry_cipher_setiv (handle, iv, sizeof (GNUNET_AES_InitializationVector));

  if (rc && ((char) rc != GPG_ERR_WEAK_KEY))
    {
      LOG_GCRY (NULL,
                GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_DEVELOPER |
                GNUNET_GE_BULK, "gcry_cipher_setiv", rc);
      gcry_cipher_close (handle);
      GNUNET_unlock_gcrypt_ ();
      return -1;
    }
  rc = gcry_cipher_decrypt (handle, result, size, block, size);
  if (rc)
    {
      LOG_GCRY (NULL,
                GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_DEVELOPER |
                GNUNET_GE_BULK, "gcry_cipher_decrypt", rc);
      gcry_cipher_close (handle);
      GNUNET_unlock_gcrypt_ ();
      return -1;
    }
  gcry_cipher_close (handle);
  GNUNET_unlock_gcrypt_ ();
  return size;
}

/* end of symcipher_gcrypt.c */
