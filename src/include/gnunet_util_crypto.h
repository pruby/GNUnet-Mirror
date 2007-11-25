/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_util_crypto.h
 * @brief cryptographic primitives for GNUnet
 *
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author Gerd Knorr <kraxel@bytesex.org>
 * @author Ioana Patrascu
 * @author Tzvetan Horozov
 */

#ifndef GNUNET_UTIL_CRYPTO_H
#define GNUNET_UTIL_CRYPTO_H

#include "gnunet_util.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#define GNUNET_RANDOM_QUALITY_STRONG GNUNET_YES
#define GNUNET_RANDOM_QUALITY_WEAK GNUNET_NO

/**
 * @brief length of the sessionkey in bytes (256 BIT sessionkey)
 */
#define GNUNET_SESSIONKEY_LEN (256/8)

/**
 * @brief Length of RSA encrypted data (2048 bit)
 *
 * We currently do not handle encryption of data
 * that can not be done in a single call to the
 * RSA methods (read: large chunks of data).
 * We should never need that, as we can use
 * the GNUNET_hash for larger pieces of data for signing,
 * and for encryption, we only need to encode sessionkeys!
 */
#define GNUNET_RSA_DATA_ENCODING_LEN 256

/**
 * Length of an RSA KEY (d,e,len), 2048 bit (=256 octests) key d, 2 byte e
 */
#define GNUNET_RSA_KEY_LEN 258

/**
 * The private information of an RSA key pair.
 */
struct GNUNET_RSA_PrivateKey;

/**
 * @brief 0-terminated ASCII encoding of a GNUNET_HashCode.
 */
typedef struct
{
  unsigned char encoding[104];
} GNUNET_EncName;

/**
 * GNUnet mandates a certain format for the encoding
 * of private RSA key information that is provided
 * by the RSA implementations.  This format is used
 * to serialize a private RSA key (typically when
 * writing it to disk).
 */
typedef struct
{
  /**
   * Total size of the structure, in bytes, in big-endian!
   */
  unsigned short len;
  unsigned short sizen;         /*  in big-endian! */
  unsigned short sizee;         /*  in big-endian! */
  unsigned short sized;         /*  in big-endian! */
  unsigned short sizep;         /*  in big-endian! */
  unsigned short sizeq;         /*  in big-endian! */
  unsigned short sizedmp1;      /*  in big-endian! */
  unsigned short sizedmq1;      /*  in big-endian! */
  /* followed by the actual values */
} GNUNET_RSA_PrivateKeyEncoded;

/**
 * @brief an RSA signature
 */
typedef struct
{
  unsigned char sig[GNUNET_RSA_DATA_ENCODING_LEN];
} GNUNET_RSA_Signature;

/**
 * @brief A public key.
 */
typedef struct
{
  /**
   * In big-endian, must be GNUNET_RSA_KEY_LEN+4
   */
  unsigned short len;
  /**
   * Size of n in key; in big-endian!
   */
  unsigned short sizen;
  /**
   * The key itself, contains n followed by e.
   */
  unsigned char key[GNUNET_RSA_KEY_LEN];
  /**
   * Padding (must be 0)
   */
  unsigned short padding;
} GNUNET_RSA_PublicKey;

/**
 * RSA Encrypted data.
 */
typedef struct
{
  unsigned char encoding[GNUNET_RSA_DATA_ENCODING_LEN];
} GNUNET_RSA_EncryptedData;

/**
 * @brief type for session keys
 */
typedef struct
{
  unsigned char key[GNUNET_SESSIONKEY_LEN];
  int crc32;                    /* checksum! */
} GNUNET_AES_SessionKey;

/**
 * @brief IV for sym cipher
 *
 * NOTE: must be smaller (!) in size than the
 * GNUNET_HashCode.
 */
typedef struct
{
  unsigned char iv[GNUNET_SESSIONKEY_LEN / 2];
} GNUNET_AES_InitializationVector;

/* **************** Functions and Macros ************* */

/**
 * Compute the CRC32 checksum for the first len
 * bytes of the buffer.
 *
 * @param buf the data over which we're taking the CRC
 * @param len the length of the buffer in bytes
 * @return the resulting CRC32 checksum
 */
int GNUNET_crc32_n (const void *buf, unsigned int len);

/**
 * Produce a random value.
 *
 * @param i the upper limit (exclusive) for the random number
 * @return a random value in the interval [0,i[.
 */
unsigned int GNUNET_random_u32 (int mode, unsigned int i);

/**
 * Random on unsigned 64-bit values.  We break them down into signed
 * 32-bit values and reassemble the 64-bit random value bit-wise.
 */
unsigned long long GNUNET_random_u64 (int mode, unsigned long long u);

/**
 * Get an array with a random permutation of the
 * numbers 0...n-1.
 * @param mode GNUNET_RANDOM_QUALITY_STRONG if the strong (but expensive) PRNG should be used, GNUNET_RANDOM_QUALITY_WEAK otherwise
 * @param n the size of the array
 * @return the permutation array (allocated from heap)
 */
unsigned int *GNUNET_permute (int mode, unsigned int n);

/**
 * Create a new Session key.
 */
void GNUNET_AES_create_session_key (GNUNET_AES_SessionKey * key);

/**
 * Encrypt a block with the public key of another
 * host that uses the same cyper.
 * @param block the block to encrypt
 * @param len the size of the block
 * @param sessionkey the key used to encrypt
 * @param iv the initialization vector to use, use INITVALUE
 *        for streams.
 * @returns the size of the encrypted block, -1 for errors
 */
int GNUNET_AES_encrypt (const void *block,
                        unsigned short len,
                        const GNUNET_AES_SessionKey * sessionkey,
                        const GNUNET_AES_InitializationVector * iv,
                        void *result);

/**
 * Decrypt a given block with the sessionkey.
 * @param sessionkey the key used to decrypt
 * @param block the data to decrypt, encoded as returned by encrypt
 * @param size how big is the block?
 * @param iv the initialization vector to use
 * @param result address to store the result at
 * @return -1 on failure, size of decrypted block on success
 */
int GNUNET_AES_decrypt (const GNUNET_AES_SessionKey * sessionkey,
                        const void *block,
                        unsigned short size,
                        const GNUNET_AES_InitializationVector * iv,
                        void *result);

/**
 * Convert GNUNET_hash to ASCII encoding.
 * @param block the GNUNET_hash code
 * @param result where to store the encoding (GNUNET_EncName can be
 *  safely cast to char*, a '\0' termination is set).
 */
void GNUNET_hash_to_enc (const GNUNET_HashCode * block,
                         GNUNET_EncName * result);

/**
 * Convert ASCII encoding back to GNUNET_hash
 * @param enc the encoding
 * @param result where to store the GNUNET_hash code
 * @return GNUNET_OK on success, GNUNET_SYSERR if result has the wrong encoding
 */
int GNUNET_enc_to_hash (const char *enc, GNUNET_HashCode * result);

/**
 * Compute the distance between 2 hashcodes.
 * The computation must be fast, not involve
 * a.a or a.e (they're used elsewhere), and
 * be somewhat consistent. And of course, the
 * result should be a positive number.
 * @return number between 0 and 65536
 */
unsigned int GNUNET_hash_distance_u32 (const GNUNET_HashCode * a,
                                       const GNUNET_HashCode * b);

/**
 * Hash block of given size.
 * @param block the data to GNUNET_hash, length is given as a second argument
 * @param ret pointer to where to write the hashcode
 */
void GNUNET_hash (const void *block, unsigned int size,
                  GNUNET_HashCode * ret);


/**
 * Compute the GNUNET_hash of an entire file.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_hash_file (struct GNUNET_GE_Context *ectx,
                      const char *filename, GNUNET_HashCode * ret);

void GNUNET_create_random_hash (GNUNET_HashCode * result);

/* compute result(delta) = b - a */
void GNUNET_hash_difference (const GNUNET_HashCode * a,
                             const GNUNET_HashCode * b,
                             GNUNET_HashCode * result);

/* compute result(b) = a + delta */
void GNUNET_hash_sum (const GNUNET_HashCode * a,
                      const GNUNET_HashCode * delta,
                      GNUNET_HashCode * result);

/* compute result = a ^ b */
void GNUNET_hash_xor (const GNUNET_HashCode * a,
                      const GNUNET_HashCode * b, GNUNET_HashCode * result);

/**
 * Convert a hashcode into a key.
 */
void GNUNET_hash_to_AES_key (const GNUNET_HashCode * hc,
                             GNUNET_AES_SessionKey * skey,
                             GNUNET_AES_InitializationVector * iv);

/**
 * Obtain a bit from a hashcode.
 * @param code the GNUNET_hash to index bit-wise
 * @param bit index into the hashcode, [0...159]
 * @return Bit \a bit from hashcode \a code, -1 for invalid index
 */
int GNUNET_hash_get_bit (const GNUNET_HashCode * code, unsigned int bit);

/**
 * Compare function for HashCodes, producing a total ordering
 * of all hashcodes.
 * @return 1 if h1 > h2, -1 if h1 < h2 and 0 if h1 == h2.
 */
int GNUNET_hash_cmp (const GNUNET_HashCode * h1, const GNUNET_HashCode * h2);

/**
 * Find out which of the two GNUNET_hash codes is closer to target
 * in the XOR metric (Kademlia).
 * @return -1 if h1 is closer, 1 if h2 is closer and 0 if h1==h2.
 */
int GNUNET_hash_xorcmp (const GNUNET_HashCode * h1,
                        const GNUNET_HashCode * h2,
                        const GNUNET_HashCode * target);

/**
 * create a new hostkey. Callee must free return value.
 */
struct GNUNET_RSA_PrivateKey *GNUNET_RSA_create_key (void);

/**
 * Deterministically (!) create a hostkey using only the
 * given HashCode as input to the PRNG.
 */
struct GNUNET_RSA_PrivateKey *GNUNET_RSA_create_key_from_hash (const
                                                               GNUNET_HashCode
                                                               * input);

/**
 * Free memory occupied by hostkey
 * @param hostkey pointer to the memory to free
 */
void GNUNET_RSA_free_key (struct GNUNET_RSA_PrivateKey *hostkey);

/**
 * Extract the public key of the host.
 * @param result where to write the result.
 */
void GNUNET_RSA_get_public_key (const struct GNUNET_RSA_PrivateKey *hostkey,
                                GNUNET_RSA_PublicKey * result);

/**
 * Encode the private key in a format suitable for
 * storing it into a file.
 * @param hostkey the hostkey to use
 * @returns encoding of the private key.
 */
GNUNET_RSA_PrivateKeyEncoded *GNUNET_RSA_encode_key (const struct
                                                     GNUNET_RSA_PrivateKey
                                                     *hostkey);

/**
 * Decode the private key from the file-format back
 * to the "normal", internal, RSA format.
 * @param encoded the encoded hostkey
 * @returns the decoded hostkey
 */
struct GNUNET_RSA_PrivateKey *GNUNET_RSA_decode_key (const
                                                     GNUNET_RSA_PrivateKeyEncoded
                                                     * encoding);

/**
 * Encrypt a block with the public key of another host that uses the
 * same cyper.
 *
 * @param block the block to encrypt
 * @param size the size of block
 * @param publicKey the encoded public key used to encrypt
 * @param target where to store the encrypted block
 * @returns GNUNET_SYSERR on error, GNUNET_OK if ok
 */
int GNUNET_RSA_encrypt (const void *block,
                        unsigned short size,
                        const GNUNET_RSA_PublicKey * publicKey,
                        GNUNET_RSA_EncryptedData * target);

/**
 * Decrypt a given block with the hostkey.
 *
 * @param key the key to use
 * @param block the data to decrypt, encoded as returned by encrypt, not consumed
 * @param result pointer to a location where the result can be stored
 * @param size how many bytes of a result are expected? Must be exact.
 * @returns the size of the decrypted block (that is, size) or -1 on error
 */
int GNUNET_RSA_decrypt (const struct GNUNET_RSA_PrivateKey *key,
                        const GNUNET_RSA_EncryptedData * block,
                        void *result, unsigned short size);

/**
 * Sign a given block.
 *
 * @param block the data to GNUNET_RSA_sign, first unsigned short_SIZE bytes give length
 * @param size how many bytes to GNUNET_RSA_sign
 * @param result where to write the signature
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int GNUNET_RSA_sign (const struct GNUNET_RSA_PrivateKey *key,
                     unsigned short size, const void *block,
                     GNUNET_RSA_Signature * result);

/**
 * Verify signature.
 * @param block the signed data
 * @param len the length of the block
 * @param sig signature
 * @param publicKey public key of the signer
 * @returns GNUNET_OK if ok, GNUNET_SYSERR if invalid
 */
int GNUNET_RSA_verify (const void *block,
                       unsigned short len,
                       const GNUNET_RSA_Signature * sig,
                       const GNUNET_RSA_PublicKey * publicKey);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_UTIL_CRYPTO_H */
#endif
/* end of gnunet_util_crypto.h */
