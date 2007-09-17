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

#define STRONG YES
#define WEAK NO

/**
 * @brief length of the sessionkey in bytes (256 BIT sessionkey)
 */
#define SESSIONKEY_LEN (256/8)

/**
 * @brief Length of RSA encrypted data (2048 bit)
 *
 * We currently do not handle encryption of data
 * that can not be done in a single call to the
 * RSA methods (read: large chunks of data).
 * We should never need that, as we can use
 * the hash for larger pieces of data for signing,
 * and for encryption, we only need to encode sessionkeys!
 */
#define RSA_ENC_LEN 256

/**
 * Length of an RSA KEY (d,e,len), 2048 bit (=256 octests) key d, 2 byte e
 */
#define RSA_KEY_LEN 258

/**
 * The private information of an RSA key pair.
 */
struct PrivateKey;

/**
 * @brief 0-terminated ASCII encoding of a HashCode512.
 */
typedef struct
{
  unsigned char encoding[104];
} EncName;

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
} PrivateKeyEncoded;

/**
 * @brief an RSA signature
 */
typedef struct
{
  unsigned char sig[RSA_ENC_LEN];
} Signature;

/**
 * @brief A public key.
 */
typedef struct
{
  /**
   * In big-endian, must be RSA_KEY_LEN+4
   */
  unsigned short len;
  /**
   * Size of n in key; in big-endian!
   */
  unsigned short sizen;
  /**
   * The key itself, contains n followed by e.
   */
  unsigned char key[RSA_KEY_LEN];
  /**
   * Padding (must be 0)
   */
  unsigned short padding;
} PublicKey;

/**
 * RSA Encrypted data.
 */
typedef struct
{
  unsigned char encoding[RSA_ENC_LEN];
} RSAEncryptedData;

/**
 * @brief type for session keys
 */
typedef struct
{
  unsigned char key[SESSIONKEY_LEN];
  int crc32;                    /* checksum! */
} SESSIONKEY;

/**
 * @brief IV for sym cipher
 *
 * NOTE: must be smaller (!) in size than the
 * HashCode512.
 */
typedef struct
{
  unsigned char iv[SESSIONKEY_LEN / 2];
} INITVECTOR;

/* **************** Functions and Macros ************* */

/**
 * Compute the CRC32 checksum for the first len
 * bytes of the buffer.
 *
 * @param buf the data over which we're taking the CRC
 * @param len the length of the buffer in bytes
 * @return the resulting CRC32 checksum
 */
int crc32N (const void *buf, int len);

/**
 * Produce a random value.
 *
 * @param i the upper limit (exclusive) for the random number
 * @return a random value in the interval [0,i[.
 */
unsigned int randomi (unsigned int i);

/**
 * Random on unsigned 64-bit values.  We break them down into signed
 * 32-bit values and reassemble the 64-bit random value bit-wise.
 */
unsigned long long randomi64 (unsigned long long u);

unsigned long long weak_randomi64 (unsigned long long u);

/**
 * Get an array with a random permutation of the
 * numbers 0...n-1.
 * @param mode STRONG if the strong (but expensive) PRNG should be used, WEAK otherwise
 * @param n the size of the array
 * @return the permutation array (allocated from heap)
 */
int *permute (int mode, int n);

/**
 * Produce a cryptographically weak random value.
 *
 * @param i the upper limit (exclusive) for the random number
 * @return a random value in the interval [0,i[.
 */
unsigned int weak_randomi (unsigned int i);

/**
 * Create a new Session key.
 */
void makeSessionkey (SESSIONKEY * key);

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
int encryptBlock (const void *block,
                  unsigned short len,
                  const SESSIONKEY * sessionkey,
                  const INITVECTOR * iv, void *result);

/**
 * Decrypt a given block with the sessionkey.
 * @param sessionkey the key used to decrypt
 * @param block the data to decrypt, encoded as returned by encrypt
 * @param size how big is the block?
 * @param iv the initialization vector to use
 * @param result address to store the result at
 * @return -1 on failure, size of decrypted block on success
 */
int decryptBlock (const SESSIONKEY * sessionkey,
                  const void *block,
                  unsigned short size, const INITVECTOR * iv, void *result);

/**
 * Convert hash to ASCII encoding.
 * @param block the hash code
 * @param result where to store the encoding (EncName can be
 *  safely cast to char*, a '\0' termination is set).
 */
void hash2enc (const HashCode512 * block, EncName * result);

/**
 * Convert ASCII encoding back to hash
 * @param enc the encoding
 * @param result where to store the hash code
 * @return OK on success, SYSERR if result has the wrong encoding
 */
int enc2hash (const char *enc, HashCode512 * result);

/**
 * Compute the distance between 2 hashcodes.
 * The computation must be fast, not involve
 * a.a or a.e (they're used elsewhere), and
 * be somewhat consistent. And of course, the
 * result should be a positive number.
 * @return number between 0 and 65536
 */
unsigned int distanceHashCode512 (const HashCode512 * a,
                                  const HashCode512 * b);

/**
 * compare two hashcodes.
 */
int equalsHashCode512 (const HashCode512 * a, const HashCode512 * b);

/**
 * Hash block of given size.
 * @param block the data to hash, length is given as a second argument
 * @param ret pointer to where to write the hashcode
 */
void hash (const void *block, unsigned int size, HashCode512 * ret);


/**
 * Compute the hash of an entire file.
 * @return OK on success, SYSERR on error
 */
int getFileHash (struct GE_Context *ectx,
                 const char *filename, HashCode512 * ret);

void makeRandomId (HashCode512 * result);

/* compute result(delta) = b - a */
void deltaId (const HashCode512 * a,
              const HashCode512 * b, HashCode512 * result);

/* compute result(b) = a + delta */
void addHashCodes (const HashCode512 * a,
                   const HashCode512 * delta, HashCode512 * result);

/* compute result = a ^ b */
void xorHashCodes (const HashCode512 * a,
                   const HashCode512 * b, HashCode512 * result);

/**
 * Convert a hashcode into a key.
 */
void hashToKey (const HashCode512 * hc, SESSIONKEY * skey, INITVECTOR * iv);

/**
 * Obtain a bit from a hashcode.
 * @param code the hash to index bit-wise
 * @param bit index into the hashcode, [0...159]
 * @return Bit \a bit from hashcode \a code, -1 for invalid index
 */
int getHashCodeBit (const HashCode512 * code, unsigned int bit);

/**
 * Compare function for HashCodes, producing a total ordering
 * of all hashcodes.
 * @return 1 if h1 > h2, -1 if h1 < h2 and 0 if h1 == h2.
 */
int hashCodeCompare (const HashCode512 * h1, const HashCode512 * h2);

/**
 * Find out which of the two hash codes is closer to target
 * in the XOR metric (Kademlia).
 * @return -1 if h1 is closer, 1 if h2 is closer and 0 if h1==h2.
 */
int hashCodeCompareDistance (const HashCode512 * h1,
                             const HashCode512 * h2,
                             const HashCode512 * target);

/**
 * create a new hostkey. Callee must free return value.
 */
struct PrivateKey *makePrivateKey (void);

/**
 * Deterministically (!) create a hostkey using only the
 * given HashCode as input to the PRNG.
 */
struct PrivateKey *makeKblockKey (const HashCode512 * input);

/**
 * Free memory occupied by hostkey
 * @param hostkey pointer to the memory to free
 */
void freePrivateKey (struct PrivateKey *hostkey);

/**
 * Extract the public key of the host.
 * @param result where to write the result.
 */
void getPublicKey (const struct PrivateKey *hostkey, PublicKey * result);

/**
 * Encode the private key in a format suitable for
 * storing it into a file.
 * @param hostkey the hostkey to use
 * @returns encoding of the private key.
 */
PrivateKeyEncoded *encodePrivateKey (const struct PrivateKey *hostkey);

/**
 * Decode the private key from the file-format back
 * to the "normal", internal, RSA format.
 * @param encoded the encoded hostkey
 * @returns the decoded hostkey
 */
struct PrivateKey *decodePrivateKey (const PrivateKeyEncoded * encoding);

/**
 * Encrypt a block with the public key of another host that uses the
 * same cyper.
 *
 * @param block the block to encrypt
 * @param size the size of block
 * @param publicKey the encoded public key used to encrypt
 * @param target where to store the encrypted block
 * @returns SYSERR on error, OK if ok
 */
int encryptPrivateKey (const void *block,
                       unsigned short size,
                       const PublicKey * publicKey,
                       RSAEncryptedData * target);

/**
 * Decrypt a given block with the hostkey.
 *
 * @param key the key to use
 * @param block the data to decrypt, encoded as returned by encrypt, not consumed
 * @param result pointer to a location where the result can be stored
 * @param size how many bytes of a result are expected? Must be exact.
 * @returns the size of the decrypted block (that is, size) or -1 on error
 */
int decryptPrivateKey (const struct PrivateKey *key,
                       const RSAEncryptedData * block,
                       void *result, unsigned short size);

/**
 * Sign a given block.
 *
 * @param block the data to sign, first unsigned short_SIZE bytes give length
 * @param size how many bytes to sign
 * @param result where to write the signature
 * @return SYSERR on error, OK on success
 */
int sign (const struct PrivateKey *key,
          unsigned short size, const void *block, Signature * result);

/**
 * Verify signature.
 * @param block the signed data
 * @param len the length of the block
 * @param sig signature
 * @param publicKey public key of the signer
 * @returns OK if ok, SYSERR if invalid
 */
int verifySig (const void *block,
               unsigned short len,
               const Signature * sig, const PublicKey * publicKey);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_UTIL_CRYPTO_H */
#endif
/* end of gnunet_util_crypto.h */
