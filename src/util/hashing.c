/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file util/hashing.c
 * @brief RIPE160MD hash related functions
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "platform.h"

#if ! (USE_OPENSSL || USE_GCRYPT)
#error Must use OpenSSL or libgcrypt
#endif

#if USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ripemd.h>
#endif

#if USE_GCRYPT
#include <gcrypt.h>
#include "locking_gcrypt.h"
#endif

/**
 * Hash block of given size.
 * @param block the data to hash, length is given as a second argument
 * @param size the length of the data to hash
 * @param ret pointer to where to write the hashcode
 */
void hash(const void * block,
	  int size,
	  HashCode160 * ret) {
#if USE_OPENSSL
  RIPEMD160(block, size, (unsigned char*) ret);
#endif
#if USE_GCRYPT
  lockGcrypt();
  gcry_md_hash_buffer(GCRY_MD_RMD160,
		      (char*) ret,
		      block,
		      size);
  unlockGcrypt();
#endif
}

/**
 * Compute the hash of an entire file.  Does NOT load the entire file
 * into memory but instead processes it in blocks.  Very important for
 * large files.
 *
 * @return OK on success, SYSERR on error
 */
int getFileHash(const char * filename,
		HashCode160 * ret) {
  char * buf;
  unsigned int len;
  unsigned int pos;
  unsigned int delta;
  int fh;
#if USE_GCRYPT
  gcry_md_hd_t hd;
  char * res;

  lockGcrypt();
  if (0 != gcry_md_open(&hd,
						GCRY_MD_RMD160,
						0)) {
	unlockGcrypt();
    return SYSERR;
  }
#endif
#if USE_OPENSSL
  RIPEMD160_CTX hd;  
  RIPEMD160_Init(&hd);
#endif

  fh = OPEN(filename, O_RDONLY);
  if (fh == -1) {
#if USE_GCRYPT
    gcry_md_close(hd);
	unlockGcrypt();
#endif
#if USE_OPENSSL
    RIPEMD160_Final((unsigned char*)ret,
		    &hd);
#endif
    return SYSERR;
  }
  pos = 0;
  buf = MALLOC(65536);
  len = getFileSize(filename);
  while (pos < len) {
    delta = 65536;
    if (len - pos < delta)
      delta = len-pos;
    if (delta != READ(fh,
		      buf,
		      delta)) {
      CLOSE(fh);
#if USE_GCRYPT
      gcry_md_close(hd);
	  unlockGcrypt();
#endif
#if USE_OPENSSL
      RIPEMD160_Final((unsigned char*)ret,
		      &hd);
#endif
      FREE(buf);
      return SYSERR;
    }
#if USE_GCRYPT  
    gcry_md_write(hd,
		  buf,
		  delta);
#endif
#if USE_OPENSSL
    RIPEMD160_Update(&hd,
		     buf,
		     delta);
#endif
    pos += delta;
  }
  CLOSE(fh);
#if USE_GCRYPT
  res = gcry_md_read(hd, 0);
  memcpy(ret,
	 res,
	 sizeof(HashCode160));
  gcry_md_close(hd);
  unlockGcrypt();
#endif
#if USE_OPENSSL
  RIPEMD160_Final((unsigned char*)ret,
		  &hd);
#endif
  FREE(buf);
  return OK;
}

/* ***************** binary-ASCII encoding *************** */

/**
 * 32 characters for encoding (hash => 32 characters)
 */
static unsigned char * encTable__ = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

static unsigned int getValue__(unsigned char a) {
  if ( (a >= '0') && (a <= '9') ) 
    return a - '0';
  if ( (a >= 'A') && (a <= 'V') )
    return (a - 'A' + 10);
  return -1;
}

/**
 * Convert hash to ASCII encoding.  The ASCII encoding is rather
 * GNUnet specific.  It was chosen such that it only uses characters
 * in [0-9A-Z], can be produced without complex arithmetics and
 * uses a small number of characters.  The theoretical limit is 28
 * characters, the GNUnet encoding uses 32 and is thus pretty close.
 *
 * @param block the hash code
 * @param result where to store the encoding (EncName can be
 *  safely cast to char*, a '\0' termination is set).
 */
void hash2enc(const HashCode160 * block,
	      EncName * result) {
  unsigned long long v1;
  unsigned long long v2;
  unsigned long long v3;

  GNUNET_ASSERT(sizeof(EncName) == 33);
  GNUNET_ASSERT(strlen(encTable__) == 32);
  v1 = (((unsigned long long) (unsigned int) block->a) << 32) + 
        (unsigned long long) (unsigned int) block->b;
  result->encoding[0] = encTable__[v1 & 31]; v1 >>= 5;
  result->encoding[1] = encTable__[v1 & 31]; v1 >>= 5;
  result->encoding[2] = encTable__[v1 & 31]; v1 >>= 5;
  result->encoding[3] = encTable__[v1 & 31]; v1 >>= 5;
  result->encoding[4] = encTable__[v1 & 31]; v1 >>= 5;
  result->encoding[5] = encTable__[v1 & 31]; v1 >>= 5;
  result->encoding[6] = encTable__[v1 & 31]; v1 >>= 5;
  result->encoding[7] = encTable__[v1 & 31]; v1 >>= 5;
  result->encoding[8] = encTable__[v1 & 31]; v1 >>= 5;
  result->encoding[9] = encTable__[v1 & 31]; v1 >>= 5; 
  result->encoding[10] = encTable__[v1 & 31]; v1 >>= 5; 
  result->encoding[11] = encTable__[v1 & 31]; v1 >>= 5; 
  v2 = (((unsigned long long) (unsigned int) block->c) << 32) + 
         (unsigned long long) (unsigned int) block->d;
  result->encoding[13] = encTable__[v2 & 31]; v2 >>= 5;
  result->encoding[14] = encTable__[v2 & 31]; v2 >>= 5;
  result->encoding[15] = encTable__[v2 & 31]; v2 >>= 5;
  result->encoding[16] = encTable__[v2 & 31]; v2 >>= 5;
  result->encoding[17] = encTable__[v2 & 31]; v2 >>= 5;
  result->encoding[18] = encTable__[v2 & 31]; v2 >>= 5;
  result->encoding[19] = encTable__[v2 & 31]; v2 >>= 5; 
  result->encoding[20] = encTable__[v2 & 31]; v2 >>= 5;
  result->encoding[21] = encTable__[v2 & 31]; v2 >>= 5;
  result->encoding[22] = encTable__[v2 & 31]; v2 >>= 5;
  result->encoding[23] = encTable__[v2 & 31]; v2 >>= 5;
  result->encoding[24] = encTable__[v2 & 31]; v2 >>= 5;

  v3 = (unsigned long long) (unsigned int) block->e; 
  result->encoding[26] = encTable__[v3 & 31]; v3 >>= 5;
  result->encoding[27] = encTable__[v3 & 31]; v3 >>= 5;
  result->encoding[28] = encTable__[v3 & 31]; v3 >>= 5;
  result->encoding[29] = encTable__[v3 & 31]; v3 >>= 5; 
  result->encoding[30] = encTable__[v3 & 31]; v3 >>= 5;
  result->encoding[31] = encTable__[v3 & 31]; v3 >>= 5;

  v1 |= (v3 & 1) << 4; /* use highest bit in v1 */
  v2 |= (v3 & 2) << 3; /* use highest bit in v2 */
  result->encoding[12] = encTable__[v1 & 31]; 
  result->encoding[25] = encTable__[v2 & 31]; 
  result->encoding[32] = '\0';
}


/**
 * Convert ASCII encoding back to hash
 * @param enc the encoding
 * @param result where to store the hash code 
 * @return OK on success, SYSERR if result has the wrong encoding
 */
int enc2hash(const char * enc,
	     HashCode160 * result) {
  unsigned long long v;
  int pos;
 
  GNUNET_ASSERT(sizeof(EncName) == 33);
  if (strlen(enc) != sizeof(EncName)-1)
    return SYSERR;
  for (pos=strlen(enc)-1;pos>=0;pos--) {
    if (-1 == getValue__(enc[pos]))
      return SYSERR;
#if EXPENSIVE_CHECKS
    GNUNET_ASSERT((encTable__[getValue__(enc[pos])] == enc[pos]));
#endif
  }

  v = getValue__(enc[12]);
  v <<= 5; v+= getValue__(enc[11]);
  v <<= 5; v+= getValue__(enc[10]);
  v <<= 5; v+= getValue__(enc[9]);
  v <<= 5; v+= getValue__(enc[8]);
  v <<= 5; v+= getValue__(enc[7]);
  v <<= 5; v+= getValue__(enc[6]);
  v <<= 5; v+= getValue__(enc[5]);
  v <<= 5; v+= getValue__(enc[4]);
  v <<= 5; v+= getValue__(enc[3]);
  v <<= 5; v+= getValue__(enc[2]);
  v <<= 5; v+= getValue__(enc[1]);
  v <<= 5; v+= getValue__(enc[0]);
  result->a = (unsigned int)(v >> 32);
  result->b = (unsigned int) v;

  v = getValue__(enc[25]);
  v <<= 5; v+= getValue__(enc[24]);
  v <<= 5; v+= getValue__(enc[23]);
  v <<= 5; v+= getValue__(enc[22]);
  v <<= 5; v+= getValue__(enc[21]);
  v <<= 5; v+= getValue__(enc[20]);
  v <<= 5; v+= getValue__(enc[19]);
  v <<= 5; v+= getValue__(enc[18]);
  v <<= 5; v+= getValue__(enc[17]);
  v <<= 5; v+= getValue__(enc[16]);
  v <<= 5; v+= getValue__(enc[15]);
  v <<= 5; v+= getValue__(enc[14]);
  v <<= 5; v+= getValue__(enc[13]);
  result->c = (unsigned int)(v >> 32);
  result->d = (unsigned int) v;

  /* get lowest two bits from 12 and 25 */
  v = ((getValue__(enc[25]) >> 4) << 1) | (getValue__(enc[12]) >> 4);
  v <<= 5; v+= getValue__(enc[31]);
  v <<= 5; v+= getValue__(enc[30]);
  v <<= 5; v+= getValue__(enc[29]);
  v <<= 5; v+= getValue__(enc[28]);
  v <<= 5; v+= getValue__(enc[27]);
  v <<= 5; v+= getValue__(enc[26]);
  result->e = (unsigned int) v;
  return OK;
}

/**
 * Compute the distance between 2 hashcodes.  The computation must be
 * fast, not involve a.a or a.e (they're used elsewhere), and be
 * somewhat consistent. And of course, the result should be a positive
 * number.
 *
 * @returns a positive number which is a measure for 
 *  hashcode proximity.
 */
int distanceHashCode160(const HashCode160 * a, 
			const HashCode160 * b) {
  int x = (a->b - b->b)>>16;
  return ((x*x)>>16);
}

/**
 * Compare two hashcodes.
 * @return 1 if they are equal, 0 if not.
 */
int equalsHashCode160(const HashCode160 * a, 
		      const HashCode160 * b) {
  return (0 == memcmp(a,b,sizeof(HashCode160)));
}

void makeRandomId(HashCode160 * result) {
  result->a = rand();
  result->b = rand();
  result->c = rand();
  result->d = rand();
  result->e = rand();
}

void deltaId(const HashCode160 * a,
	     const HashCode160 * b,
	     HashCode160 * result) {
  result->a = b->a - a->a;
  result->b = b->b - a->b;
  result->c = b->c - a->c;
  result->d = b->d - a->d;
  result->e = b->e - a->e;
}

void addHashCodes(const HashCode160 * a,
		  const HashCode160 * delta,
		  HashCode160 * result) {
  result->a = delta->a + a->a;
  result->b = delta->b + a->b;
  result->c = delta->c + a->c;
  result->d = delta->d + a->d;
  result->e = delta->e + a->e;
}

void xorHashCodes(const HashCode160 * a,
		  const HashCode160 * b,
		  HashCode160 * result) {
  result->a = b->a ^ a->a;
  result->b = b->b ^ a->b;
  result->c = b->c ^ a->c;
  result->d = b->d ^ a->d;
  result->e = b->e ^ a->e;
}

/**
 * Check if two hosts are the same.
 * @return YES if they are equal, otherwise NO
 */
int hostIdentityEquals(const PeerIdentity * first, 
		       const PeerIdentity * second) {
  if ( (first == NULL) || 
       (second == NULL) )
    return NO;
  return equalsHashCode160(&first->hashPubKey,
			   &second->hashPubKey);
}

/**
 * Convert a hashcode into a key.
 */
void hashToKey(const HashCode160 * hc,
	       SESSIONKEY * skey,
	       INITVECTOR * iv) {
  memcpy(skey,
	 hc,
	 sizeof(SESSIONKEY));
  skey->crc32 = htonl(crc32N(skey, 
			     SESSIONKEY_LEN));
  memcpy(&iv->iv[0], 
	 &(((char *)hc)[sizeof(SESSIONKEY)]), 
	 sizeof(HashCode160) - sizeof(SESSIONKEY));
  GNUNET_ASSERT(sizeof(HashCode160) - sizeof(SESSIONKEY) ==
		sizeof(INITVECTOR) - (sizeof(HashCode160) - sizeof(SESSIONKEY)));
  memcpy(&iv->iv[sizeof(HashCode160) - sizeof(SESSIONKEY)],
	 &(((char *)hc)[sizeof(SESSIONKEY)]), 
	 sizeof(HashCode160) - sizeof(SESSIONKEY));
}


/**
 * Obtain a bit from a hashcode.
 * @param code the hash to index bit-wise
 * @param bit index into the hashcode, [0...159]
 * @return Bit \a bit from hashcode \a code, -1 for invalid index
 */
int getHashCodeBit(const HashCode160 * code,
		   unsigned int bit) {
  if (bit >= 8 * sizeof(HashCode160)) {
    BREAK();
    return -1; /* error */
  }
  return (((unsigned char*)code)[bit >> 3] & (1 << bit & 7)) > 0;
}

/**
 * Compare function for HashCodes, producing a total ordering
 * of all hashcodes.
 * @return 1 if h1 > h2, -1 if h1 < h2 and 0 if h1 == h2.
 */
int hashCodeCompare(const HashCode160 * h1,
		    const HashCode160 * h2) {
  int i;
  int diff;
  /* FIXME: we can do this much more efficiently... */
  for (i = sizeof(HashCode160)*8 - 1; i >= 0; --i) {
    diff = getHashCodeBit(h2, i) - getHashCodeBit(h1, i);
    if (diff < 0) 
      return -1;
    else if (diff > 0)
      return 1;
  }
  return 0;
}

/**
 * Find out which of the two hash codes is closer to target
 * in the XOR metric (Kademlia).
 * @return -1 if h1 is closer, 1 if h2 is closer and 0 if h1==h2.
 */
int hashCodeCompareDistance(const HashCode160 * h1,
			    const HashCode160 * h2,
			    const HashCode160 * target) {
  int i;
#if 0
  int diff;
  int b1, b2, bt;
#endif
  unsigned int d1;
  unsigned int d2;

  for (i=sizeof(HashCode160)/sizeof(unsigned int)-1;i>=0;i--) {
    d1 = ((unsigned int*)h1)[i] ^ ((unsigned int*)target)[i];
    d2 = ((unsigned int*)h2)[i] ^ ((unsigned int*)target)[i];
    if (d1 > d2)
      return 1;
    else if (d1 < d2)
      return -1;
  }
#if 0
  /* Old code: */
  for (i = sizeof(HashCode160) * 8 - 1; i >= 0; --i) {
    b1 = getHashCodeBit(h1, i);
    b2 = getHashCodeBit(h2, i);
    bt = getHashCodeBit(target, i);
    /* Check XOR distance. */
    diff = (b2 ^ bt) - (b1 ^ bt);
    if (diff < 0) 
      return -1;
    else if (diff > 0)
      return 1;
  }
#endif
  return 0;
}

/* end of hashing.c */
