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

     SHA-512 code by Jean-Luc Cooke <jlcooke@certainkey.com>

     Copyright (c) Jean-Luc Cooke <jlcooke@certainkey.com>
     Copyright (c) Andrew McDonald <andrew@mcdonald.org.uk>
     Copyright (c) 2003 Kyle McMartin <kyle@debian.org>
*/

/**
 * @file util/hashing.c
 * @brief RIPE160MD hash related functions
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "platform.h"

#define SHA512_DIGEST_SIZE 64
#define SHA512_HMAC_BLOCK_SIZE 128

struct sha512_ctx {
  unsigned long long state[8];
  unsigned int count[4];
  unsigned char buf[128];
};

static unsigned long long Ch(unsigned long long x,
			     unsigned long long y,
			     unsigned long long z) {
  return z ^ (x & (y ^ z));
}

static unsigned long long Maj(unsigned long long x,
			      unsigned long long y,
			      unsigned long long z) {
  return (x & y) | (z & (x | y));
}

static unsigned long long RORu64(unsigned long long x,
				 unsigned long long y) {
  return (x >> y) | (x << (64 - y));
}

const unsigned long long sha512_K[80] = {
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
  0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
  0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
  0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
  0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
  0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
  0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
  0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
  0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
  0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
  0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
  0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
  0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
  0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
  0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
  0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
  0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
  0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
  0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
  0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
  0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

#define e0(x)       (RORu64(x,28) ^ RORu64(x,34) ^ RORu64(x,39))
#define e1(x)       (RORu64(x,14) ^ RORu64(x,18) ^ RORu64(x,41))
#define s0(x)       (RORu64(x, 1) ^ RORu64(x, 8) ^ (x >> 7))
#define s1(x)       (RORu64(x,19) ^ RORu64(x,61) ^ (x >> 6))

/* H* initial state for SHA-512 */
#define H0         0x6a09e667f3bcc908ULL
#define H1         0xbb67ae8584caa73bULL
#define H2         0x3c6ef372fe94f82bULL
#define H3         0xa54ff53a5f1d36f1ULL
#define H4         0x510e527fade682d1ULL
#define H5         0x9b05688c2b3e6c1fULL
#define H6         0x1f83d9abfb41bd6bULL
#define H7         0x5be0cd19137e2179ULL

/* H'* initial state for SHA-384 */
#define HP0 0xcbbb9d5dc1059ed8ULL
#define HP1 0x629a292a367cd507ULL
#define HP2 0x9159015a3070dd17ULL
#define HP3 0x152fecd8f70e5939ULL
#define HP4 0x67332667ffc00b31ULL
#define HP5 0x8eb44a8768581511ULL
#define HP6 0xdb0c2e0d64f98fa7ULL
#define HP7 0x47b5481dbefa4fa4ULL

static void LOAD_OP(int I, unsigned long long *W, const unsigned char *input) {
  unsigned long long t1  = input[(8*I)  ] & 0xff;
  t1 <<= 8;
  t1 |= input[(8*I)+1] & 0xff;
  t1 <<= 8;
  t1 |= input[(8*I)+2] & 0xff;
  t1 <<= 8;
  t1 |= input[(8*I)+3] & 0xff;
  t1 <<= 8;
  t1 |= input[(8*I)+4] & 0xff;
  t1 <<= 8;
  t1 |= input[(8*I)+5] & 0xff;
  t1 <<= 8;
  t1 |= input[(8*I)+6] & 0xff;
  t1 <<= 8;
  t1 |= input[(8*I)+7] & 0xff;
  W[I] = t1;
}

static void BLEND_OP(int I, unsigned long long *W) {
  W[I] = s1(W[I-2]) + W[I-7] + s0(W[I-15]) + W[I-16];
}

static void
sha512_transform(unsigned long long *state, const unsigned char *input) {
  unsigned long long a, b, c, d, e, f, g, h, t1, t2;
  unsigned long long W[80];

  int i;

  /* load the input */
  for (i = 0; i < 16; i++)
    LOAD_OP(i, W, input);

  for (i = 16; i < 80; i++) {
    BLEND_OP(i, W);
  }

  /* load the state into our registers */
  a=state[0];   b=state[1];   c=state[2];   d=state[3];
  e=state[4];   f=state[5];   g=state[6];   h=state[7];

  /* now iterate */
  for (i=0; i<80; i+=8) {
    t1 = h + e1(e) + Ch(e,f,g) + sha512_K[i  ] + W[i  ];
    t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
    t1 = g + e1(d) + Ch(d,e,f) + sha512_K[i+1] + W[i+1];
    t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
    t1 = f + e1(c) + Ch(c,d,e) + sha512_K[i+2] + W[i+2];
    t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
    t1 = e + e1(b) + Ch(b,c,d) + sha512_K[i+3] + W[i+3];
    t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
    t1 = d + e1(a) + Ch(a,b,c) + sha512_K[i+4] + W[i+4];
    t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
    t1 = c + e1(h) + Ch(h,a,b) + sha512_K[i+5] + W[i+5];
    t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
    t1 = b + e1(g) + Ch(g,h,a) + sha512_K[i+6] + W[i+6];
    t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
    t1 = a + e1(f) + Ch(f,g,h) + sha512_K[i+7] + W[i+7];
    t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;
  }

  state[0] += a; state[1] += b; state[2] += c; state[3] += d;
  state[4] += e; state[5] += f; state[6] += g; state[7] += h;

  /* erase our data */
  a = b = c = d = e = f = g = h = t1 = t2 = 0;
  memset(W, 0, 80 * sizeof(unsigned long long));
}

static void
sha512_init(struct sha512_ctx * sctx) {
  sctx->state[0] = H0;
  sctx->state[1] = H1;
  sctx->state[2] = H2;
  sctx->state[3] = H3;
  sctx->state[4] = H4;
  sctx->state[5] = H5;
  sctx->state[6] = H6;
  sctx->state[7] = H7;
  sctx->count[0] = sctx->count[1] = sctx->count[2] = sctx->count[3] = 0;
  memset(sctx->buf, 0, sizeof(sctx->buf));
}

static void
sha512_update(struct sha512_ctx * sctx,
	      const unsigned char *data,
	      unsigned int len) {
  unsigned int i, index, part_len;

  /* Compute number of bytes mod 128 */
  index = (unsigned int)((sctx->count[0] >> 3) & 0x7F);

  /* Update number of bits */
  if ((sctx->count[0] += (len << 3)) < (len << 3)) {
    if ((sctx->count[1] += 1) < 1)
      if ((sctx->count[2] += 1) < 1)
	sctx->count[3]++;
    sctx->count[1] += (len >> 29);
  }

  part_len = 128 - index;

  /* Transform as many times as possible. */
  if (len >= part_len) {
    memcpy(&sctx->buf[index], data, part_len);
    sha512_transform(sctx->state, sctx->buf);

    for (i = part_len; i + 127 < len; i+=128)
      sha512_transform(sctx->state, &data[i]);

    index = 0;
  } else {
    i = 0;
  }

  /* Buffer remaining input */
  memcpy(&sctx->buf[index], &data[i], len - i);
}

static void
sha512_final(struct sha512_ctx * sctx,
	     unsigned char *hash) {
  static unsigned char padding[128] = { 0x80, };

  unsigned int t;
  unsigned long long t2;
  unsigned char bits[128];
  unsigned int index, pad_len;
  int i, j;

  index = pad_len = t = i = j = 0;
  t2 = 0;

  /* Save number of bits */
  t = sctx->count[0];
  bits[15] = t; t>>=8;
  bits[14] = t; t>>=8;
  bits[13] = t; t>>=8;
  bits[12] = t;
  t = sctx->count[1];
  bits[11] = t; t>>=8;
  bits[10] = t; t>>=8;
  bits[9 ] = t; t>>=8;
  bits[8 ] = t;
  t = sctx->count[2];
  bits[7 ] = t; t>>=8;
  bits[6 ] = t; t>>=8;
  bits[5 ] = t; t>>=8;
  bits[4 ] = t;
  t = sctx->count[3];
  bits[3 ] = t; t>>=8;
  bits[2 ] = t; t>>=8;
  bits[1 ] = t; t>>=8;
  bits[0 ] = t;

  /* Pad out to 112 mod 128. */
  index = (sctx->count[0] >> 3) & 0x7f;
  pad_len = (index < 112) ? (112 - index) : ((128+112) - index);
  sha512_update(sctx, padding, pad_len);

  /* Append length (before padding) */
  sha512_update(sctx, bits, 16);

  /* Store state in digest */
  for (i = j = 0; i < 8; i++, j += 8) {
    t2 = sctx->state[i];
    hash[j+7] = (char)t2 & 0xff; t2>>=8;
    hash[j+6] = (char)t2 & 0xff; t2>>=8;
    hash[j+5] = (char)t2 & 0xff; t2>>=8;
    hash[j+4] = (char)t2 & 0xff; t2>>=8;
    hash[j+3] = (char)t2 & 0xff; t2>>=8;
    hash[j+2] = (char)t2 & 0xff; t2>>=8;
    hash[j+1] = (char)t2 & 0xff; t2>>=8;
    hash[j  ] = (char)t2 & 0xff;
  }

  /* Zeroize sensitive information. */
  memset(sctx, 0, sizeof(struct sha512_ctx));
}

/**
 * Hash block of given size.
 *
 * @param block the data to hash, length is given as a second argument
 * @param size the length of the data to hash
 * @param ret pointer to where to write the hashcode
 */
void hash(const void * block,
	  unsigned int size,
	  HashCode512 * ret) {
  struct sha512_ctx ctx;

  sha512_init(&ctx);
  sha512_update(&ctx, block, size);
  sha512_final(&ctx, (unsigned char*) ret);
}

/**
 * Compute the hash of an entire file.  Does NOT load the entire file
 * into memory but instead processes it in blocks.  Very important for
 * large files.
 *
 * @return OK on success, SYSERR on error
 */
int getFileHash(const char * filename,
		HashCode512 * ret) {
  unsigned char * buf;
  unsigned long long len;
  unsigned long long pos;
  unsigned int delta;
  int fh;
  struct sha512_ctx ctx;

  if (OK != getFileSize(filename,
			&len))
    return SYSERR;
  fh = fileopen(filename,
#ifdef O_LARGEFILE
		O_RDONLY | O_LARGEFILE
#else
		O_RDONLY
#endif
	    );
  if (fh == -1) {
    LOG_FILE_STRERROR(LOG_ERROR, "open", filename);
    return SYSERR;
  }
  sha512_init(&ctx);
  pos = 0;
  buf = MALLOC(65536);
  while (pos < len) {
    delta = 65536;
    if (len - pos < delta)
      delta = len-pos;
    if (delta != READ(fh,
		      buf,
		      delta)) {
		  LOG(LOG_ERROR, "Error reading from file at position %i\n", pos);
      closefile(fh);
      FREE(buf);
      return SYSERR;
    }
    sha512_update(&ctx,
		  buf,
		  delta);
    if (pos + delta > pos)
      pos += delta;
    else
      break;
  }
  closefile(fh);
  sha512_final(&ctx,
	       (unsigned char*) ret);
  FREE(buf);
  return OK;
}

/* ***************** binary-ASCII encoding *************** */

/**
 * 32 characters for encoding (hash => 32 characters)
 */
static char * encTable__ = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

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
 * in [0-9A-V], can be produced without complex arithmetics and uses a
 * small number of characters.  The GNUnet encoding uses 102
 * characters plus a null terminator.
 *
 * @param block the hash code
 * @param result where to store the encoding (EncName can be
 *  safely cast to char*, a '\0' termination is set).
 */
void hash2enc(const HashCode512 * block,
	      EncName * result) {
  unsigned int wpos;
  unsigned int rpos;
  unsigned int bits;
  unsigned int vbit;

  GNUNET_ASSERT(block != NULL);
  GNUNET_ASSERT(result != NULL);
  vbit = 0;
  wpos = 0;
  rpos = 0;
  bits = 0;
  while ( (rpos < sizeof(HashCode512)) ||
	  (vbit > 0) ) {
    if ( (rpos < sizeof(HashCode512)) &&
	 (vbit < 5) ) {
      bits = (bits << 8) | ((unsigned char*)block)[rpos++]; /* eat 8 more bits */
      vbit += 8;
    }
    if (vbit < 5) {
      bits = bits << (5 - vbit); /* zero-padding */
      GNUNET_ASSERT(vbit == 2); /* padding by 3: 512+3 mod 5 == 0 */
      vbit = 5;
    }
    GNUNET_ASSERT(wpos < sizeof(EncName)-1);
    result->encoding[wpos++] = encTable__[(bits >> (vbit - 5)) & 31];
    vbit -= 5;
  }
  GNUNET_ASSERT(wpos == sizeof(EncName)-1);
  GNUNET_ASSERT(vbit == 0);
  result->encoding[wpos] = '\0';
}

/**
 * Convert ASCII encoding back to hash
 *
 * @param enc the encoding
 * @param result where to store the hash code
 * @return OK on success, SYSERR if result has the wrong encoding
 */
int enc2hash(const char * enc,
	     HashCode512 * result) {
  unsigned int rpos;
  unsigned int wpos;
  unsigned int bits;
  unsigned int vbit;

  if (strlen(enc) != sizeof(EncName)-1)
    return SYSERR;

  vbit = 2; /* padding! */
  wpos = sizeof(HashCode512);
  rpos = sizeof(EncName)-1;
  bits = getValue__(enc[--rpos]) >> 3;
  while (wpos > 0) {
    GNUNET_ASSERT(rpos > 0);
    bits = (getValue__(enc[--rpos]) << vbit) | bits;
    vbit += 5;
    if (vbit >= 8) {
      ((unsigned char*)result)[--wpos]
	= (unsigned char) bits;
      bits = bits >> 8;
      vbit -= 8;
    }
  }
  GNUNET_ASSERT(rpos == 0);
  GNUNET_ASSERT(vbit == 0);
  return OK;
}

/**
 * Compute the distance between 2 hashcodes.  The computation must be
 * fast, not involve bits[0] or bits[4] (they're used elsewhere), and be
 * somewhat consistent. And of course, the result should be a positive
 * number.
 *
 * @returns a positive number which is a measure for
 *  hashcode proximity.
 */
int distanceHashCode512(const HashCode512 * a,
			const HashCode512 * b) {
  int x = (a->bits[1] - b->bits[1])>>16;
  return ((x*x)>>16);
}

/**
 * Compare two hashcodes.
 * @return 1 if they are equal, 0 if not.
 */
int equalsHashCode512(const HashCode512 * a,
		      const HashCode512 * b) {
  return (0 == memcmp(a,b,sizeof(HashCode512)));
}

void makeRandomId(HashCode512 * result) {
  int i;
  for (i=(sizeof(HashCode512)/sizeof(unsigned int))-1;i>=0;i--)
    result->bits[i] = rand();
}

void deltaId(const HashCode512 * a,
	     const HashCode512 * b,
	     HashCode512 * result) {
  int i;
  for (i=(sizeof(HashCode512)/sizeof(unsigned int))-1;i>=0;i--)
    result->bits[i] = b->bits[i] - a->bits[i];
}

void addHashCodes(const HashCode512 * a,
		  const HashCode512 * delta,
		  HashCode512 * result) {
  int i;
  for (i=(sizeof(HashCode512)/sizeof(unsigned int))-1;i>=0;i--)
    result->bits[i] = delta->bits[i] + a->bits[i];
}

void xorHashCodes(const HashCode512 * a,
		  const HashCode512 * b,
		  HashCode512 * result) {
  int i;
  for (i=(sizeof(HashCode512)/sizeof(unsigned int))-1;i>=0;i--)
    result->bits[i] = a->bits[i] ^ a->bits[i];
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
  return equalsHashCode512(&first->hashPubKey,
			   &second->hashPubKey);
}

/**
 * Convert a hashcode into a key.
 */
void hashToKey(const HashCode512 * hc,
	       SESSIONKEY * skey,
	       INITVECTOR * iv) {
  GNUNET_ASSERT(sizeof(HashCode512) >=
		SESSIONKEY_LEN +
		sizeof(INITVECTOR));
  memcpy(skey,
	 hc,
	 SESSIONKEY_LEN);
  skey->crc32 = htonl(crc32N(skey,
			     SESSIONKEY_LEN));
  memcpy(iv,
	 &((char *)hc)[SESSIONKEY_LEN],
	 sizeof(INITVECTOR));
}

/**
 * Obtain a bit from a hashcode.
 * @param code the hash to index bit-wise
 * @param bit index into the hashcode, [0...511]
 * @return Bit \a bit from hashcode \a code, -1 for invalid index
 */
int getHashCodeBit(const HashCode512 * code,
		   unsigned int bit) {
  if (bit >= 8 * sizeof(HashCode512)) {
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
int hashCodeCompare(const HashCode512 * h1,
		    const HashCode512 * h2) {
  unsigned int * i1;
  unsigned int * i2;
  int i;

  i1 = (unsigned int*) h1;
  i2 = (unsigned int*) h2;
  for (i=(sizeof(HashCode512) / sizeof(unsigned int))-1;i>=0;i--) {
    if (i1[i] > i2[i])
      return 1;
    if (i1[i] < i2[i])
      return -1;
  }
  return 0;
}

/**
 * Find out which of the two hash codes is closer to target
 * in the XOR metric (Kademlia).
 * @return -1 if h1 is closer, 1 if h2 is closer and 0 if h1==h2.
 */
int hashCodeCompareDistance(const HashCode512 * h1,
			    const HashCode512 * h2,
			    const HashCode512 * target) {
  int i;
#if 0
  int diff;
  int b1, b2, bt;
#endif
  unsigned int d1;
  unsigned int d2;

  for (i=sizeof(HashCode512)/sizeof(unsigned int)-1;i>=0;i--) {
    d1 = ((unsigned int*)h1)[i] ^ ((unsigned int*)target)[i];
    d2 = ((unsigned int*)h2)[i] ^ ((unsigned int*)target)[i];
    if (d1 > d2)
      return 1;
    else if (d1 < d2)
      return -1;
  }
#if 0
  /* Old code: */
  for (i = sizeof(HashCode512) * 8 - 1; i >= 0; --i) {
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
