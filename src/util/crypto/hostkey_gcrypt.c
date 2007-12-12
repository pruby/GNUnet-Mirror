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
 * @file util/hostkey_gcrypt.c
 * @brief public key cryptography (RSA) with libgcrypt
 * @author Christian Grothoff
 *
 * Note that the code locks often needlessly on the gcrypt-locking api.
 * One would think that simple MPI operations should not require locking
 * (since only global operations on the random pool must be locked,
 * strictly speaking).  But libgcrypt does sometimes require locking in
 * unexpected places, so the safe solution is to always lock even if it
 * is not required.  The performance impact is minimal anyway.
 */

#include "gnunet_util.h"
#include "gnunet_util_crypto.h"
#include "locking_gcrypt.h"
#include "platform.h"
#include <gcrypt.h>

/**
 * Use LOG_ERROR for anything that should never happen
 * (indicates a bug).
 */
#define LOG_ERROR (GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK)

/**
 * The private information of an RSA key pair.
 */
struct GNUNET_RSA_PrivateKey
{
  gcry_sexp_t sexp;
};

#define HOSTKEY_LEN 2048

#define EXTRA_CHECKS ALLOW_EXTRA_CHECKS


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
 * If target != size, move target bytes to the
 * end of the size-sized buffer and zero out the
 * first target-size bytes.
 */
static void
adjust (unsigned char *buf, size_t size, size_t target)
{
  if (size < target)
    {
      memmove (&buf[target - size], buf, size);
      memset (buf, 0, target - size);
    }
}

/**
 * This HostKey implementation uses RSA.
 */
struct GNUNET_RSA_PrivateKey *
GNUNET_RSA_create_key ()
{
  struct GNUNET_RSA_PrivateKey *ret;
  gcry_sexp_t s_key;
  gcry_sexp_t s_keyparam;
  int rc;

  GNUNET_lock_gcrypt_ ();
  rc = gcry_sexp_build (&s_keyparam,
                        NULL,
                        "(genkey(rsa(nbits %d)(rsa-use-e 3:257)))",
                        HOSTKEY_LEN);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_sexp_build", rc);
      GNUNET_unlock_gcrypt_ ();
      return NULL;
    }
  rc = gcry_pk_genkey (&s_key, s_keyparam);
  gcry_sexp_release (s_keyparam);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_pk_genkey", rc);
      GNUNET_unlock_gcrypt_ ();
      return NULL;
    }

#if EXTRA_CHECKS
  if ((rc = gcry_pk_testkey (s_key)))
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_pk_testkey", rc);
      GNUNET_unlock_gcrypt_ ();
      return NULL;
    }
#endif
  GNUNET_unlock_gcrypt_ ();
  ret = GNUNET_malloc (sizeof (struct GNUNET_RSA_PrivateKey));
  ret->sexp = s_key;
  return ret;
}

/**
 * Free memory occupied by hostkey
 */
void
GNUNET_RSA_free_key (struct GNUNET_RSA_PrivateKey *hostkey)
{
  GNUNET_lock_gcrypt_ ();
  gcry_sexp_release (hostkey->sexp);
  GNUNET_unlock_gcrypt_ ();
  GNUNET_free (hostkey);
}

static int
key_from_sexp (gcry_mpi_t * array,
               gcry_sexp_t sexp, const char *topname, const char *elems)
{
  gcry_sexp_t list, l2;
  const char *s;
  int i, idx;

  GNUNET_lock_gcrypt_ ();
  list = gcry_sexp_find_token (sexp, topname, 0);
  if (!list)
    {
      GNUNET_unlock_gcrypt_ ();
      return 1;
    }
  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  if (!list)
    {
      GNUNET_unlock_gcrypt_ ();
      return 2;
    }

  idx = 0;
  for (s = elems; *s; s++, idx++)
    {
      l2 = gcry_sexp_find_token (list, s, 1);
      if (!l2)
        {
          for (i = 0; i < idx; i++)
            {
              gcry_free (array[i]);
              array[i] = NULL;
            }
          gcry_sexp_release (list);
          GNUNET_unlock_gcrypt_ ();
          return 3;             /* required parameter not found */
        }
      array[idx] = gcry_sexp_nth_mpi (l2, 1, GCRYMPI_FMT_USG);
      gcry_sexp_release (l2);
      if (!array[idx])
        {
          for (i = 0; i < idx; i++)
            {
              gcry_free (array[i]);
              array[i] = NULL;
            }
          gcry_sexp_release (list);
          GNUNET_unlock_gcrypt_ ();
          return 4;             /* required parameter is invalid */
        }
    }
  gcry_sexp_release (list);
  GNUNET_unlock_gcrypt_ ();
  return 0;
}

/**
 * Extract the public key of the host.
 * @param hostkey the hostkey to extract into the result.
 * @param result where to write the result.
 */
void
GNUNET_RSA_get_public_key (const struct GNUNET_RSA_PrivateKey *hostkey,
                           GNUNET_RSA_PublicKey * result)
{
  gcry_mpi_t skey[2];
  size_t size;
  int rc;

  GNUNET_lock_gcrypt_ ();
  rc = key_from_sexp (skey, hostkey->sexp, "public-key", "ne");
  if (rc)
    rc = key_from_sexp (skey, hostkey->sexp, "private-key", "ne");
  if (rc)
    rc = key_from_sexp (skey, hostkey->sexp, "rsa", "ne");
  if (rc)
    DIE_GCRY (NULL, "key_from_sexp", rc);

  result->len =
    htons (sizeof (GNUNET_RSA_PublicKey) - sizeof (result->padding));
  result->sizen = htons (GNUNET_RSA_DATA_ENCODING_LEN);
  result->padding = 0;
  size = GNUNET_RSA_DATA_ENCODING_LEN;
  rc = gcry_mpi_print (GCRYMPI_FMT_USG,
                       &result->key[0], size, &size, skey[0]);
  if (rc)
    DIE_GCRY (NULL, "gcry_mpi_print", rc);
  adjust (&result->key[0], size, GNUNET_RSA_DATA_ENCODING_LEN);
  size = GNUNET_RSA_KEY_LEN - GNUNET_RSA_DATA_ENCODING_LEN;
  rc = gcry_mpi_print (GCRYMPI_FMT_USG,
                       &result->key[GNUNET_RSA_DATA_ENCODING_LEN], size,
                       &size, skey[1]);
  if (rc)
    DIE_GCRY (NULL, "gcry_mpi_print", rc);
  adjust (&result->key[GNUNET_RSA_DATA_ENCODING_LEN], size,
          GNUNET_RSA_KEY_LEN - GNUNET_RSA_DATA_ENCODING_LEN);
  gcry_mpi_release (skey[0]);
  gcry_mpi_release (skey[1]);
  GNUNET_unlock_gcrypt_ ();
}


/**
 * Internal: publicKey => RSA-Key.
 *
 * Note that the return type is not actually a private
 * key but rather an sexpression for the public key!
 */
static struct GNUNET_RSA_PrivateKey *
public2PrivateKey (const GNUNET_RSA_PublicKey * publicKey)
{
  struct GNUNET_RSA_PrivateKey *ret;
  gcry_sexp_t result;
  gcry_mpi_t n;
  gcry_mpi_t e;
  size_t size;
  size_t erroff;
  int rc;

  if ((ntohs (publicKey->sizen) != GNUNET_RSA_DATA_ENCODING_LEN) ||
      (ntohs (publicKey->len) !=
       sizeof (GNUNET_RSA_PublicKey) - sizeof (publicKey->padding)))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return NULL;
    }
  size = GNUNET_RSA_DATA_ENCODING_LEN;
  GNUNET_lock_gcrypt_ ();
  rc = gcry_mpi_scan (&n, GCRYMPI_FMT_USG, &publicKey->key[0], size, &size);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_mpi_scan", rc);
      GNUNET_unlock_gcrypt_ ();
      return NULL;
    }
  size = GNUNET_RSA_KEY_LEN - GNUNET_RSA_DATA_ENCODING_LEN;
  rc = gcry_mpi_scan (&e,
                      GCRYMPI_FMT_USG,
                      &publicKey->key[GNUNET_RSA_DATA_ENCODING_LEN], size,
                      &size);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_mpi_scan", rc);
      gcry_mpi_release (n);
      GNUNET_unlock_gcrypt_ ();
      return NULL;
    }
  rc = gcry_sexp_build (&result,
                        &erroff, "(public-key(rsa(n %m)(e %m)))", n, e);
  gcry_mpi_release (n);
  gcry_mpi_release (e);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_sexp_build", rc);        /* erroff gives more info */
      GNUNET_unlock_gcrypt_ ();
      return NULL;
    }
  GNUNET_unlock_gcrypt_ ();
  ret = GNUNET_malloc (sizeof (struct GNUNET_RSA_PrivateKey));
  ret->sexp = result;
  return ret;
}

/**
 * Encode the private key in a format suitable for
 * storing it into a file.
 * @returns encoding of the private key.
 *    The first 4 bytes give the size of the array, as usual.
 */
GNUNET_RSA_PrivateKeyEncoded *
GNUNET_RSA_encode_key (const struct GNUNET_RSA_PrivateKey * hostkey)
{
  GNUNET_RSA_PrivateKeyEncoded *retval;
  gcry_mpi_t pkv[6];
  void *pbu[6];
  size_t sizes[6];
  int rc;
  int i;
  int size;

  GNUNET_lock_gcrypt_ ();
#if EXTRA_CHECKS
  if (gcry_pk_testkey (hostkey->sexp))
    {
      GNUNET_GE_BREAK (NULL, 0);
      GNUNET_unlock_gcrypt_ ();
      return NULL;
    }
#endif

  memset (pkv, 0, sizeof (gcry_mpi_t) * 6);
  rc = key_from_sexp (pkv, hostkey->sexp, "private-key", "nedpqu");
  if (rc)
    rc = key_from_sexp (pkv, hostkey->sexp, "rsa", "nedpqu");
  if (rc)
    rc = key_from_sexp (pkv, hostkey->sexp, "private-key", "nedpq");
  if (rc)
    rc = key_from_sexp (pkv, hostkey->sexp, "rsa", "nedpq");
  if (rc)
    rc = key_from_sexp (pkv, hostkey->sexp, "private-key", "ned");
  if (rc)
    rc = key_from_sexp (pkv, hostkey->sexp, "rsa", "ned");
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "key_from_sexp", rc);
      GNUNET_unlock_gcrypt_ ();
      return NULL;
    }
  size = sizeof (GNUNET_RSA_PrivateKeyEncoded);
  for (i = 0; i < 6; i++)
    {
      if (pkv[i] != NULL)
        {
          rc = gcry_mpi_aprint (GCRYMPI_FMT_USG,
                                (unsigned char **) &pbu[i],
                                &sizes[i], pkv[i]);
          size += sizes[i];
          if (rc)
            {
              LOG_GCRY (NULL, LOG_ERROR, "gcry_mpi_aprint", rc);
              while (i > 0)
                if (pbu[i] != NULL)
                  free (pbu[--i]);
              for (i = 0; i < 6; i++)
                if (pkv[i] != NULL)
                  gcry_mpi_release (pkv[i]);
              GNUNET_unlock_gcrypt_ ();
              return NULL;
            }
        }
      else
        {
          pbu[i] = NULL;
          sizes[i] = 0;
        }
    }
  GNUNET_GE_ASSERT (NULL, size < 65536);
  retval = GNUNET_malloc (size);
  retval->len = htons (size);
  i = 0;
  retval->sizen = htons (sizes[0]);
  memcpy (&((char *) (&retval[1]))[i], pbu[0], sizes[0]);
  i += sizes[0];
  retval->sizee = htons (sizes[1]);
  memcpy (&((char *) (&retval[1]))[i], pbu[1], sizes[1]);
  i += sizes[1];
  retval->sized = htons (sizes[2]);
  memcpy (&((char *) (&retval[1]))[i], pbu[2], sizes[2]);
  i += sizes[2];
  /* swap p and q! */
  retval->sizep = htons (sizes[4]);
  memcpy (&((char *) (&retval[1]))[i], pbu[4], sizes[4]);
  i += sizes[4];
  retval->sizeq = htons (sizes[3]);
  memcpy (&((char *) (&retval[1]))[i], pbu[3], sizes[3]);
  i += sizes[3];
  retval->sizedmp1 = htons (0);
  retval->sizedmq1 = htons (0);
  memcpy (&((char *) (&retval[1]))[i], pbu[5], sizes[5]);
  for (i = 0; i < 6; i++)
    {
      if (pkv[i] != NULL)
        gcry_mpi_release (pkv[i]);
      if (pbu[i] != NULL)
        free (pbu[i]);
    }
  GNUNET_unlock_gcrypt_ ();
  return retval;
}

/**
 * Decode the private key from the file-format back
 * to the "normal", internal format.
 */
struct GNUNET_RSA_PrivateKey *
GNUNET_RSA_decode_key (const GNUNET_RSA_PrivateKeyEncoded * encoding)
{
  struct GNUNET_RSA_PrivateKey *ret;
  gcry_sexp_t res;
  gcry_mpi_t n, e, d, p, q, u;
  int rc;
  size_t size;
  int pos;

  pos = 0;
  size = ntohs (encoding->sizen);
  GNUNET_lock_gcrypt_ ();
  rc = gcry_mpi_scan (&n,
                      GCRYMPI_FMT_USG,
                      &((const unsigned char *) (&encoding[1]))[pos],
                      size, &size);
  pos += ntohs (encoding->sizen);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_mpi_scan", rc);
      GNUNET_unlock_gcrypt_ ();
      return NULL;
    }
  size = ntohs (encoding->sizee);
  rc = gcry_mpi_scan (&e,
                      GCRYMPI_FMT_USG,
                      &((const unsigned char *) (&encoding[1]))[pos],
                      size, &size);
  pos += ntohs (encoding->sizee);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_mpi_scan", rc);
      gcry_mpi_release (n);
      GNUNET_unlock_gcrypt_ ();
      return NULL;
    }
  size = ntohs (encoding->sized);
  rc = gcry_mpi_scan (&d,
                      GCRYMPI_FMT_USG,
                      &((const unsigned char *) (&encoding[1]))[pos],
                      size, &size);
  pos += ntohs (encoding->sized);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_mpi_scan", rc);
      gcry_mpi_release (n);
      gcry_mpi_release (e);
      GNUNET_unlock_gcrypt_ ();
      return NULL;
    }
  /* swap p and q! */
  size = ntohs (encoding->sizep);
  if (size > 0)
    {
      rc = gcry_mpi_scan (&q,
                          GCRYMPI_FMT_USG,
                          &((const unsigned char *) (&encoding[1]))[pos],
                          size, &size);
      pos += ntohs (encoding->sizep);
      if (rc)
        {
          LOG_GCRY (NULL, LOG_ERROR, "gcry_mpi_scan", rc);
          gcry_mpi_release (n);
          gcry_mpi_release (e);
          gcry_mpi_release (d);
          GNUNET_unlock_gcrypt_ ();
          return NULL;
        }
    }
  else
    q = NULL;
  size = ntohs (encoding->sizeq);
  if (size > 0)
    {
      rc = gcry_mpi_scan (&p,
                          GCRYMPI_FMT_USG,
                          &((const unsigned char *) (&encoding[1]))[pos],
                          size, &size);
      pos += ntohs (encoding->sizeq);
      if (rc)
        {
          LOG_GCRY (NULL, LOG_ERROR, "gcry_mpi_scan", rc);
          gcry_mpi_release (n);
          gcry_mpi_release (e);
          gcry_mpi_release (d);
          if (q != NULL)
            gcry_mpi_release (q);
          GNUNET_unlock_gcrypt_ ();
          return NULL;
        }
    }
  else
    p = NULL;
  pos += ntohs (encoding->sizedmp1);
  pos += ntohs (encoding->sizedmq1);
  size = ntohs (encoding->len) - sizeof (GNUNET_RSA_PrivateKeyEncoded) - pos;
  if (size > 0)
    {
      rc = gcry_mpi_scan (&u,
                          GCRYMPI_FMT_USG,
                          &((const unsigned char *) (&encoding[1]))[pos],
                          size, &size);
      if (rc)
        {
          LOG_GCRY (NULL, LOG_ERROR, "gcry_mpi_scan", rc);
          gcry_mpi_release (n);
          gcry_mpi_release (e);
          gcry_mpi_release (d);
          if (p != NULL)
            gcry_mpi_release (p);
          if (q != NULL)
            gcry_mpi_release (q);
          GNUNET_unlock_gcrypt_ ();
          return NULL;
        }
    }
  else
    u = NULL;

  if ((p != NULL) && (q != NULL) && (u != NULL))
    {
      rc = gcry_sexp_build (&res, &size,        /* erroff */
                            "(private-key(rsa(n %m)(e %m)(d %m)(p %m)(q %m)(u %m)))",
                            n, e, d, p, q, u);
    }
  else
    {
      if ((p != NULL) && (q != NULL))
        {
          rc = gcry_sexp_build (&res, &size,    /* erroff */
                                "(private-key(rsa(n %m)(e %m)(d %m)(p %m)(q %m)))",
                                n, e, d, p, q);
        }
      else
        {
          rc = gcry_sexp_build (&res, &size,    /* erroff */
                                "(private-key(rsa(n %m)(e %m)(d %m)))",
                                n, e, d);
        }
    }
  gcry_mpi_release (n);
  gcry_mpi_release (e);
  gcry_mpi_release (d);
  if (p != NULL)
    gcry_mpi_release (p);
  if (q != NULL)
    gcry_mpi_release (q);
  if (u != NULL)
    gcry_mpi_release (u);

  if (rc)
    LOG_GCRY (NULL, LOG_ERROR, "gcry_sexp_build", rc);
#if EXTRA_CHECKS
  if (gcry_pk_testkey (res))
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_pk_testkey", rc);
      GNUNET_unlock_gcrypt_ ();
      return NULL;
    }
#endif
  ret = GNUNET_malloc (sizeof (struct GNUNET_RSA_PrivateKey));
  ret->sexp = res;
  GNUNET_unlock_gcrypt_ ();
  return ret;
}

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
int
GNUNET_RSA_encrypt (const void *block,
                    unsigned short size,
                    const GNUNET_RSA_PublicKey * publicKey,
                    GNUNET_RSA_EncryptedData * target)
{
  gcry_sexp_t result;
  gcry_sexp_t data;
  struct GNUNET_RSA_PrivateKey *pubkey;
  gcry_mpi_t val;
  gcry_mpi_t rval;
  size_t isize;
  size_t erroff;
  int rc;

  GNUNET_GE_ASSERT (NULL, size <= sizeof (GNUNET_HashCode));
  pubkey = public2PrivateKey (publicKey);
  isize = size;
  GNUNET_lock_gcrypt_ ();
  rc = gcry_mpi_scan (&val, GCRYMPI_FMT_USG, block, isize, &isize);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_mpi_scan", rc);
      GNUNET_RSA_free_key (pubkey);
      GNUNET_unlock_gcrypt_ ();
      return GNUNET_SYSERR;
    }
  rc = gcry_sexp_build (&data,
                        &erroff, "(data (flags pkcs1)(value %m))", val);
  gcry_mpi_release (val);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_sexp_build", rc);        /* more info in erroff */
      GNUNET_RSA_free_key (pubkey);
      GNUNET_unlock_gcrypt_ ();
      return GNUNET_SYSERR;
    }

  rc = gcry_pk_encrypt (&result, data, pubkey->sexp);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_pk_encrypt", rc);
      gcry_sexp_release (data);
      GNUNET_RSA_free_key (pubkey);
      GNUNET_unlock_gcrypt_ ();
      return GNUNET_SYSERR;
    }
  gcry_sexp_release (data);
  GNUNET_RSA_free_key (pubkey);

  rc = key_from_sexp (&rval, result, "rsa", "a");
  gcry_sexp_release (result);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "key_from_sexp", rc);
      GNUNET_unlock_gcrypt_ ();
      return GNUNET_SYSERR;
    }
  isize = sizeof (GNUNET_RSA_EncryptedData);
  rc = gcry_mpi_print (GCRYMPI_FMT_USG,
                       (unsigned char *) target, isize, &isize, rval);
  gcry_mpi_release (rval);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_mpi_print", rc);
      GNUNET_unlock_gcrypt_ ();
      return GNUNET_SYSERR;
    }
  adjust (&target->encoding[0], isize, sizeof (GNUNET_RSA_EncryptedData));
  GNUNET_unlock_gcrypt_ ();
  return GNUNET_OK;
}

/**
 * Decrypt a given block with the hostkey.
 *
 * @param hostkey the hostkey with which to decrypt this block
 * @param block the data to decrypt, encoded as returned by encrypt
 * @param result pointer to a location where the result can be stored
 * @param max the maximum number of bits to store for the result, if
 *        the decrypted block is bigger, an error is returned
 * @returns the size of the decrypted block, -1 on error
 */
int
GNUNET_RSA_decrypt (const struct GNUNET_RSA_PrivateKey *hostkey,
                    const GNUNET_RSA_EncryptedData * block,
                    void *result, unsigned short max)
{
  gcry_sexp_t resultsexp;
  gcry_sexp_t data;
  size_t erroff;
  size_t size;
  gcry_mpi_t val;
  int rc;
  unsigned char *endp;
  unsigned char *tmp;

  GNUNET_lock_gcrypt_ ();
#if EXTRA_CHECKS
  rc = gcry_pk_testkey (hostkey->sexp);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_pk_testkey", rc);
      GNUNET_unlock_gcrypt_ ();
      return -1;
    }
#endif
  size = sizeof (GNUNET_RSA_EncryptedData);
  rc = gcry_mpi_scan (&val,
                      GCRYMPI_FMT_USG, &block->encoding[0], size, &size);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_mpi_scan", rc);
      GNUNET_unlock_gcrypt_ ();
      return GNUNET_SYSERR;
    }
  rc = gcry_sexp_build (&data, &erroff, "(enc-val(flags)(rsa(a %m)))", val);
  gcry_mpi_release (val);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_sexp_build", rc);        /* more info in erroff */
      GNUNET_unlock_gcrypt_ ();
      return GNUNET_SYSERR;
    }
  rc = gcry_pk_decrypt (&resultsexp, data, hostkey->sexp);
  gcry_sexp_release (data);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_pk_decrypt", rc);
      GNUNET_unlock_gcrypt_ ();
      return GNUNET_SYSERR;
    }

  /* resultsexp has format "(value %m)" */
  val = gcry_sexp_nth_mpi (resultsexp, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (resultsexp);
  if (val == NULL)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_sexp_nth_mpi", rc);
      GNUNET_unlock_gcrypt_ ();
      return GNUNET_SYSERR;
    }
  tmp = GNUNET_malloc (max + HOSTKEY_LEN / 8);
  size = max + HOSTKEY_LEN / 8;
  rc = gcry_mpi_print (GCRYMPI_FMT_USG, tmp, size, &size, val);
  gcry_mpi_release (val);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_mpi_print", rc);
      GNUNET_free (tmp);
      GNUNET_unlock_gcrypt_ ();
      return GNUNET_SYSERR;
    }

  endp = tmp;
  endp += (size - max);
  size = max;
  memcpy (result, endp, size);
  GNUNET_free (tmp);
  GNUNET_unlock_gcrypt_ ();
  return size;
}

/**
 * Sign a given block.
 *
 * @param hostkey the hostkey with which to GNUNET_RSA_sign this block
 * @param size how many bytes to GNUNET_RSA_sign
 * @param block the data to GNUNET_RSA_sign
 * @param sig where to write the signature
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int
GNUNET_RSA_sign (const struct GNUNET_RSA_PrivateKey *hostkey,
                 unsigned short size, const void *block,
                 GNUNET_RSA_Signature * sig)
{
  gcry_sexp_t result;
  gcry_sexp_t data;
  size_t ssize;
  gcry_mpi_t rval;
  GNUNET_HashCode hc;
  char *buff;
  int bufSize;
  int rc;

  GNUNET_hash (block, size, &hc);
#define FORMATSTRING "(4:data(5:flags5:pkcs1)(4:hash6:sha51264:0123456789012345678901234567890123456789012345678901234567890123))"
  bufSize = strlen (FORMATSTRING) + 1;
  buff = GNUNET_malloc (bufSize);
  memcpy (buff, FORMATSTRING, bufSize);
  memcpy (&buff
          [bufSize -
           strlen
           ("0123456789012345678901234567890123456789012345678901234567890123))")
           - 1], &hc, sizeof (GNUNET_HashCode));
  GNUNET_lock_gcrypt_ ();
  rc = gcry_sexp_new (&data, buff, bufSize, 0);
  GNUNET_free (buff);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_sexp_new", rc);
      GNUNET_unlock_gcrypt_ ();
      return GNUNET_SYSERR;
    }
  rc = gcry_pk_sign (&result, data, hostkey->sexp);
  gcry_sexp_release (data);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_pk_sign", rc);
      GNUNET_unlock_gcrypt_ ();
      return GNUNET_SYSERR;
    }
  rc = key_from_sexp (&rval, result, "rsa", "s");
  gcry_sexp_release (result);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "key_from_sexp", rc);
      GNUNET_unlock_gcrypt_ ();
      return GNUNET_SYSERR;
    }
  ssize = sizeof (GNUNET_RSA_Signature);
  rc = gcry_mpi_print (GCRYMPI_FMT_USG,
                       (unsigned char *) sig, ssize, &ssize, rval);
  gcry_mpi_release (rval);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_mpi_print", rc);
      GNUNET_unlock_gcrypt_ ();
      return GNUNET_SYSERR;
    }
  adjust (&sig->sig[0], ssize, sizeof (GNUNET_RSA_Signature));
  GNUNET_unlock_gcrypt_ ();
  return GNUNET_OK;
}

/**
 * Verify signature.
 *
 * @param block the signed data
 * @param len the length of the block
 * @param sig signature
 * @param publicKey public key of the signer
 * @returns GNUNET_OK if ok, GNUNET_SYSERR if invalid
 */
int
GNUNET_RSA_verify (const void *block,
                   unsigned short len,
                   const GNUNET_RSA_Signature * sig,
                   const GNUNET_RSA_PublicKey * publicKey)
{
  gcry_sexp_t data;
  gcry_sexp_t sigdata;
  size_t size;
  gcry_mpi_t val;
  struct GNUNET_RSA_PrivateKey *hostkey;
  GNUNET_HashCode hc;
  char *buff;
  int bufSize;
  size_t erroff;
  int rc;

  size = sizeof (GNUNET_RSA_Signature);
  GNUNET_lock_gcrypt_ ();
  rc = gcry_mpi_scan (&val,
                      GCRYMPI_FMT_USG,
                      (const unsigned char *) sig, size, &size);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_mpi_scan", rc);
      GNUNET_unlock_gcrypt_ ();
      return GNUNET_SYSERR;
    }
  rc = gcry_sexp_build (&sigdata, &erroff, "(sig-val(rsa(s %m)))", val);
  gcry_mpi_release (val);
  if (rc)
    {
      LOG_GCRY (NULL, LOG_ERROR, "gcry_sexp_build", rc);
      GNUNET_unlock_gcrypt_ ();
      return GNUNET_SYSERR;
    }
  GNUNET_hash (block, len, &hc);
  bufSize = strlen (FORMATSTRING) + 1;
  buff = GNUNET_malloc (bufSize);
  memcpy (buff, FORMATSTRING, bufSize);
  memcpy (&buff[strlen (FORMATSTRING) -
                strlen
                ("0123456789012345678901234567890123456789012345678901234567890123))")],
          &hc, sizeof (GNUNET_HashCode));
  rc = gcry_sexp_new (&data, buff, bufSize, 0);
  GNUNET_free (buff);
  hostkey = public2PrivateKey (publicKey);
  if (hostkey == NULL)
    {
      gcry_sexp_release (data);
      gcry_sexp_release (sigdata);
      return GNUNET_SYSERR;
    }
  rc = gcry_pk_verify (sigdata, data, hostkey->sexp);
  GNUNET_RSA_free_key (hostkey);
  gcry_sexp_release (data);
  gcry_sexp_release (sigdata);
  if (rc)
    {
      GNUNET_GE_LOG (NULL,
                     GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK |
                     GNUNET_GE_DEVELOPER,
                     _("RSA signature verification failed at %s:%d: %s\n"),
                     __FILE__, __LINE__, gcry_strerror (rc));
      GNUNET_unlock_gcrypt_ ();
      return GNUNET_SYSERR;
    }
  else
    {
      GNUNET_unlock_gcrypt_ ();
      return GNUNET_OK;
    }
}


/* end of hostkey_gcrypt.c */
