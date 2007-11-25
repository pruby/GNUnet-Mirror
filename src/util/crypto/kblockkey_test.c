/*
     This file is part of GNUnet.
     Copyright (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/crypto/kblockkey_test.c
 * @brief testcase for util/crypto/kblockkey.c
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_util_crypto.h"
#include "platform.h"

#define TESTSTRING "Hello World\0"
#define MAX_TESTVAL 20
#define UNIQUE_ITER 6
#define ITER 10


static int
testMultiKey (const char *word)
{
  GNUNET_HashCode in;
  struct GNUNET_RSA_PrivateKey *hostkey;
  GNUNET_RSA_PublicKey pkey;
  GNUNET_RSA_PublicKey pkey1;
  int i;

  fprintf (stderr, "Testing KBlock key uniqueness (%s) ", word);
  GNUNET_hash (word, strlen (word), &in);
  hostkey = GNUNET_RSA_create_key_from_hash (&in);
  if (hostkey == NULL)
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  GNUNET_RSA_get_public_key (hostkey, &pkey);
  /*
     for (i=0;i<sizeof(GNUNET_RSA_PublicKey);i++)
     printf("%02x", ((unsigned char*) &pkey)[i]);
     printf("\n"); */
  GNUNET_RSA_free_key (hostkey);
  for (i = 0; i < UNIQUE_ITER; i++)
    {
      fprintf (stderr, ".");
      hostkey = GNUNET_RSA_create_key_from_hash (&in);
      if (hostkey == NULL)
        {
          GNUNET_GE_BREAK (NULL, 0);
          fprintf (stderr, " ERROR\n");
          return GNUNET_SYSERR;
        }
      GNUNET_RSA_get_public_key (hostkey, &pkey1);
      GNUNET_RSA_free_key (hostkey);
      if (0 != memcmp (&pkey, &pkey1, sizeof (GNUNET_RSA_PublicKey)))
        {
          GNUNET_GE_BREAK (NULL, 0);
          fprintf (stderr, " ERROR\n");
          return GNUNET_SYSERR;
        }
    }
  fprintf (stderr, " OK\n");
  return GNUNET_OK;
}


static int
testEncryptDecrypt (struct GNUNET_RSA_PrivateKey *hostkey)
{
  GNUNET_RSA_PublicKey pkey;
  GNUNET_RSA_EncryptedData target;
  char result[MAX_TESTVAL];
  int i;
  GNUNET_Int32Time start;
  int ok;

  fprintf (stderr, "W");
  GNUNET_RSA_get_public_key (hostkey, &pkey);

  ok = 0;
  GNUNET_get_time_int32 (&start);
  for (i = 0; i < ITER; i++)
    {
      fprintf (stderr, ".");
      if (GNUNET_SYSERR == GNUNET_RSA_encrypt (TESTSTRING,
                                               strlen (TESTSTRING) + 1,
                                               &pkey, &target))
        {
          fprintf (stderr, "encryptPrivateKey returned SYSERR\n");
          ok++;
          continue;
        }
      if (-1 == GNUNET_RSA_decrypt (hostkey,
                                    &target, result, strlen (TESTSTRING) + 1))
        {
          fprintf (stderr, "decryptPrivateKey returned SYSERR\n");
          ok++;
          continue;
        }
      if (strncmp (TESTSTRING, result, strlen (TESTSTRING)) != 0)
        {
          printf ("%s != %.*s - testEncryptDecrypt failed!\n",
                  TESTSTRING, MAX_TESTVAL, result);
          ok++;
          continue;
        }
    }
  printf ("%d RSA encrypt/decrypt operations %ds (%d failures)\n",
          ITER, (int) (GNUNET_get_time_int32 (NULL) - start), ok);
  if (ok == 0)
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
}

static int
testSignVerify (struct GNUNET_RSA_PrivateKey *hostkey)
{
  GNUNET_RSA_Signature sig;
  GNUNET_RSA_PublicKey pkey;
  int i;
  GNUNET_Int32Time start;
  int ok = GNUNET_OK;

  fprintf (stderr, "W");
  GNUNET_RSA_get_public_key (hostkey, &pkey);
  GNUNET_get_time_int32 (&start);
  for (i = 0; i < ITER; i++)
    {
      fprintf (stderr, ".");
      if (GNUNET_SYSERR ==
          GNUNET_RSA_sign (hostkey, strlen (TESTSTRING), TESTSTRING, &sig))
        {
          fprintf (stderr, "sign returned SYSERR\n");
          ok = GNUNET_SYSERR;
          continue;
        }
      if (GNUNET_SYSERR ==
          GNUNET_RSA_verify (TESTSTRING, strlen (TESTSTRING), &sig, &pkey))
        {
          printf ("testSignVerify failed!\n");
          ok = GNUNET_SYSERR;
          continue;
        }
    }
  printf ("%d RSA sign/verify operations %ds\n",
          ITER, (int) (GNUNET_get_time_int32 (NULL) - start));
  return ok;
}

static int
testPrivateKeyEncoding (const struct GNUNET_RSA_PrivateKey *hostkey)
{
  GNUNET_RSA_PrivateKeyEncoded *encoding;
  struct GNUNET_RSA_PrivateKey *hostkey2;
  GNUNET_RSA_PublicKey pkey;
  GNUNET_RSA_EncryptedData target;
  char result[MAX_TESTVAL];
  int i;
  GNUNET_Int32Time start;
  int ok = GNUNET_OK;

  fprintf (stderr, "W");

  GNUNET_get_time_int32 (&start);
  for (i = 0; i < ITER; i++)
    {
      fprintf (stderr, ".");
      GNUNET_RSA_get_public_key (hostkey, &pkey);
      if (GNUNET_SYSERR == GNUNET_RSA_encrypt (TESTSTRING,
                                               strlen (TESTSTRING) + 1,
                                               &pkey, &target))
        {
          fprintf (stderr, "encryptPrivateKey returned SYSERR\n");
          ok = GNUNET_SYSERR;
          continue;
        }
      encoding = GNUNET_RSA_encode_key (hostkey);
      if (encoding == NULL)
        {
          fprintf (stderr, "encodePrivateKey returned NULL\n");
          ok = GNUNET_SYSERR;
          continue;
        }
      hostkey2 = GNUNET_RSA_decode_key (encoding);
      GNUNET_free (encoding);
      if (GNUNET_SYSERR == GNUNET_RSA_decrypt (hostkey2,
                                               &target,
                                               result,
                                               strlen (TESTSTRING) + 1))
        {
          fprintf (stderr, "decryptPrivateKey returned SYSERR\n");
          ok = GNUNET_SYSERR;
          GNUNET_RSA_free_key (hostkey2);
          continue;
        }
      GNUNET_RSA_free_key (hostkey2);
      if (strncmp (TESTSTRING, result, strlen (TESTSTRING)) != 0)
        {
          printf ("%s != %.*s - testEncryptDecrypt failed!\n",
                  TESTSTRING, (int) strlen (TESTSTRING), result);
          ok = GNUNET_SYSERR;
          continue;
        }
    }
  printf ("%d RSA encrypt/encode/decode/decrypt operations %ds\n",
          ITER, (int) (GNUNET_get_time_int32 (NULL) - start));
  return ok;
}

int
main (int argc, char *argv[])
{
  int failureCount = 0;
  GNUNET_HashCode in;
  struct GNUNET_RSA_PrivateKey *hostkey;

  GNUNET_create_random_hash (&in);
  hostkey = GNUNET_RSA_create_key_from_hash (&in);
  if (hostkey == NULL)
    {
      printf ("\nmakeKblockKey failed!\n");
      return 1;
    }

  if (GNUNET_OK != testMultiKey ("foo"))
    failureCount++;
  if (GNUNET_OK != testMultiKey ("bar"))
    failureCount++;
  if (GNUNET_OK != testEncryptDecrypt (hostkey))
    failureCount++;
  if (GNUNET_OK != testSignVerify (hostkey))
    failureCount++;
  if (GNUNET_OK != testPrivateKeyEncoding (hostkey))
    failureCount++;
  GNUNET_RSA_free_key (hostkey);

  if (failureCount != 0)
    {
      printf ("\n\n%d TESTS FAILED!\n\n", failureCount);
      return -1;
    }
  return 0;
}
