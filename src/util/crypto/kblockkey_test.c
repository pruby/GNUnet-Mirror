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
  HashCode512 in;
  struct PrivateKey *hostkey;
  PublicKey pkey;
  PublicKey pkey1;
  int i;

  fprintf (stderr, "Testing KBlock key uniqueness (%s) ", word);
  hash (word, strlen (word), &in);
  hostkey = makeKblockKey (&in);
  if (hostkey == NULL)
    {
      GE_BREAK (NULL, 0);
      return SYSERR;
    }
  getPublicKey (hostkey, &pkey);
  /*
     for (i=0;i<sizeof(PublicKey);i++)
     printf("%02x", ((unsigned char*) &pkey)[i]);
     printf("\n"); */
  freePrivateKey (hostkey);
  for (i = 0; i < UNIQUE_ITER; i++)
    {
      fprintf (stderr, ".");
      hostkey = makeKblockKey (&in);
      if (hostkey == NULL)
        {
          GE_BREAK (NULL, 0);
          fprintf (stderr, " ERROR\n");
          return SYSERR;
        }
      getPublicKey (hostkey, &pkey1);
      freePrivateKey (hostkey);
      if (0 != memcmp (&pkey, &pkey1, sizeof (PublicKey)))
        {
          GE_BREAK (NULL, 0);
          fprintf (stderr, " ERROR\n");
          return SYSERR;
        }
    }
  fprintf (stderr, " OK\n");
  return OK;
}


static int
testEncryptDecrypt (struct PrivateKey *hostkey)
{
  PublicKey pkey;
  RSAEncryptedData target;
  char result[MAX_TESTVAL];
  int i;
  TIME_T start;
  int ok;

  fprintf (stderr, "W");
  getPublicKey (hostkey, &pkey);

  ok = 0;
  TIME (&start);
  for (i = 0; i < ITER; i++)
    {
      fprintf (stderr, ".");
      if (SYSERR == encryptPrivateKey (TESTSTRING,
                                       strlen (TESTSTRING) + 1,
                                       &pkey, &target))
        {
          fprintf (stderr, "encryptPrivateKey returned SYSERR\n");
          ok++;
          continue;
        }
      if (-1 == decryptPrivateKey (hostkey,
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
          ITER, (int) (TIME (NULL) - start), ok);
  if (ok == 0)
    return OK;
  else
    return SYSERR;
}

static int
testSignVerify (struct PrivateKey *hostkey)
{
  Signature sig;
  PublicKey pkey;
  int i;
  TIME_T start;
  int ok = OK;

  fprintf (stderr, "W");
  getPublicKey (hostkey, &pkey);
  TIME (&start);
  for (i = 0; i < ITER; i++)
    {
      fprintf (stderr, ".");
      if (SYSERR == sign (hostkey, strlen (TESTSTRING), TESTSTRING, &sig))
        {
          fprintf (stderr, "sign returned SYSERR\n");
          ok = SYSERR;
          continue;
        }
      if (SYSERR == verifySig (TESTSTRING, strlen (TESTSTRING), &sig, &pkey))
        {
          printf ("testSignVerify failed!\n");
          ok = SYSERR;
          continue;
        }
    }
  printf ("%d RSA sign/verify operations %ds\n",
          ITER, (int) (TIME (NULL) - start));
  return ok;
}

static int
testPrivateKeyEncoding (const struct PrivateKey *hostkey)
{
  PrivateKeyEncoded *encoding;
  struct PrivateKey *hostkey2;
  PublicKey pkey;
  RSAEncryptedData target;
  char result[MAX_TESTVAL];
  int i;
  TIME_T start;
  int ok = OK;

  fprintf (stderr, "W");

  TIME (&start);
  for (i = 0; i < ITER; i++)
    {
      fprintf (stderr, ".");
      getPublicKey (hostkey, &pkey);
      if (SYSERR == encryptPrivateKey (TESTSTRING,
                                       strlen (TESTSTRING) + 1,
                                       &pkey, &target))
        {
          fprintf (stderr, "encryptPrivateKey returned SYSERR\n");
          ok = SYSERR;
          continue;
        }
      encoding = encodePrivateKey (hostkey);
      if (encoding == NULL)
        {
          fprintf (stderr, "encodePrivateKey returned NULL\n");
          ok = SYSERR;
          continue;
        }
      hostkey2 = decodePrivateKey (encoding);
      FREE (encoding);
      if (SYSERR == decryptPrivateKey (hostkey2,
                                       &target,
                                       result, strlen (TESTSTRING) + 1))
        {
          fprintf (stderr, "decryptPrivateKey returned SYSERR\n");
          ok = SYSERR;
          freePrivateKey (hostkey2);
          continue;
        }
      freePrivateKey (hostkey2);
      if (strncmp (TESTSTRING, result, strlen (TESTSTRING)) != 0)
        {
          printf ("%s != %.*s - testEncryptDecrypt failed!\n",
                  TESTSTRING, (int) strlen (TESTSTRING), result);
          ok = SYSERR;
          continue;
        }
    }
  printf ("%d RSA encrypt/encode/decode/decrypt operations %ds\n",
          ITER, (int) (TIME (NULL) - start));
  return ok;
}

int
main (int argc, char *argv[])
{
  int failureCount = 0;
  HashCode512 in;
  struct PrivateKey *hostkey;

  makeRandomId (&in);
  hostkey = makeKblockKey (&in);
  if (hostkey == NULL)
    {
      printf ("\nmakeKblockKey failed!\n");
      return 1;
    }

  if (OK != testMultiKey ("foo"))
    failureCount++;
  if (OK != testMultiKey ("bar"))
    failureCount++;
  if (OK != testEncryptDecrypt (hostkey))
    failureCount++;
  if (OK != testSignVerify (hostkey))
    failureCount++;
  if (OK != testPrivateKeyEncoding (hostkey))
    failureCount++;
  freePrivateKey (hostkey);

  if (failureCount != 0)
    {
      printf ("\n\n%d TESTS FAILED!\n\n", failureCount);
      return -1;
    }
  return 0;
}
