/*
     This file is part of GNUnet.
     (C) 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/crypto/hostkeytest.c
 * @brief testcase for RSA public key crypto (hostkey.h)
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_util_crypto.h"
#include "platform.h"

#define TESTSTRING "Hello World\0"
#define MAX_TESTVAL sizeof(SESSIONKEY)
#define ITER 10

#define PERF NO

static int
testEncryptDecrypt ()
{
  struct PrivateKey *hostkey;
  PublicKey pkey;
  RSAEncryptedData target;
  char result[MAX_TESTVAL];
  int i;
  TIME_T start;
  int ok;

  fprintf (stderr, "W");
  hostkey = makePrivateKey ();
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
  freePrivateKey (hostkey);
  if (ok == 0)
    return OK;
  else
    return SYSERR;
}

#if PERF
static int
testEncryptPerformance ()
{
  struct PrivateKey *hostkey;
  PublicKey pkey;
  RSAEncryptedData target;
  int i;
  cron_t start;
  int ok;

  fprintf (stderr, "W");
  hostkey = makePrivateKey ();
  getPublicKey (hostkey, &pkey);

  ok = 0;
  start = get_time ();
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
    }
  printf ("%d RSA encrypt operations %llu ms (%d failures)\n",
          ITER, get_time () - start, ok);
  freePrivateKey (hostkey);
  if (ok != 0)
    return SYSERR;
  return OK;
}
#endif

static int
testEncryptDecryptSK ()
{
  struct PrivateKey *hostkey;
  PublicKey pkey;
  RSAEncryptedData target;
  SESSIONKEY insk;
  SESSIONKEY outsk;
  int i;
  TIME_T start;
  int ok;

  fprintf (stderr, "W");
  hostkey = makePrivateKey ();
  getPublicKey (hostkey, &pkey);

  ok = 0;
  TIME (&start);
  for (i = 0; i < ITER; i++)
    {
      fprintf (stderr, ".");
      makeSessionkey (&insk);
      if (SYSERR == encryptPrivateKey (&insk,
                                       sizeof (SESSIONKEY), &pkey, &target))
        {
          fprintf (stderr, "encryptPrivateKey returned SYSERR\n");
          ok++;
          continue;
        }
      if (-1 == decryptPrivateKey (hostkey,
                                   &target, &outsk, sizeof (SESSIONKEY)))
        {
          fprintf (stderr, "decryptPrivateKey returned SYSERR\n");
          ok++;
          continue;
        }
      if (0 != memcmp (&insk, &outsk, sizeof (SESSIONKEY)))
        {
          printf ("testEncryptDecryptSK failed!\n");
          ok++;
          continue;
        }
    }
  printf ("%d RSA encrypt/decrypt SK operations %ds (%d failures)\n",
          ITER, (int) (TIME (NULL) - start), ok);
  freePrivateKey (hostkey);
  if (ok != 0)
    return SYSERR;
  return OK;
}

static int
testSignVerify ()
{
  struct PrivateKey *hostkey;
  Signature sig;
  PublicKey pkey;
  int i;
  TIME_T start;
  int ok = OK;

  fprintf (stderr, "W");
  hostkey = makePrivateKey ();
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
  freePrivateKey (hostkey);
  return ok;
}

#if PERF
static int
testSignPerformance ()
{
  struct PrivateKey *hostkey;
  Signature sig;
  PublicKey pkey;
  int i;
  cron_t start;
  int ok = OK;

  fprintf (stderr, "W");
  hostkey = makePrivateKey ();
  getPublicKey (hostkey, &pkey);
  start = get_time ();
  for (i = 0; i < ITER; i++)
    {
      fprintf (stderr, ".");
      if (SYSERR == sign (hostkey, strlen (TESTSTRING), TESTSTRING, &sig))
        {
          fprintf (stderr, "sign returned SYSERR\n");
          ok = SYSERR;
          continue;
        }
    }
  printf ("%d RSA sign operations %llu ms\n", ITER, get_time () - start);
  freePrivateKey (hostkey);
  return ok;
}
#endif

static int
testPrivateKeyEncoding ()
{
  struct PrivateKey *hostkey;
  PrivateKeyEncoded *encoding;
  PublicKey pkey;
  RSAEncryptedData target;
  char result[MAX_TESTVAL];
  int i;
  TIME_T start;
  int ok = OK;

  fprintf (stderr, "W");
  hostkey = makePrivateKey ();

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
      freePrivateKey (hostkey);
      if (encoding == NULL)
        {
          fprintf (stderr, "encodePrivateKey returned NULL\n");
          ok = SYSERR;
          continue;
        }
      hostkey = decodePrivateKey (encoding);
      FREE (encoding);
      if (SYSERR == decryptPrivateKey (hostkey,
                                       &target,
                                       result, strlen (TESTSTRING) + 1))
        {
          fprintf (stderr, "decryptPrivateKey returned SYSERR\n");
          ok = SYSERR;
          continue;
        }
      if (strncmp (TESTSTRING, result, strlen (TESTSTRING)) != 0)
        {
          printf ("%s != %.*s - testEncryptDecrypt failed!\n",
                  TESTSTRING, (int) strlen (TESTSTRING), result);
          ok = SYSERR;
          continue;
        }
    }
  freePrivateKey (hostkey);
  printf ("%d RSA encrypt/encode/decode/decrypt operations %ds\n",
          ITER, (int) (TIME (NULL) - start));
  return ok;
}

int
main (int argc, char *argv[])
{
  int failureCount = 0;

#if PERF
  if (OK != testEncryptPerformance ())
    failureCount++;
  if (OK != testSignPerformance ())
    failureCount++;
#endif
  if (OK != testEncryptDecryptSK ())
    failureCount++;
  if (OK != testEncryptDecrypt ())
    failureCount++;
  if (OK != testSignVerify ())
    failureCount++;
  if (OK != testPrivateKeyEncoding ())
    failureCount++;

  if (failureCount != 0)
    {
      printf ("\n\n%d TESTS FAILED!\n\n", failureCount);
      return -1;
    }
  return 0;
}                               /* end of main */
