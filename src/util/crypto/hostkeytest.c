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
#define MAX_TESTVAL sizeof(GNUNET_AES_SessionKey)
#define ITER 10

#define PERF GNUNET_NO

static int
testEncryptDecrypt ()
{
  struct GNUNET_RSA_PrivateKey *hostkey;
  GNUNET_RSA_PublicKey pkey;
  GNUNET_RSA_EncryptedData target;
  char result[MAX_TESTVAL];
  int i;
  GNUNET_Int32Time start;
  int ok;

  fprintf (stderr, "W");
  hostkey = GNUNET_RSA_create_key ();
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
  GNUNET_RSA_free_key (hostkey);
  if (ok == 0)
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
}

#if PERF
static int
testEncryptPerformance ()
{
  struct GNUNET_RSA_PrivateKey *hostkey;
  GNUNET_RSA_PublicKey pkey;
  GNUNET_RSA_EncryptedData target;
  int i;
  GNUNET_CronTime start;
  int ok;

  fprintf (stderr, "W");
  hostkey = GNUNET_RSA_create_key ();
  GNUNET_RSA_get_public_key (hostkey, &pkey);

  ok = 0;
  start = GNUNET_get_time ();
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
    }
  printf ("%d RSA encrypt operations %llu ms (%d failures)\n",
          ITER, GNUNET_get_time () - start, ok);
  GNUNET_RSA_free_key (hostkey);
  if (ok != 0)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}
#endif

static int
testEncryptDecryptSK ()
{
  struct GNUNET_RSA_PrivateKey *hostkey;
  GNUNET_RSA_PublicKey pkey;
  GNUNET_RSA_EncryptedData target;
  GNUNET_AES_SessionKey insk;
  GNUNET_AES_SessionKey outsk;
  int i;
  GNUNET_Int32Time start;
  int ok;

  fprintf (stderr, "W");
  hostkey = GNUNET_RSA_create_key ();
  GNUNET_RSA_get_public_key (hostkey, &pkey);

  ok = 0;
  GNUNET_get_time_int32 (&start);
  for (i = 0; i < ITER; i++)
    {
      fprintf (stderr, ".");
      GNUNET_AES_create_session_key (&insk);
      if (GNUNET_SYSERR == GNUNET_RSA_encrypt (&insk,
                                               sizeof (GNUNET_AES_SessionKey),
                                               &pkey, &target))
        {
          fprintf (stderr, "encryptPrivateKey returned SYSERR\n");
          ok++;
          continue;
        }
      if (-1 == GNUNET_RSA_decrypt (hostkey,
                                    &target, &outsk,
                                    sizeof (GNUNET_AES_SessionKey)))
        {
          fprintf (stderr, "decryptPrivateKey returned SYSERR\n");
          ok++;
          continue;
        }
      if (0 != memcmp (&insk, &outsk, sizeof (GNUNET_AES_SessionKey)))
        {
          printf ("testEncryptDecryptSK failed!\n");
          ok++;
          continue;
        }
    }
  printf ("%d RSA encrypt/decrypt SK operations %ds (%d failures)\n",
          ITER, (int) (GNUNET_get_time_int32 (NULL) - start), ok);
  GNUNET_RSA_free_key (hostkey);
  if (ok != 0)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

static int
testSignVerify ()
{
  struct GNUNET_RSA_PrivateKey *hostkey;
  GNUNET_RSA_Signature sig;
  GNUNET_RSA_PublicKey pkey;
  int i;
  GNUNET_Int32Time start;
  int ok = GNUNET_OK;

  fprintf (stderr, "W");
  hostkey = GNUNET_RSA_create_key ();
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
  GNUNET_RSA_free_key (hostkey);
  return ok;
}

#if PERF
static int
testSignPerformance ()
{
  struct GNUNET_RSA_PrivateKey *hostkey;
  GNUNET_RSA_Signature sig;
  GNUNET_RSA_PublicKey pkey;
  int i;
  GNUNET_CronTime start;
  int ok = GNUNET_OK;

  fprintf (stderr, "W");
  hostkey = GNUNET_RSA_create_key ();
  GNUNET_RSA_get_public_key (hostkey, &pkey);
  start = GNUNET_get_time ();
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
    }
  printf ("%d RSA sign operations %llu ms\n", ITER,
          GNUNET_get_time () - start);
  GNUNET_RSA_free_key (hostkey);
  return ok;
}
#endif

static int
testPrivateKeyEncoding ()
{
  struct GNUNET_RSA_PrivateKey *hostkey;
  GNUNET_RSA_PrivateKeyEncoded *encoding;
  GNUNET_RSA_PublicKey pkey;
  GNUNET_RSA_EncryptedData target;
  char result[MAX_TESTVAL];
  int i;
  GNUNET_Int32Time start;
  int ok = GNUNET_OK;

  fprintf (stderr, "W");
  hostkey = GNUNET_RSA_create_key ();

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
      GNUNET_RSA_free_key (hostkey);
      if (encoding == NULL)
        {
          fprintf (stderr, "encodePrivateKey returned NULL\n");
          ok = GNUNET_SYSERR;
          continue;
        }
      hostkey = GNUNET_RSA_decode_key (encoding);
      GNUNET_free (encoding);
      if (GNUNET_SYSERR == GNUNET_RSA_decrypt (hostkey,
                                               &target,
                                               result,
                                               strlen (TESTSTRING) + 1))
        {
          fprintf (stderr, "decryptPrivateKey returned SYSERR\n");
          ok = GNUNET_SYSERR;
          continue;
        }
      if (strncmp (TESTSTRING, result, strlen (TESTSTRING)) != 0)
        {
          printf ("%s != %.*s - testEncryptDecrypt failed!\n",
                  TESTSTRING, (int) strlen (TESTSTRING), result);
          ok = GNUNET_SYSERR;
          continue;
        }
    }
  GNUNET_RSA_free_key (hostkey);
  printf ("%d RSA encrypt/encode/decode/decrypt operations %ds\n",
          ITER, (int) (GNUNET_get_time_int32 (NULL) - start));
  return ok;
}

int
main (int argc, char *argv[])
{
  int failureCount = 0;

  GNUNET_disable_entropy_gathering ();
#if PERF
  if (GNUNET_OK != testEncryptPerformance ())
    failureCount++;
  if (GNUNET_OK != testSignPerformance ())
    failureCount++;
#endif
  if (GNUNET_OK != testEncryptDecryptSK ())
    failureCount++;
  if (GNUNET_OK != testEncryptDecrypt ())
    failureCount++;
  if (GNUNET_OK != testSignVerify ())
    failureCount++;
  if (GNUNET_OK != testPrivateKeyEncoding ())
    failureCount++;

  if (failureCount != 0)
    {
      printf ("\n\n%d TESTS FAILED!\n\n", failureCount);
      return -1;
    }
  return 0;
}                               /* end of main */
