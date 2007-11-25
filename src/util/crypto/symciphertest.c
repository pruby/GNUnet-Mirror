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
 * SymCipher testcode.
 * @author Christian Grothoff
 * @file util/crypto/symciphertest.c
 */

#include "gnunet_util.h"
#include "gnunet_util_crypto.h"
#include "platform.h"

#define TESTSTRING "Hello World!"
#define INITVALUE "InitializationVectorValue"

static int
testSymcipher ()
{
  GNUNET_AES_SessionKey key;
  char result[100];
  int size;
  char res[100];

  GNUNET_AES_create_session_key (&key);
  size = GNUNET_AES_encrypt (TESTSTRING,
                             strlen (TESTSTRING) + 1,
                             &key,
                             (const GNUNET_AES_InitializationVector *)
                             INITVALUE, result);
  if (size == -1)
    {
      printf ("symciphertest failed: encryptBlock returned %d\n", size);
      return 1;
    }
  size = GNUNET_AES_decrypt (&key,
                             result, size,
                             (const GNUNET_AES_InitializationVector *)
                             INITVALUE, res);
  if (strlen (TESTSTRING) + 1 != size)
    {
      printf ("symciphertest failed: decryptBlock returned %d\n", size);
      return 1;
    }
  if (0 != strcmp (res, TESTSTRING))
    {
      printf ("symciphertest failed: %s != %s\n", res, TESTSTRING);
      return 1;
    }
  else
    return 0;
}

int
verifyCrypto ()
{
  GNUNET_AES_SessionKey key;
  char result[GNUNET_SESSIONKEY_LEN];
  char *res;
  int ret;

  unsigned char plain[] =
    { 29, 128, 192, 253, 74, 171, 38, 187, 84, 219, 76, 76, 209, 118, 33, 249,
    172, 124, 96, 9, 157, 110, 8, 215, 200, 63, 69, 230, 157, 104, 247, 164
  };
  unsigned char raw_key[] =
    { 106, 74, 209, 88, 145, 55, 189, 135, 125, 180, 225, 108, 183, 54, 25,
    169, 129, 188, 131, 75, 227, 245, 105, 10, 225, 15, 115, 159, 148, 184,
    34, 191
  };
  unsigned char encrresult[] =
    { 167, 102, 230, 233, 127, 195, 176, 107, 17, 91, 199, 127, 96, 113, 75,
    195, 245, 217, 61, 236, 159, 165, 103, 121, 203, 99, 202, 41, 23, 222, 25,
    102, 1
  };

  res = NULL;
  ret = 0;

  memcpy (key.key, raw_key, GNUNET_SESSIONKEY_LEN);
  key.crc32 = htonl (GNUNET_crc32_n (&key, GNUNET_SESSIONKEY_LEN));

  if (ntohl (key.crc32) != (unsigned int) 38125195LL)
    {
      printf ("Static key has different CRC: %u - %u\n",
              ntohl (key.crc32), key.crc32);

      ret = 1;
      goto error;
    }

  if (GNUNET_SESSIONKEY_LEN !=
      GNUNET_AES_encrypt (plain,
                          GNUNET_SESSIONKEY_LEN,
                          &key,
                          (const GNUNET_AES_InitializationVector *)
                          "testtesttesttest", result))
    {
      printf ("Wrong return value from encrypt block.\n");
      ret = 1;
      goto error;
    }

  if (memcmp (encrresult, result, GNUNET_SESSIONKEY_LEN) != 0)
    {
      printf ("Encrypted result wrong.\n");
      ret = 1;
      goto error;
    }

  res = GNUNET_malloc (GNUNET_SESSIONKEY_LEN);

  if (GNUNET_SESSIONKEY_LEN !=
      GNUNET_AES_decrypt (&key,
                          result,
                          GNUNET_SESSIONKEY_LEN,
                          (const GNUNET_AES_InitializationVector *)
                          "testtesttesttest", res))
    {
      printf ("Wrong return value from decrypt block.\n");
      ret = 1;
      goto error;
    }

  if (memcmp (res, plain, GNUNET_SESSIONKEY_LEN) != 0)
    {
      printf ("Decrypted result does not match input.\n");

      ret = 1;
    }

error:

  GNUNET_free_non_null (res);

  return ret;
}

int
main (int argc, char *argv[])
{
  int failureCount = 0;

  GNUNET_GE_ASSERT (NULL,
                    strlen (INITVALUE) >
                    sizeof (GNUNET_AES_InitializationVector));
  failureCount += testSymcipher ();
  failureCount += verifyCrypto ();

  if (failureCount != 0)
    {
      printf ("%d TESTS FAILED!\n", failureCount);
      return -1;
    }
  return 0;
}

/* end of symciphertest.c */
