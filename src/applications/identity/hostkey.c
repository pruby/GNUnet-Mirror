/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file identity/hostkey.c
 * @brief module encapsulating our secret key for the peer
 *
 * @author Christian Grothoff
 */

#include "hostkey.h"
#include "gnunet_directories.h"
#include "platform.h"

#define EXTRA_CHECKS ALLOW_EXTRA_CHECKS

/**
 * Name of the file in which we store the hostkey.
 */
#define HOSTKEYFILE ".hostkey"

/**
 * The SECRET hostkey.  Keep local, never export outside of this
 * module!
 */
static struct GNUNET_RSA_PrivateKey *hostkey;

/**
 * The public hostkey
 */
static GNUNET_RSA_PublicKey publicKey;

/**
 * Get the public key of the host
 *
 * @return reference to the public key. Do not free it!
 */
const GNUNET_RSA_PublicKey *
getPublicPrivateKey ()
{
  return &publicKey;
}

/**
 * Sign arbitrary data. ALWAYS use only on data we generated
 * entirely!
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int
signData (const void *data, unsigned short size,
          GNUNET_RSA_Signature * result)
{
  int ret;

  ret = GNUNET_RSA_sign (hostkey, size, data, result);
#if EXTRA_CHECKS
  if (ret == GNUNET_OK)
    {
      GNUNET_GE_ASSERT (NULL,
                        GNUNET_OK == GNUNET_RSA_verify (data, size, result,
                                                        &publicKey));
    }
#endif
  return ret;
}

/**
 * Decrypt a given block with the hostkey.
 *
 * @param block the data to decrypt, encoded as returned by encrypt, not consumed
 * @param result pointer to a location where the result can be stored
 * @param max the maximum number of bits to store for the result, if
 *        the decrypted block is bigger, an error is returned
 * @returns the size of the decrypted block, -1 on error
 */
int
decryptData (const GNUNET_RSA_EncryptedData * block, void *result,
             unsigned int max)
{
  return GNUNET_RSA_decrypt (hostkey, block, result, max);
}

void
initPrivateKey (struct GNUNET_GE_Context *ectx,
                struct GNUNET_GC_Configuration *cfg)
{
  char *gnHome;
  char *hostkeyfile;
  GNUNET_RSA_PrivateKeyEncoded *encPrivateKey;
  unsigned short len;
  int res;

  GNUNET_GE_ASSERT (ectx,
                    -1 != GNUNET_GC_get_configuration_value_filename (cfg,
                                                                      "GNUNETD",
                                                                      "GNUNETD_HOME",
                                                                      GNUNET_DEFAULT_DAEMON_VAR_DIRECTORY,
                                                                      &gnHome));
  GNUNET_disk_directory_create (ectx, gnHome);
  if (GNUNET_YES != GNUNET_disk_directory_test (ectx, gnHome))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_FATAL | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_IMMEDIATE,
                     _("Failed to access GNUnet home directory `%s'\n"),
                     gnHome);
      abort ();
    }

  /* read or create public key */
  hostkeyfile = GNUNET_malloc (strlen (gnHome) + strlen (HOSTKEYFILE) + 2);
  strcpy (hostkeyfile, gnHome);
  GNUNET_free (gnHome);
  if (hostkeyfile[strlen (hostkeyfile) - 1] != DIR_SEPARATOR)
    strcat (hostkeyfile, DIR_SEPARATOR_STR);
  strcat (hostkeyfile, HOSTKEYFILE);
  res = 0;
  if (GNUNET_YES == GNUNET_disk_file_test (ectx, hostkeyfile))
    {
      res =
        GNUNET_disk_file_read (ectx, hostkeyfile, sizeof (unsigned short),
                               &len);
    }
  encPrivateKey = NULL;
  if (res == sizeof (unsigned short))
    {
      encPrivateKey =
        (GNUNET_RSA_PrivateKeyEncoded *) GNUNET_malloc (ntohs (len));
      if (ntohs (len) !=
          GNUNET_disk_file_read (ectx, hostkeyfile, ntohs (len),
                                 encPrivateKey))
        {
          GNUNET_free (encPrivateKey);
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_USER |
                         GNUNET_GE_IMMEDIATE | GNUNET_GE_ADMIN,
                         _
                         ("Existing hostkey in file `%s' failed format check, creating new hostkey.\n"),
                         hostkeyfile);
          encPrivateKey = NULL;
        }
    }
  if (encPrivateKey == NULL)
    {                           /* make new hostkey */
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_BULK,
                     _("Creating new hostkey (this may take a while).\n"));
      hostkey = GNUNET_RSA_create_key ();
      GNUNET_GE_ASSERT (ectx, hostkey != NULL);
      encPrivateKey = GNUNET_RSA_encode_key (hostkey);
      GNUNET_GE_ASSERT (ectx, encPrivateKey != NULL);
      GNUNET_disk_file_write (ectx,
                              hostkeyfile,
                              encPrivateKey, ntohs (encPrivateKey->len),
                              "600");
      GNUNET_free (encPrivateKey);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_BULK,
                     _("Done creating hostkey.\n"));
    }
  else
    {
      hostkey = GNUNET_RSA_decode_key (encPrivateKey);
      GNUNET_free (encPrivateKey);
    }
  GNUNET_free (hostkeyfile);
  GNUNET_GE_ASSERT (ectx, hostkey != NULL);
  GNUNET_RSA_get_public_key (hostkey, &publicKey);
}


void
donePrivateKey ()
{
  GNUNET_GE_ASSERT (NULL, hostkey != NULL);
  GNUNET_RSA_free_key (hostkey);
  hostkey = NULL;
}

/* end of hostkey.c */
