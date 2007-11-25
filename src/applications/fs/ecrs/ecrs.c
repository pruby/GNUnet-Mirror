/*
     This file is part of GNUnet.
     (C) 2004, 2005. 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/ecrs.c
 * @brief ECRS helper functions
 * @see http://gnunet.org/encoding.php3
 * @author Krista Bennett
 * @author Christian Grothoff
 */

#include "platform.h"
#include "ecrs.h"

void
GNUNET_ECRS_encryptInPlace (const GNUNET_HashCode * hc, void *data,
                            unsigned int len)
{
  char *tmp;
  GNUNET_AES_SessionKey skey;
  GNUNET_AES_InitializationVector iv;

  GNUNET_hash_to_AES_key (hc, &skey, &iv);
  tmp = GNUNET_malloc (len);
  GNUNET_GE_ASSERT (NULL,
                    len == GNUNET_AES_encrypt (data, len, &skey, &iv, tmp));
  memcpy (data, tmp, len);
  GNUNET_free (tmp);
}

void
GNUNET_ECRS_decryptInPlace (const GNUNET_HashCode * hc, void *data,
                            unsigned int len)
{
  char *tmp;
  GNUNET_AES_SessionKey skey;
  GNUNET_AES_InitializationVector iv;

  GNUNET_hash_to_AES_key (hc, &skey, &iv);
  tmp = GNUNET_malloc (len);
  GNUNET_GE_ASSERT (NULL,
                    len == GNUNET_AES_decrypt (&skey, data, len, &iv, tmp));
  memcpy (data, tmp, len);
  GNUNET_free (tmp);
}

/* end of ecrs.c */
