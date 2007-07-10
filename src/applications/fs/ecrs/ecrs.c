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
ECRS_encryptInPlace (const HashCode512 * hc, void *data, unsigned int len)
{
  char *tmp;
  SESSIONKEY skey;
  INITVECTOR iv;

  hashToKey (hc, &skey, &iv);
  tmp = MALLOC (len);
  GE_ASSERT (NULL, len == encryptBlock (data, len, &skey, &iv, tmp));
  memcpy (data, tmp, len);
  FREE (tmp);
}

void
ECRS_decryptInPlace (const HashCode512 * hc, void *data, unsigned int len)
{
  char *tmp;
  SESSIONKEY skey;
  INITVECTOR iv;

  hashToKey (hc, &skey, &iv);
  tmp = MALLOC (len);
  GE_ASSERT (NULL, len == decryptBlock (&skey, data, len, &iv, tmp));
  memcpy (data, tmp, len);
  FREE (tmp);
}

/* end of ecrs.c */
