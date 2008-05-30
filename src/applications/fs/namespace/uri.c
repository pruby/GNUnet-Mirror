/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/namespace/uri.c
 * @brief uri support
 * @author Christian Grothoff
 *
 * TODO:
 * - consider remembering the char*-form of the
 *   namespace identifier (optionally?)
 *   => generate better names when possible!
 *   (this would require changes in ECRS!)
 */

#include "platform.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_namespace_lib.h"
#include "gnunet_pseudonym_lib.h"

/**
 * Convert namespace URI to a human readable format
 * (using the namespace description, if available).
 */
char *
GNUNET_NS_sks_uri_to_human_readable_string (struct GNUNET_GE_Context *ectx,
                                            struct GNUNET_GC_Configuration
                                            *cfg,
                                            const struct GNUNET_ECRS_URI *uri)
{
  GNUNET_EncName enc;
  char *ret;
  char *name;
  GNUNET_HashCode nsid;
  GNUNET_HashCode chk;

  if (!GNUNET_ECRS_uri_test_sks (uri))
    return NULL;
  GNUNET_ECRS_uri_get_namespace_from_sks (uri, &nsid);
  name = GNUNET_PSEUDO_id_to_name (ectx, cfg, &nsid);
  if (name == NULL)
    return GNUNET_ECRS_uri_to_string (uri);
  GNUNET_ECRS_uri_get_content_hash_from_sks (uri, &chk);
  GNUNET_hash_to_enc (&chk, &enc);
  ret = GNUNET_malloc (strlen (name) + 4 + sizeof (GNUNET_EncName));
  strcpy (ret, name);
  strcat (ret, ": ");
  strcat (ret, (const char *) &enc);
  return ret;
}

/* end of uri.c */
