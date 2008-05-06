/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/ecrs.h
 * @brief shared definitions for ECRS
 * @author Igor Wronsky, Christian Grothoff
 */

#ifndef GNUNET_ECRS_H
#define GNUNET_ECRS_H

#include "ecrs_core.h"
#include "tree.h"
#include <extractor.h>

#define EXTRA_CHECKS ALLOW_EXTRA_CHECKS


/**
 * Fixed GNUNET_EC_SBlock updateInterval codes. Positive values
 * are interpreted as durations (in seconds) for periodical
 * updates.
 */
#define SBLOCK_UPDATE_SPORADIC GNUNET_ECRS_SBLOCK_UPDATE_SPORADIC
#define SBLOCK_UPDATE_NONE     GNUNET_ECRS_SBLOCK_UPDATE_NONE


typedef struct Location
{
  /**
   * Information about the shared file.
   */
  GNUNET_EC_FileIdentifier fi;

  /**
   * Identity of the peer sharing the file.
   */
  GNUNET_RSA_PublicKey peer;

  /**
   * Time when the HELLO *and* this location URI
   * expire (they expire together!).
   */
  GNUNET_Int32Time expirationTime;

  /**
   * RSA signature over the GNUNET_EC_FileIdentifier,
   * GNUNET_hash of the peer and expiration time.
   */
  GNUNET_RSA_Signature contentSignature;

} Location;

enum uri_types
{ chk, sks, ksk, loc };

typedef struct GNUNET_ECRS_URI
{
  enum uri_types type;
  union
  {
    struct
    {
      /**
       * Keywords start with a '+' if they are
       * mandatory (in which case the '+' is NOT
       * part of the keyword) and with a
       * simple space if they are optional
       * (in which case the space is ALSO not
       * part of the actual keyword).
       *
       * Double-quotes to protect spaces and
       * %-encoding are NOT used internally
       * (only in URI-strings).
       */
      char **keywords;
      unsigned int keywordCount;
    } ksk;
    struct
    {
      GNUNET_HashCode namespace;
      GNUNET_HashCode identifier;
    } sks;
    GNUNET_EC_FileIdentifier fi;
    Location loc;
  } data;
} URI;

typedef struct
{
  EXTRACTOR_KeywordType type;
  char *data;
} Item;

/**
 * Meta data to associate with a file, directory or namespace.
 */
typedef struct GNUNET_ECRS_MetaData
{
  unsigned int itemCount;
  Item *items;
} MetaData;


void GNUNET_ECRS_encryptInPlace (const GNUNET_HashCode * hc,
                                 void *data, unsigned int len);

void GNUNET_ECRS_decryptInPlace (const GNUNET_HashCode * hc,
                                 void *data, unsigned int len);



#endif
