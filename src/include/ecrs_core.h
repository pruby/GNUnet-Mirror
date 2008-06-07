/*
     This file is part of GNUnet
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file include/ecrs_core.h
 * @brief support for ECRS encoding of files; also defines
 *        the structs for the various ECRS block types
 *        This file should NOT be installed, it is ONLY
 *        used internally!
 * @author Christian Grothoff
 */

#ifndef GNUNET_ECRS_CORE_H
#define GNUNET_ECRS_CORE_H

#include "gnunet_util.h"
#include "gnunet_datastore_service.h"

/**
 * @brief content hash key
 */
typedef struct
{
  GNUNET_HashCode key;
  GNUNET_HashCode query;
} GNUNET_EC_ContentHashKey;

/**
 * @brief information required to download a file from GNUnet
 *
 * A GNUNET_EC_FileIdentifier groups the information
 * required to download (and check) a file.
 */
typedef struct
{

  /**
   * Total size of the file in bytes. (network byte order (!))
   */
  unsigned long long file_length;

  /**
   * Query and key of the top GNUNET_EC_IBlock.
   */
  GNUNET_EC_ContentHashKey chk;

} GNUNET_EC_FileIdentifier;

/**
 * @brief data block
 */
typedef struct
{

  /**
   * Type of the block, in network byte order.
   */
  unsigned int type;

  /* data follows here */

} GNUNET_EC_DBlock;

typedef struct
{

  /**
   * Type of the block (IBLOCK), in network byte order.
   */
  GNUNET_EC_DBlock iblock;

  GNUNET_EC_ContentHashKey data[1];

} GNUNET_EC_IBlock;

/**
 * @brief keyword block (advertising data under a keyword)
 */
typedef struct
{

  /**
   * Type of the block (KBLOCK), in network byte order.
   */
  unsigned int type;

  /**
   * GNUNET_RSA_Signature using RSA-key generated from search keyword.
   */
  GNUNET_RSA_Signature signature;

  /**
   * Key generated (!) from the H(keyword) as the seed!
   */
  GNUNET_RSA_PublicKey keyspace;

  /* 0-terminated URI here */

  /* variable-size Meta-Data follows here
     (or, in the case of a KSBlock, an SBlock follows) */

} GNUNET_EC_KBlock;

typedef struct
{

  /**
   * Type of the block (SBLOCK), in network byte order.
   */
  unsigned int type;

  /**
   * RSA signature (from pseudonym controlling the namespace)
   */
  GNUNET_RSA_Signature signature;

  /**
   * Public key of the pseudonym; S = H(subspace);
   */
  GNUNET_RSA_PublicKey subspace;

  /* from here on signed */

  /**
   * R = H(H(I))^S, used for routing, or all zeros for
   * namespace advertisements (in which case the
   * 0-terminated update identifier is the name of the
   * root); the URI will be empty in this case and
   * no encryption will be used (this type of SBlock
   * will only be published as the encrypted part of
   * a KSBlock).
   */
  GNUNET_HashCode identifier;
  /* from here on encrypted (with H(I)) */

  /* 0-terminated identifier of update follows
     here; if strlen() == 0, no updates are allowed */

  /* 0-terminated URI (as string) follows here! */

  /* variable-size Meta-Data follows here! */
} GNUNET_EC_SBlock;

/**
 * @brief keyword-GNUNET_EC_SBlock (advertising namespace under a keyword)
 */
typedef struct
{

  /**
   * Type of the block (KSBLOCK), in network byte order.
   */
  unsigned int type;

  GNUNET_EC_KBlock kblock;

  GNUNET_EC_SBlock sblock;
} GNUNET_EC_KSBlock;

/**
 * Perform on-demand content encoding.
 *
 * @param data the data to encode
 * @param len the length of the data
 * @param query the query that was used to query
 *  for the content (verified that it matches
 *  data)
 * @param value the encoded data (set);
 *        the anonymity_level is to be set to 0
 *        (caller should have checked before calling
 *        this method).
 * @return GNUNET_OK on success, GNUNET_SYSERR if data does not
 *  match the query
 */
int GNUNET_EC_file_block_encode (const GNUNET_EC_DBlock * data,
                                 unsigned int len,
                                 const GNUNET_HashCode * query,
                                 GNUNET_DatastoreValue ** value);

/**
 * Get the query that will be used to query for
 * a certain block of data.
 *
 * @param db the block in plaintext
 */
void GNUNET_EC_file_block_get_query (const GNUNET_EC_DBlock * data,
                                     unsigned int len,
                                     GNUNET_HashCode * query);


/**
 * Get the key that will be used to decrypt
 * a certain block of data.
 */
void GNUNET_EC_file_block_get_key (const GNUNET_EC_DBlock * data,
                                   unsigned int len, GNUNET_HashCode * key);

/**
 * What is the type of the given block of data?
 */
unsigned int GNUNET_EC_file_block_get_type (unsigned int size,
                                            const GNUNET_EC_DBlock * data);

/**
 * What is the main query (the one that is used in
 * routing and for the DB lookup) for the given
 * content and block type?
 *
 * @param type the type of the encoding
 * @param data the content (encoded)
 * @param verify should the data be verified?  Use GNUNET_NO if
 *         data integrity has been checked before (maybe much faster!)
 * @param query set to the query for the content
 * @return GNUNET_SYSERR if the content is invalid or
 *   the content type is not known
 */
int GNUNET_EC_file_block_check_and_get_query (unsigned int size,
                                              const GNUNET_EC_DBlock * data,
                                              int verify,
                                              GNUNET_HashCode * query);

/**
 * Verify that the given Datum is a valid response
 * to a given query.
 *
 * @param type the type of the query
 * @param size the size of the data
 * @param data the encoded data
 * @param knownDatumQuery result of GNUNET_EC_file_block_check_and_get_query
 * @param keyCount the number of keys in the query
 * @param keys the keys of the query
 * @return GNUNET_YES if this data matches the query, otherwise
 *         GNUNET_NO; GNUNET_SYSERR if the keyCount does not match the
 *         query type
 */
int GNUNET_EC_is_block_applicable_for_query (unsigned int type,
                                             unsigned int size,
                                             const GNUNET_EC_DBlock * data,
                                             const GNUNET_HashCode *
                                             knownDatumQuery,
                                             unsigned int keyCount,
                                             const GNUNET_HashCode * keys);

#endif
