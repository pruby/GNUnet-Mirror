/*
     This file is part of GNUnet

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
 * @file applications/fs/module/fs.h
 * @brief FS Client-Server messages
 * @author Christian Grothoff
 */
#ifndef FS_H
#define FS_H

#include "gnunet_blockstore.h"

/**
 * Client to server: search for content.  Variable
 * size message, there is at least one query, but
 * there maybe more than one (the semantics depend
 * on the type).
 */
typedef struct {
  CS_HEADER header;

  /** 
   * Priority of the search.
   */
  unsigned int prio;

  /**
   * At what time does the search expire?
   */
  cron_t expiration;

  /**
   * Type of the content that we're looking for.
   * 0 for any.
   */
  unsigned int type;

  /**
   * What are the anonymity requirements for this content?
   * Use 0 if anonymity is not required (enables direct
   * sharing / DHT routing).
   */
  unsigned int anonymityLevel;

  /**
   * What are the queries?
   */
  HashCode160 query[1];

} RequestSearch;

/**
 * Server to client: content (in response to a RequestSearch).  The
 * header is followed by variable size data (the data portion
 * of the Datastore_Value).
 */
typedef struct {
  CS_HEADER header;

} ReplyContent;


/**
 * Client to server: insert content.
 * This struct is followed by a variable
 * number of bytes of content.
 */
typedef struct {
  CS_HEADER header;

  /** 
   * Priority for the on-demand encoded entry.
   */
  unsigned int prio;

  /**
   * At what time does the entry expire?
   */
  cron_t expiration;

  /**
   * What are the anonymity requirements for this content?
   * Use 0 if anonymity is not required (enables direct
   * sharing / DHT routing).
   */
  unsigned int anonymityLevel;

} RequestInsert;

/**
 * Client to server: index content (for on-demand
 * encoding).  This struct is followed by a variable
 * number of bytes of content.
 */
typedef struct {
  CS_HEADER header;

  /** 
   * Priority for the on-demand encoded entry.
   */
  unsigned int prio;

  /**
   * At what time does the entry expire?
   */
  cron_t expiration;

  /**
   * At what offset in the plaintext file is
   * this content stored?
   */
  unsigned long long fileOffset;

  /**
   * What are the anonymity requirements for this content?
   * Use 0 if anonymity is not required (enables direct
   * sharing / DHT routing).
   */
  unsigned int anonymityLevel;

  /**
   * What is the hash of the file that contains
   * this block?  Used by gnunetd for the name
   * of the file in the on-demand datastore.
   */
  HashCode160 fileId;

} RequestIndex;

/**
 * Client to server: delete content.  This struct is followed by a
 * variable number of bytes of the content that is to be deleted.
 */
typedef struct {
  CS_HEADER header;

} RequestDelete;


/**
 * Client to server: unindex file.
 */
typedef struct {
  CS_HEADER header;

  /**
   * Size of each block of the file.
   */
  unsigned int blocksize;

  /**
   * What is the hash of the file that should be
   * unindexed?
   */
  HashCode160 fileId;

} RequestUnindex;

/**
 * Client to server: test if file is indexed
 */
typedef struct {
  CS_HEADER header;

  /**
   * What is the hash of the file that should be
   * unindexed?
   */
  HashCode160 fileId;

} RequestTestindex;


/**
 * Encapsulation of the data in the format that is passed through gap.
 * We essentially add the timeout value since that part is supposed to
 * be communicated to other peers.
 */
typedef struct {
  DataContainer dc;
  unsigned long long timeout;
} GapWrapper;


#endif
