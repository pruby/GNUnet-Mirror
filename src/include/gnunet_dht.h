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
 * @file include/gnunet_dht.h
 * @brief data structures exchanged between between DHT clients and the GNUnet DHT module
 * @author Tomi Tukiainen, Marko Räihä, Christian Grothoff
 *
 * Typical clients are likely to prefer using the synchronous
 * gnunet_dht_lib instead of sending these messages manually.
 */

#ifndef GNUNET_DHT_H
#define GNUNET_DHT_H 

#include "gnunet_util.h"

/* ************* API specific errorcodes *********** */

#define DHT_ERRORCODES__TIMEOUT -2
#define DHT_ERRORCODES__OUT_OF_SPACE -3
#define DHT_ERRORCODES__TABLE_NOT_FOUND -4


/* ************************* CS messages ***************************** */
/* these messages are exchanged between gnunetd and the clients (APIs) */

/**
 * DHT table identifier.  A special identifier (all zeros) is
 * used internally by the DHT.  That table is used to lookup
 * tables.  The GNUnet DHT infrastructure supports multiple
 * tables, the table to lookup peers is just one of these.
 */
typedef HashCode160 DHT_TableId; 

#define equalsDHT_TableId(a,b) equalsHashCode160(a,b)

/**
 * TCP communication: client to gnunetd: join table.
 * All future communications via this socket are reserved
 * for either gnunetd requesting datastore operations or 
 * the client sending a leave table message.
 */
typedef struct {

  CS_HEADER header;

  unsigned long long timeout;  /* nbo */

  DHT_TableId table;  

} DHT_CS_REQUEST_JOIN;

/**
 * TCP communication: client to gnunetd: leave table 
 */
typedef struct {

  CS_HEADER header;
  
  unsigned long long timeout;  /* nbo */

  DHT_TableId table;  

} DHT_CS_REQUEST_LEAVE; 


/**
 * TCP communication: put <key,value>-mapping to table.
 * Reply is an ACK.
 */
typedef struct {

  CS_HEADER header;
  
  unsigned long long timeout;  /* nbo */
  
  DHT_TableId table; 

  HashCode160 key;

} DHT_CS_REQUEST_PUT;

/**
 * TCP communication: put <key,value>-mapping to table.
 * Reply is an ACK.
 */
typedef struct {

  DHT_CS_REQUEST_PUT dht_cs_request_put;

  char value[1];

} DHT_CS_REQUEST_PUT_GENERIC;

/**
 * TCP communication: get <key,value>-mappings
 * for given key. Reply is a DHT_CS_REPLY_RESULTS message.
 */
typedef struct {

  CS_HEADER header;

  unsigned int type;

  unsigned long long timeout;  /* nbo */

  DHT_TableId table; 

  /* one or more keys */
  HashCode160 keys;

} DHT_CS_REQUEST_GET;

/**
 * remove value.  Reply is just an ACK.
 */
typedef struct {

  CS_HEADER header;
  
  unsigned long long timeout; /* nbo */

  DHT_TableId table; 
  
  HashCode160 key;

} DHT_CS_REQUEST_REMOVE;

/**
 * remove value.  Reply is just an ACK.
 */
typedef struct {

  DHT_CS_REQUEST_REMOVE dht_cs_request_remove;

  char value[1];

} DHT_CS_REQUEST_REMOVE_GENERIC;


/**
 * gnunetd to client: iterate over all values.  Reply is
 * a DHT_CS_REPLY_RESULTS message.
 */
typedef struct {

  CS_HEADER header;
  
} DHT_CS_REQUEST_ITERATE;

/**
 * TCP communication: Results for a request.  Uses a separate message
 * for each result; DHT_CS_REPLY_RESULTS maybe repeated many
 * times (the total number is given in totalResults).
 */
typedef struct {

  CS_HEADER header;

  unsigned int totalResults;

  DHT_TableId table; 

} DHT_CS_REPLY_RESULTS;

/**
 * TCP communication: Results for a request.  If not all results fit
 * into a single message, DHT_CS_REPLY_RESULTS maybe repeated many
 * times.
 */
typedef struct {

  DHT_CS_REPLY_RESULTS dht_cs_reply_results;

  /**
   * Results data; serialized version of DataContainer.
   */
  char data[1]; 

} DHT_CS_REPLY_RESULTS_GENERIC;


/**
 * TCP communication: status response for a request
 */
typedef struct {

  CS_HEADER header;

  int status; /* NBO */

  DHT_TableId table; 

} DHT_CS_REPLY_ACK;

#endif /* GNUNET_DHT_H */
