/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004 Christian Grothoff (and other contributing authors)

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
 * @file util/tcp_return.c
 * @brief code to communicate simple (int) return values via reliable
 *        TCP stream
 * @author Christian Grothoff
 *
 * Helper methods to send and receive return values over a TCP stream
 * that has tcpio (see util/tcpio.c) semantics.
 */

#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "platform.h"

/**
 * Obtain a return value from a remote call from TCP.
 *
 * @param sock the TCP socket
 * @param ret the return value from TCP
 * @return SYSERR on error, OK if the return value was read
 * successfully
 */
int readTCPResult(GNUNET_TCP_SOCKET * sock,
		  int * ret) {
  CS_returnvalue_MESSAGE * rv;

  rv = NULL;
  if (SYSERR == readFromSocket(sock,
			       (CS_MESSAGE_HEADER **) &rv)) {
    LOG(LOG_WARNING,
	_("`%s' failed, other side closed connection.\n"),
	__FUNCTION__);
    return SYSERR;
  }
  if ( (ntohs(rv->header.size) != sizeof(CS_returnvalue_MESSAGE)) ||
       (ntohs(rv->header.type) != CS_PROTO_RETURN_VALUE) ) {
    LOG(LOG_WARNING,
	_("`%s' failed, reply invalid!\n"),
	__FUNCTION__);
    FREE(rv);
    return SYSERR;
  }
  *ret = ntohl(rv->return_value);
  FREE(rv);
  return OK;
}

/**
 * Send a return value to the caller of a remote call via
 * TCP.
 * @param sock the TCP socket
 * @param ret the return value to send via TCP
 * @return SYSERR on error, OK if the return value was
 *         send successfully
 */
int sendTCPResult(GNUNET_TCP_SOCKET * sock,
		  int ret) {
  CS_returnvalue_MESSAGE rv;

  rv.header.size
    = htons(sizeof(CS_returnvalue_MESSAGE));
  rv.header.type
    = htons(CS_PROTO_RETURN_VALUE);
  rv.return_value
    = htonl(ret);
  return writeToSocket(sock,
		       &rv.header);
}





/* end of tcp_return.c */
