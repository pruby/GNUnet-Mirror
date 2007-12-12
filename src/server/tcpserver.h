/*
     This file is part of GNUnet
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file server/tcpserver.h
 * @brief TCP server (gnunetd-client communication).
 * @author Christian Grothoff
 */

#ifndef TCPSERVER_H
#define TCPSERVER_H

#include "gnunet_util.h"
#include "gnunet_core.h"

/**
 * Initialize the TCP port and listen for incoming client connections.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_CORE_cs_init (struct GNUNET_GE_Context *ectx,
                         struct GNUNET_GC_Configuration *cfg);

/**
 * Stop the server (but do not yet destroy the data structures)
 */
int GNUNET_CORE_stop_cs_server (void);

/**
 * Shutdown the module.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_CORE_cs_done (void);

/**
 * Register a method as a handler for specific message
 * types.
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received, if the callback returns
 *        GNUNET_SYSERR, processing of the message is discontinued
 *        afterwards (all other parts are ignored)
 * @return GNUNET_OK on success, GNUNET_SYSERR if there is already a
 *         handler for that type
 */
int GNUNET_CORE_register_handler (unsigned short type,
                                  GNUNET_ClientRequestHandler callback);

/**
 * Unregister a method as a handler for specific message
 * types.
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received, if the callback returns
 *        GNUNET_SYSERR, processing of the message is discontinued
 *        afterwards (all other parts are ignored)
 * @return GNUNET_OK on success, GNUNET_SYSERR if there is no or another
 *         handler for that type
 */
int GNUNET_CORE_unregister_handler (unsigned short type,
                                    GNUNET_ClientRequestHandler callback);

int GNUNET_CORE_cs_register_exit_handler (GNUNET_ClientExitHandler callback);

int GNUNET_CORE_cs_exit_handler_unregister (GNUNET_ClientExitHandler
                                            callback);

/**
 * Send a message to the client identified by the handle.  Note that
 * the core will typically buffer these messages as much as possible
 * and only return GNUNET_SYSERR if it runs out of buffers.  Returning GNUNET_OK
 * on the other hand does NOT confirm delivery since the actual
 * transfer happens asynchronously.
 */
int GNUNET_CORE_cs_send_to_client (struct GNUNET_ClientHandle *handle,
                                   const GNUNET_MessageHeader * message,
                                   int force);


/**
 * Send a return value to the caller of a remote call via
 * TCP.
 * @param sock the TCP socket
 * @param ret the return value to send via TCP
 * @return GNUNET_SYSERR on error, GNUNET_OK if the return value was
 *         send successfully
 */
int GNUNET_CORE_cs_send_result_to_client (struct GNUNET_ClientHandle *sock,
                                          int ret);

/**
 * Send an error message to the caller of a remote call via
 * TCP.
 * @param sock the TCP socket
 * @param message the error message to send via TCP
 * @return GNUNET_SYSERR on error, GNUNET_OK if the return value was
 *         send successfully
 */
int GNUNET_CORE_cs_send_error_to_client (struct GNUNET_ClientHandle *sock,
                                         GNUNET_GE_KIND kind,
                                         const char *message);

void GNUNET_CORE_cs_terminate_client_connection (struct GNUNET_ClientHandle
                                                 *sock);

/**
 * Check if a handler is registered for a given
 * message type.
 *
 * @param type the message type
 * @return number of registered handlers (0 or 1)
 */
unsigned int GNUNET_CORE_cs_test_handler_registered (unsigned short type);

struct GNUNET_GE_Context
  *GNUNET_CORE_cs_create_client_log_context (GNUNET_GE_KIND mask,
                                             struct GNUNET_ClientHandle
                                             *handle);

#endif
/* end of tcpserver.h */
