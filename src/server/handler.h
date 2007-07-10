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
 * @file server/handler.h
 * @brief Main handler for incoming packets.
 * @author Christian Grothoff
 */

#ifndef HANDLER_H
#define HANDLER_H

#include "gnunet_util.h"
#include "connection.h"


/**
 * Initialize message handling module (make ready to register
 * handlers).
 */
void initHandler (struct GE_Context *e);

/**
 * Shutdown message handling module.
 */
void doneHandler ();

/**
 * Start processing messages from the transports.
 */
void enableCoreProcessing ();

/**
 * Stop processing messages from the transports.
 */
void disableCoreProcessing ();

/**
 * Handle a message (that was decrypted if needed).  Processes the
 * message by calling the registered handler for each message part.
 *
 * @param wasEncrypted YES if it was encrypted,
 *                     NO if plaintext,
 */
void injectMessage (const PeerIdentity * sender,
                    const char *msg,
                    unsigned int size, int wasEncrypted, TSession * session);

/**
 * Processing of a message from the transport layer (receive
 * implementation).  Detects if the message is encrypted, possibly
 * decrypts and calls injectMessage.
 */
void core_receive (P2P_PACKET * mp);

/**
 * Register a method as a handler for specific message
 * types.
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received, if the callback returns
 *        SYSERR, processing of the message is discontinued
 *        afterwards (all other parts are ignored)
 * @return OK on success, SYSERR if there is already a
 *         handler for that type
 */
int registerp2pHandler (const unsigned short type,
                        MessagePartHandler callback);


/**
 * Unregister a method as a handler for specific message
 * types. Only for encrypted messages!
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received
 * @return OK on success, SYSERR if there is a different
 *         handler for that type
 */
int unregisterp2pHandler (const unsigned short type,
                          MessagePartHandler callback);


/**
 * Register a method as a handler for specific message types.  Note
 * that it IS possible to register multiple handlers for the same
 * message.  In that case, they will ALL be executed in the order of
 * registration, unless one of them returns SYSERR in which case the
 * remaining handlers and the rest of the message are ignored.
 *
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received
 * @return OK on success, SYSERR if core threads are running
 *        and updates to the handler list are illegal!
 */
int registerPlaintextHandler (const unsigned short type,
                              PlaintextMessagePartHandler callback);


/**
 * Unregister a method as a handler for specific message types. Only
 * for plaintext messages!
 *
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received
 * @return OK on success, SYSERR if there is a different
 *        handler for that type or if core threads are running
 *        and updates to the handler list are illegal!
 */
int unregisterPlaintextHandler (const unsigned short type,
                                PlaintextMessagePartHandler callback);

/**
 * Is a handler registered for messages of the given type?
 * @param type the message type
 * @param handlerType 0 for plaintext P2P,
 *                    1 for ciphertext P2P,
 *                    2 for either plaintext or ciphertext P2P,
 *                    3 for client-server
 *        NO for ciphertext handlers, SYSERR for either
 * @return number of handlers registered, 0 for none,
 *        SYSERR for invalid value of handlerType
 */
int isHandlerRegistered (unsigned short type, unsigned short handlerType);


#endif
/* end of handler.h */
