/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_util_network_client.h
 * @brief networking interface for GNUnet clients
 *
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author Gerd Knorr <kraxel@bytesex.org>
 * @author Ioana Patrascu
 * @author Tzvetan Horozov
 */

#ifndef GNUNET_UTIL_NETWORK_CLIENT_H
#define GNUNET_UTIL_NETWORK_CLIENT_H

#include "gnunet_util_network.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

struct GNUNET_ClientServerConnection;

/**
 * Get a connection with gnunetd.
 */
struct GNUNET_ClientServerConnection *GNUNET_client_connection_create (struct
                                                                       GNUNET_GE_Context
                                                                       *ectx,
                                                                       struct
                                                                       GNUNET_GC_Configuration
                                                                       *cfg);

/**
 * Close a GNUnet TCP socket for now (use to temporarily close
 * a TCP connection that will probably not be used for a long
 * time; the socket will still be auto-reopened by the
 * GNUNET_client_connection_read/GNUNET_client_connection_write methods if it is a client-socket).
 *
 * Also, you must still call GNUNET_client_connection_destroy to free all
 * resources associated with the connection.
 */
void GNUNET_client_connection_close_temporarily (struct
                                                 GNUNET_ClientServerConnection
                                                 *sock);

/**
 * Close a GNUnet TCP socket forever.
 * Prevent it from being opened again.
 *
 * Also, you must still call GNUNET_client_connection_destroy to free all
 * resources associated with the connection.
 */
void GNUNET_client_connection_close_forever (struct
                                             GNUNET_ClientServerConnection
                                             *sock);

/**
 * Destroy connection between gnunetd and clients.
 * Also closes the connection if it is still active.
 */
void GNUNET_client_connection_destroy (struct GNUNET_ClientServerConnection
                                       *con);

/**
 * Check if a socket is open. Will ALWAYS return 'true' for a valid
 * client socket (even if the connection is closed), but will return
 * false for a closed server socket.
 *
 * @return GNUNET_YES if open, GNUNET_NO if closed
 */
int GNUNET_client_connection_test_connected (struct
                                             GNUNET_ClientServerConnection
                                             *sock);

/**
 * Check a socket, open and connect if it is closed and it is a
 * client-socket.
 *
 * @return GNUNET_OK if the socket is now open, GNUNET_SYSERR if not
 */
int GNUNET_client_connection_ensure_connected (struct
                                               GNUNET_ClientServerConnection
                                               *sock);

/**
 * Read from a GNUnet client-server connection.
 *
 * @param sock the socket
 * @param buffer the buffer to write data to
 *        if NULL == *buffer, *buffer is allocated (caller frees)
 * @return GNUNET_OK if the read was successful, GNUNET_SYSERR if the socket
 *         was closed by the other side (if the socket is a
 *         client socket and is used again, the next
 *         read/write call will automatically attempt
 *         to re-establish the connection).
 */
int GNUNET_client_connection_read (struct GNUNET_ClientServerConnection *sock,
                                   GNUNET_MessageHeader ** buffer);

/**
 * Write to a GNUnet TCP socket.
 *
 * @param sock the socket to write to
 * @param buffer the buffer to write
 * @return GNUNET_OK if the write was sucessful,
 *         GNUNET_SYSERR if the write failed (error will be logged)
 */
int GNUNET_client_connection_write (struct GNUNET_ClientServerConnection
                                    *sock,
                                    const GNUNET_MessageHeader * buffer);

/**
 * Obtain a simple return value from the connection.
 * Note that the protocol will automatically communicate
 * errors and pass those to the error context used when
 * the socket was created.  In that case, read_result
 * will return GNUNET_SYSERR for the corresponding communication.
 *
 * @param sock the TCP socket
 * @param ret the return value from TCP
 * @return GNUNET_SYSERR on error, GNUNET_OK if the return value was
 *         read successfully
 */
int GNUNET_client_connection_read_result (struct GNUNET_ClientServerConnection
                                          *sock, int *ret);

/**
 * Send a simple return value to the other side.
 *
 * @param sock the TCP socket
 * @param ret the return value to send via TCP
 * @return GNUNET_SYSERR on error, GNUNET_OK if the return value was
 *         send successfully
 */
int GNUNET_client_connection_write_result (struct
                                           GNUNET_ClientServerConnection
                                           *sock, int ret);

/**
 * Stop gnunetd
 *
 * Note that returning an error does NOT mean that
 * gnunetd will continue to run (it may have been
 * shutdown by something else in the meantime or
 * crashed).  Call GNUNET_test_daemon_running() frequently
 * to check the status of gnunetd.
 *
 * Furthermore, note that this WILL potentially kill
 * gnunetd processes on remote machines that cannot
 * be restarted with startGNUnetDaemon!
 *
 * This function does NOT need the PID and will also
 * kill daemonized gnunetd's.
 *
 * @return GNUNET_OK successfully stopped, GNUNET_SYSERR: error
 */
int GNUNET_client_connection_request_daemon_shutdown (struct
                                                      GNUNET_ClientServerConnection
                                                      *sock);

/**
 * Checks if gnunetd is running
 *
 * Uses GNUNET_CS_PROTO_TRAFFIC_COUNT query to determine if gnunetd is
 * running.
 *
 * @return GNUNET_OK if gnunetd is running, GNUNET_SYSERR if not
 */
int GNUNET_test_daemon_running (struct GNUNET_GE_Context *ectx,
                                struct GNUNET_GC_Configuration *cfg);

/**
 * Wait until the gnunet daemon is
 * running.
 *
 * @param timeout how long to wait at most in ms
 * @return GNUNET_OK if gnunetd is now running
 */
int GNUNET_wait_for_daemon_running (struct GNUNET_GE_Context *ectx,
                                    struct GNUNET_GC_Configuration *cfg,
                                    GNUNET_CronTime timeout);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_UTIL_NETWORK_CLIENT_H */
#endif
/* end of gnunet_util_network_client.h */
