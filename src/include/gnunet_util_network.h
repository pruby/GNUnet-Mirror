/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_util_network.h
 * @brief networking interface to libgnunetutil
 *
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author Gerd Knorr <kraxel@bytesex.org>
 * @author Ioana Patrascu
 * @author Tzvetan Horozov
 */

#ifndef GNUNET_UTIL_NETWORK_H
#define GNUNET_UTIL_NETWORK_H

#include "gnunet_util_config.h"
#include "gnunet_util_string.h"
#include "gnunet_util_os.h"
#include "gnunet_util_threads.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * We use an unsigned short in the protocol header, thus:
 */
#define GNUNET_MAX_BUFFER_SIZE 65536

/**
 * @brief Specify low-level network IO behavior
 */
typedef enum
{

  /**
   * Do not block.
   */
  GNUNET_NC_NONBLOCKING = 0x000,

  /**
   * Call may block.
   */
  GNUNET_NC_BLOCKING = 0x001,

  /**
   * Ignore interrupts (re-try if operation
   * was aborted due to interrupt)
   */
  GNUNET_NC_IGNORE_INT = 0x010,

  /**
   * Always try to read/write the maximum
   * amount of data (using possibly multiple
   * calls).  Only return on non-interrupt
   * error or if completely done.
   */
  GNUNET_NC_COMPLETE_TRANSFER = 0x111,

} GNUNET_NC_KIND;

/**
 * @brief 512-bit hashcode
 */
typedef struct
{
  unsigned int bits[512 / 8 / sizeof (unsigned int)];   /* = 16 */
} GNUNET_HashCode;

/**
 * The identity of the host (basically the SHA-512 hashcode of
 * it's public key).
 */
typedef struct
{
  GNUNET_HashCode hashPubKey GNUNET_PACKED;
} GNUNET_PeerIdentity;

/**
 * Header for all Client-Server communications.
 */
typedef struct
{

  /**
   * The length of the struct (in bytes, including the length field itself)
   */
  unsigned short size GNUNET_PACKED;

  /**
   * The type of the message (XX_CS_PROTO_XXXX)
   */
  unsigned short type GNUNET_PACKED;

} GNUNET_MessageHeader;

/**
 * Client-server communication: simple return value
 */
typedef struct
{

  /**
   * The CS header (values: sizeof(GNUNET_MessageReturnValue) + error-size, GNUNET_CS_PROTO_RETURN_VALUE)
   */
  GNUNET_MessageHeader header;

  /**
   * The return value (network byte order)
   */
  int return_value GNUNET_PACKED;

} GNUNET_MessageReturnValue;

/**
 * Client-server communication: simple error message
 */
typedef struct
{

  /**
   * The CS header.
   */
  GNUNET_MessageHeader header;

  /**
   * The return value (network byte order)
   */
  GNUNET_GE_KIND kind GNUNET_PACKED;

} GNUNET_MessageReturnErrorMessage;

/**
 * @brief IPV4 network in CIDR notation.
 */
struct GNUNET_IPv4NetworkSet;

/**
 * @brief IPV6 network in CIDR notation.
 */
struct GNUNET_IPv6NetworkSet;

/**
 * @brief handle for a system socket
 */
struct GNUNET_SocketHandle;

/**
 * @brief handle for a select manager
 */
struct GNUNET_SelectHandle;

/**
 * @brief callback for handling messages received by select
 *
 * @param sock socket on which the message was received
 *        (should ONLY be used to queue reply using select methods)
 * @return GNUNET_OK if message was valid, GNUNET_SYSERR if corresponding
 *  socket should be closed
 */
typedef int (*GNUNET_SelectMessageHandler) (void *mh_cls,
                                            struct GNUNET_SelectHandle * sh,
                                            struct GNUNET_SocketHandle * sock,
                                            void *sock_ctx,
                                            const GNUNET_MessageHeader * msg);

/**
 * We've accepted a connection, check that
 * the connection is valid and create the
 * corresponding sock_ctx for the new
 * connection.
 *
 * @param addr the address of the other side as reported by OS
 * @param addr_len the size of the address
 * @return NULL to reject connection, otherwise value of sock_ctx
 *         for the new connection
 */
typedef void *(*GNUNET_SelectAcceptHandler) (void *ah_cls,
                                             struct GNUNET_SelectHandle * sh,
                                             struct GNUNET_SocketHandle *
                                             sock, const void *addr,
                                             unsigned int addr_len);

/**
 * Select has been forced to close a connection.
 * Free the associated context.
 */
typedef void (*GNUNET_SelectCloseHandler) (void *ch_cls,
                                           struct GNUNET_SelectHandle * sh,
                                           struct GNUNET_SocketHandle * sock,
                                           void *sock_ctx);

/* *********************** endianess conversion ************* */

/**
 * Convert a long-long to host-byte-order.
 * @param n the value in network byte order
 * @return the same value in host byte order
 */
unsigned long long GNUNET_ntohll (unsigned long long n);

/**
 * Convert a long long to network-byte-order.
 * @param n the value in host byte order
 * @return the same value in network byte order
 */
unsigned long long GNUNET_htonll (unsigned long long n);

/* ***************** basic parsing **************** */

/**
 * Parse a network specification. The argument specifies
 * a list of networks. The format is
 * <tt>[network/netmask;]*</tt> (no whitespace, must be terminated
 * with a semicolon). The network must be given in dotted-decimal
 * notation. The netmask can be given in CIDR notation (/16) or
 * in dotted-decimal (/255.255.0.0).
 * <p>
 * @param routeList a string specifying the forbidden networks
 * @return the converted list, NULL if the syntax is flawed
 */
struct GNUNET_IPv4NetworkSet *GNUNET_parse_ipv4_network_specification (struct
                                                                       GNUNET_GE_Context
                                                                       *ectx,
                                                                       const
                                                                       char
                                                                       *routeList);

/**
 * Parse a network specification. The argument specifies
 * a list of networks. The format is
 * <tt>[network/netmask;]*</tt> (no whitespace, must be terminated
 * with a semicolon). The network must be given in dotted-decimal
 * notation. The netmask can be given in CIDR notation (/16) or
 * in dotted-decimal (/255.255.0.0).
 * <p>
 * @param routeList a string specifying the forbidden networks
 * @return the converted list, NULL if the syntax is flawed
 */
struct GNUNET_IPv6NetworkSet *GNUNET_parse_ipv6_network_specification (struct
                                                                       GNUNET_GE_Context
                                                                       *ectx,
                                                                       const
                                                                       char
                                                                       *routeList);

/**
 * Actual definitions will be in system header files.
 */
struct sockaddr;
struct in_addr;
struct in6_addr;


/**
 * Check if the given IP address is in the list of
 * IP addresses.
 * @param list a list of networks
 * @param ip the IP to check (in network byte order)
 * @return GNUNET_NO if the IP is not in the list, GNUNET_YES if it it is
 */
int GNUNET_check_ipv4_listed (const struct GNUNET_IPv4NetworkSet *list,
                              const struct in_addr *ip);

/**
 * Check if the given IP address is in the list of
 * IP addresses.
 * @param list a list of networks
 * @param ip the IP to check (in network byte order)
 * @return GNUNET_NO if the IP is not in the list, GNUNET_YES if it it is
 */
int GNUNET_check_ipv6_listed (const struct GNUNET_IPv6NetworkSet *list,
                              const struct in6_addr *ip);


/* ********************* low-level socket operations **************** */

/**
 * Create a socket handle by boxing an OS socket.
 * The OS socket should henceforth be no longer used
 * directly.  GNUNET_socket_destroy will close it.
 */
struct GNUNET_SocketHandle *GNUNET_socket_create (struct GNUNET_GE_Context
                                                  *ectx,
                                                  struct GNUNET_LoadMonitor
                                                  *mon, int osSocket);

/**
 * Create a socket handle by boxing an OS socket.
 * The OS socket should henceforth be no longer used
 * directly.  GNUNET_socket_destroy will close it.
 */
struct GNUNET_SocketHandle *
GNUNET_socket_create_connect_to_host (struct GNUNET_LoadMonitor *mon, 
				      const char *hostname,
				      unsigned short port);

/**
 * Close the socket (does NOT destroy it)
 */
void GNUNET_socket_close (struct GNUNET_SocketHandle *s);

/**
 * Destroy the socket (also closes it).
 */
void GNUNET_socket_destroy (struct GNUNET_SocketHandle *s);

/**
 * Depending on doBlock, enable or disable the nonblocking mode
 * of socket s.
 *
 * @return Upon successful completion, it returns zero.
 * @return Otherwise -1 is returned.
 */
int GNUNET_socket_set_blocking (struct GNUNET_SocketHandle *s, int doBlock);

/**
 * Check whether the socket is blocking
 * @param s the socket
 * @return GNUNET_YES if blocking, GNUNET_NO non-blocking
 */
int GNUNET_socket_test_blocking (struct GNUNET_SocketHandle *s);

/**
 * Do a read on the given socket.
 *
 * @brief reads at most max bytes to buf. Interrupts are IGNORED.
 * @param s socket
 * @param nc
 * @param buf buffer
 * @param max maximum number of bytes to read
 * @param read number of bytes actually read.
 *             0 is returned if no more bytes can be read
 * @return GNUNET_SYSERR on error, GNUNET_YES on success or GNUNET_NO if the operation
 *         would have blocked
 */
int GNUNET_socket_recv (struct GNUNET_SocketHandle *s,
                        GNUNET_NC_KIND nc, void *buf, size_t max,
                        size_t * read);

int GNUNET_socket_recv_from (struct GNUNET_SocketHandle *s,
                             GNUNET_NC_KIND nc,
                             void *buf,
                             size_t max,
                             size_t * read, char *from,
                             unsigned int *fromlen);

/**
 * Do a write on the given socket.
 * Write at most max bytes from buf.
 *
 * @param s socket
 * @param buf buffer to send
 * @param max maximum number of bytes to send
 * @param sent number of bytes actually sent
 * @return GNUNET_SYSERR on error, GNUNET_YES on success or
 *         GNUNET_NO if the operation would have blocked.
 */
int GNUNET_socket_send (struct GNUNET_SocketHandle *s,
                        GNUNET_NC_KIND nc, const void *buf, size_t max,
                        size_t * sent);

int GNUNET_socket_send_to (struct GNUNET_SocketHandle *s,
                           GNUNET_NC_KIND nc,
                           const void *buf,
                           size_t max,
                           size_t * sent, const char *dst,
                           unsigned int dstlen);

/**
 * Check if socket is valid
 * @return GNUNET_YES if valid, GNUNET_NO otherwise
 */
int GNUNET_socket_test_valid (struct GNUNET_SocketHandle *s);


/* ********************* select operations **************** */


/**
 * Start a select thread that will accept connections
 * from the given socket and pass messages read to the
 * given message handler.
 *
 * @param desc for debugging (description)
 * @param sock the listen socket
 * @param max_addr_len maximum expected length of addresses for
 *        connections accepted on the given socket
 * @param timeout after how long should inactive connections be
 *        closed?  Use 0 for no timeout.  The specified timeout
 *        will be the default for all new connections;
 *        after (!) returning (!) from the accept handler,
 *        clients can change the timeout of an individual
 *        socket using GNUNET_select_change_timeout.
 * @param mon maybe NULL
 * @param memory_quota amount of memory available for
 *        queueing messages (in bytes)
 * @param socket_quota how many connections do we
 *        accept at most? 0 for unbounded
 * @return NULL on error
 */
struct GNUNET_SelectHandle *GNUNET_select_create (const char *desc,
                                                  int is_udp,
                                                  struct GNUNET_GE_Context
                                                  *ectx,
                                                  struct GNUNET_LoadMonitor
                                                  *mon, int sock,
                                                  unsigned int max_addr_len,
                                                  GNUNET_CronTime timeout,
                                                  GNUNET_SelectMessageHandler
                                                  mh, void *mh_cls,
                                                  GNUNET_SelectAcceptHandler
                                                  ah, void *ah_cls,
                                                  GNUNET_SelectCloseHandler
                                                  ch, void *ch_cls,
                                                  unsigned int memory_quota,
                                                  int socket_quota);

/**
 * Terminate the select thread, close the socket and
 * all associated connections.
 */
void GNUNET_select_destroy (struct GNUNET_SelectHandle *sh);

/**
 * Queue the given message with the select thread.
 *
 * @param mayBlock if GNUNET_YES, blocks this thread until message
 *        has been sent
 * @param force message is important, queue even if
 *        there is not enough space
 * @return GNUNET_OK if the message was sent or queued
 *         GNUNET_NO if there was not enough memory to queue it,
 *         GNUNET_SYSERR if the sock does not belong with this select
 */
int GNUNET_select_write (struct GNUNET_SelectHandle *sh,
                         struct GNUNET_SocketHandle *sock,
                         const GNUNET_MessageHeader * msg, int mayBlock,
                         int force);


/**
 * Would select queue or send the given message at this time?
 *
 * @param mayBlock if GNUNET_YES, blocks this thread until message
 *        has been sent
 * @param size size of the message
 * @param force message is important, queue even if
 *        there is not enough space
 * @return GNUNET_OK if the message would be sent or queued,
 *         GNUNET_NO if there was not enough memory to queue it,
 *         GNUNET_SYSERR if the sock does not belong with this select
 */
int GNUNET_select_test_write_now (struct GNUNET_SelectHandle *sh,
                                  struct GNUNET_SocketHandle *sock,
                                  unsigned int size, int mayBlock, int force);

/**
 * Add another (already connected) socket to the set of
 * sockets managed by the select.
 */
int GNUNET_select_connect (struct GNUNET_SelectHandle *sh,
                           struct GNUNET_SocketHandle *sock, void *sock_ctx);


/**
 * Change the timeout for this socket to a custom
 * value.  Use 0 to use the default timeout for
 * this select.
 */
int GNUNET_select_change_timeout (struct GNUNET_SelectHandle *sh,
                                  struct GNUNET_SocketHandle *sock,
                                  GNUNET_CronTime timeout);

/**
 */
int GNUNET_select_update_closure (struct GNUNET_SelectHandle *sh,
                                  struct GNUNET_SocketHandle *sock,
                                  void *old_sock_ctx, void *new_sock_ctx);

/**
 * Close the associated socket and remove it from the
 * set of sockets managed by select.
 */
int GNUNET_select_disconnect (struct GNUNET_SelectHandle *sh,
                              struct GNUNET_SocketHandle *sock);

/**
 * Convert a string to an IP address. May block!
 *
 * @param hostname the hostname to resolve
 * @param domain AF_INET or AF_INET6; use AF_UNSPEC for "any"
 * @param *sa should be of type "struct sockaddr*" and
 *        will be set to the IP address on success;
 *        if *sa is NULL, sufficient space will be
 *        allocated.
 * @param socklen will be set to the length of *sa.
 *        If *sa is not NULL, socklen will be checked
 *        to see if sufficient space is provided and
 *        updated to the amount of space actually
 *        required/used.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_get_ip_from_hostname (struct GNUNET_GE_Context *ectx,
                             const char *hostname,
                             int domain,
                             struct sockaddr **sa, unsigned int *socklen);

/**
 * Get an IP address as a string (works for both IPv4 and IPv6).  Note
 * that the resolution happens asynchronously and that the first call
 * may not immediately result in the FQN (but instead in a
 * human-readable IP address).
 *
 * @param sa should be of type "struct sockaddr*"
 */
char *GNUNET_get_ip_as_string (const void *sa,
                               unsigned int salen, int do_resolve);

/**
 * Get the IP address for the local machine.
 * @return NULL on error, IP as string otherwise
 */
char *GNUNET_get_local_ip (struct GNUNET_GC_Configuration *cfg,
                           struct GNUNET_GE_Context *ectx,
                           struct in_addr *addr);


/**
 * Change a file descriptor that refers to a pipe
 * to non-blocking IO.
 * @return GNUNET_OK on success
 */
int GNUNET_pipe_make_nonblocking (struct GNUNET_GE_Context *ectx, int pipe);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_UTIL_NETWORK_H */
#endif
/* end of gnunet_util_network.h */
