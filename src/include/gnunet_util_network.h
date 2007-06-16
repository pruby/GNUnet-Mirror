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
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * We use an unsigned short in the protocol header, thus:
 */
#define MAX_BUFFER_SIZE 65536

/**
 * @brief Specify low-level network IO behavior
 */
typedef enum {

  /**
   * Do not block.
   */
  NC_Nonblocking = 0x000,

  /**
   * Call may block.
   */
  NC_Blocking    = 0x001,

  /**
   * Ignore interrupts (re-try if operation
   * was aborted due to interrupt)
   */
  NC_IgnoreInt   = 0x010,

  /**
   * Always try to read/write the maximum
   * amount of data (using possibly multiple
   * calls).  Only return on non-interrupt
   * error or if completely done.
   */
  NC_Complete    = 0x111,

} NC_KIND;

/**
 * @brief 512-bit hashcode
 */
typedef struct {
  unsigned int bits[512 / 8 / sizeof(unsigned int)]; /* = 16 */
} HashCode512;

/**
 * The identity of the host (basically the SHA-512 hashcode of
 * it's public key).
 */
typedef struct {
  HashCode512 hashPubKey;
} PeerIdentity;

/**
 * Header for all Client-Server communications.
 */
typedef struct {

  /**
   * The length of the struct (in bytes, including the length field itself)
   */
  unsigned short size;

  /**
   * The type of the message (XX_CS_PROTO_XXXX)
   */
  unsigned short type;

} MESSAGE_HEADER;

/**
 * Client-server communication: simple return value
 */
typedef struct {

  /**
   * The CS header (values: sizeof(CS_returnvalue_MESSAGE) + error-size, CS_PROTO_RETURN_VALUE)
   */
  MESSAGE_HEADER header;

  /**
   * The return value (network byte order)
   */
  int return_value;

} RETURN_VALUE_MESSAGE;

/**
 * Client-server communication: simple error message
 */
typedef struct {

  /**
   * The CS header (values: sizeof(CS_returnvalue_MESSAGE) + error-size, CS_PROTO_RETURN_VALUE)
   */
  MESSAGE_HEADER header;

  /**
   * The return value (network byte order)
   */
  GE_KIND kind;

} RETURN_ERROR_MESSAGE;


/**
 * @brief an IPv4 address
 */
typedef struct {
  /**
   * struct in_addr
   */
  unsigned int addr;
} IPaddr;

/**
 * @brief IPV4 network in CIDR notation.
 */
struct CIDRNetwork;

/**
 * @brief an IPV6 address.
 */
typedef struct {
  /**
   * struct in6_addr addr;
   */
  unsigned int addr[4];
} IP6addr;

/**
 * @brief IPV6 network in CIDR notation.
 */
struct CIDR6Network;

/**
 * @brief handle for a system socket
 */
struct SocketHandle;

/**
 * @brief handle for a select manager
 */
struct SelectHandle;

/**
 * @brief callback for handling messages received by select
 *
 * @param sock socket on which the message was received
 *        (should ONLY be used to queue reply using select methods)
 * @return OK if message was valid, SYSERR if corresponding
 *  socket should be closed
 */
typedef int (*SelectMessageHandler)(void * mh_cls,
				    struct SelectHandle * sh,
				    struct SocketHandle * sock,
				    void * sock_ctx,
				    const MESSAGE_HEADER * msg);			

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
typedef void * (*SelectAcceptHandler)(void * ah_cls,
				      struct SelectHandle * sh,
				      struct SocketHandle * sock,
				      const void * addr,
				      unsigned int addr_len);

/**
 * Select has been forced to close a connection.
 * Free the associated context.
 */
typedef void (*SelectCloseHandler)(void * ch_cls,
				   struct SelectHandle * sh,
				   struct SocketHandle * sock,
				   void * sock_ctx);

/* *********************** endianess conversion ************* */

/**
 * Convert a long-long to host-byte-order.
 * @param n the value in network byte order
 * @return the same value in host byte order
 */
unsigned long long ntohll(unsigned long long n);

/**
 * Convert a long long to network-byte-order.
 * @param n the value in host byte order
 * @return the same value in network byte order
 */
unsigned long long htonll(unsigned long long n);

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
 * @return the converted list, NULL if the synatx is flawed
 */
struct CIDRNetwork *
parse_ipv4_network_specification(struct GE_Context * ectx,
				 const char * routeList);

/**
 * Parse a network specification. The argument specifies
 * a list of networks. The format is
 * <tt>[network/netmask;]*</tt> (no whitespace, must be terminated
 * with a semicolon). The network must be given in dotted-decimal
 * notation. The netmask can be given in CIDR notation (/16) or
 * in dotted-decimal (/255.255.0.0).
 * <p>
 * @param routeList a string specifying the forbidden networks
 * @return the converted list, NULL if the synatx is flawed
 */
struct CIDR6Network *
parse_ipv6_network_specification(struct GE_Context * ectx,
				 const char * routeList);

/**
 * Check if the given IP address is in the list of
 * IP addresses.
 * @param list a list of networks
 * @param ip the IP to check (in network byte order)
 * @return NO if the IP is not in the list, YES if it it is
 */
int check_ipv4_listed(const struct CIDRNetwork * list,
		      IPaddr ip);

/**
 * Check if the given IP address is in the list of
 * IP addresses.
 * @param list a list of networks
 * @param ip the IP to check (in network byte order)
 * @return NO if the IP is not in the list, YES if it it is
 */
int check_ipv6_listed(const struct CIDR6Network * list,
		      IP6addr ip);

#define PRIP(ip) (unsigned int)(((unsigned int)(ip))>>24), \
                 (unsigned int)((((unsigned)(ip)))>>16 & 255), \
                 (unsigned int)((((unsigned int)(ip)))>>8 & 255), \
                 (unsigned int)((((unsigned int)(ip))) & 255)

/**
 * Get the IP address of the given host.
 *
 * @return OK on success, SYSERR on error
 */
int get_host_by_name(struct GE_Context * ectx,
		     const char * hostname,
		     IPaddr * ip);

/* ********************* low-level socket operations **************** */

/**
 * Create a socket handle by boxing an OS socket.
 * The OS socket should henceforth be no longer used
 * directly.  socket_destroy will close it.
 */
struct SocketHandle *
socket_create(struct GE_Context * ectx,
	      struct LoadMonitor * mon,
	      int osSocket);

/**
 * Close the socket (does NOT destroy it)
 */
void socket_close(struct SocketHandle * s);

/**
 * Destroy the socket (also closes it).
 */
void socket_destroy(struct SocketHandle * s);

/**
 * Depending on doBlock, enable or disable the nonblocking mode
 * of socket s.
 *
 * @return Upon successful completion, it returns zero.
 * @return Otherwise -1 is returned.
 */
int socket_set_blocking(struct SocketHandle * s,
			int doBlock);

/**
 * Check whether the socket is blocking
 * @param s the socket
 * @return YES if blocking, NO non-blocking
 */
int socket_test_blocking(struct SocketHandle * s);

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
 * @return SYSERR on error, YES on success or NO if the operation
 *         would have blocked
 */
int socket_recv(struct SocketHandle * s,
		NC_KIND nc,
		void * buf,
		size_t max,
		size_t * read);

int socket_recv_from(struct SocketHandle * s,
		     NC_KIND nc,
		     void * buf,
		     size_t max,
		     size_t * read,
		     char * from,
		     unsigned int * fromlen);

/**
 * Do a write on the given socket.
 * Write at most max bytes from buf.
 *
 * @param s socket
 * @param buf buffer to send
 * @param max maximum number of bytes to send
 * @param sent number of bytes actually sent
 * @return SYSERR on error, YES on success or
 *         NO if the operation would have blocked.
 */
int socket_send(struct SocketHandle * s,
		NC_KIND nc,
		const void * buf,
		size_t max,
		size_t * sent);

int socket_send_to(struct SocketHandle * s,
		   NC_KIND nc,
		   const void * buf,
		   size_t max,
		   size_t * sent,
		   const char * dst,
		   unsigned int dstlen);

/**
 * Check if socket is valid
 * @return YES if valid, NO otherwise
 */
int socket_test_valid(struct SocketHandle * s);


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
 *        closed?  Use 0 for no timeout
 * @param mon maybe NULL
 * @param memory_quota amount of memory available for
 *        queueing messages (in bytes)
 * @return NULL on error
 */
struct SelectHandle *
select_create(const char * desc,
	      int is_udp,
	      struct GE_Context * ectx,
	      struct LoadMonitor * mon,
	      int sock,
	      unsigned int max_addr_len,
	      cron_t timeout,
	      SelectMessageHandler mh,
	      void * mh_cls,
	      SelectAcceptHandler ah,
	      void * ah_cls,
	      SelectCloseHandler ch,
	      void * ch_cls,
	      unsigned int memory_quota);

/**
 * Terminate the select thread, close the socket and
 * all associated connections.
 */
void select_destroy(struct SelectHandle * sh);

/**
 * Queue the given message with the select thread.
 *
 * @param mayBlock if YES, blocks this thread until message
 *        has been sent
 * @param force message is important, queue even if
 *        there is not enough space
 * @return OK if the message was sent or queued
 *         NO if there was not enough memory to queue it,
 *         SYSERR if the sock does not belong with this select
 */
int select_write(struct SelectHandle * sh,
		 struct SocketHandle * sock,
		 const MESSAGE_HEADER * msg,
		 int mayBlock,
		 int force);


/**
 * Would select queue or send the given message at this time?
 *
 * @param mayBlock if YES, blocks this thread until message
 *        has been sent
 * @param size size of the message
 * @param force message is important, queue even if
 *        there is not enough space
 * @return OK if the message would be sent or queued,
 *         NO if there was not enough memory to queue it,
 *         SYSERR if the sock does not belong with this select
 */
int select_would_try(struct SelectHandle * sh,
		     struct SocketHandle * sock,
		     unsigned int size,
		     int mayBlock,
		     int force);

/**
 * Add another (already connected) socket to the set of
 * sockets managed by the select.
 */
int select_connect(struct SelectHandle * sh,
		   struct SocketHandle * sock,
		   void * sock_ctx);

/**
 * Close the associated socket and remove it from the
 * set of sockets managed by select.
 */
int select_disconnect(struct SelectHandle * sh,
		      struct SocketHandle * sock);


/**
 * Get an IP address as a string (works for both IPv4 and IPv6).  Note
 * that the resolution happens asynchronously and that the first call
 * may not immediately result in the FQN (but instead in a
 * human-readable IP address).
 *
 * @param sa should be of type "struct sockaddr*"
 */ 
char * network_get_ip_as_string(const void * sa,
				unsigned int salen,
				int do_resolve);

/**
 * Get the IP address for the local machine.
 * @return NULL on error, IP as string otherwise
 */
char * network_get_local_ip(struct GC_Configuration * cfg,
			    struct GE_Context * ectx,
			    IPaddr * addr);



#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_UTIL_NETWORK_H */
#endif
/* end of gnunet_util_network.h */
