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

struct ClientServerConnection;

struct SocketHandle;

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

/* ***************** high-level GNUnet client-server connections *********** */

/**
 * Get a connection with gnunetd.
 */
struct ClientServerConnection * 
daemon_connection_create(struct GE_Context * ectx,
			 struct GC_Configuration * cfg);

/**
 * Initialize a GNUnet server socket.
 * @param sock the open socket
 * @param result the SOCKET (filled in)
 * @return OK (always successful)
 */
struct ClientServerConnection * 
client_connection_create(struct GE_Context * ectx,
			 struct GC_Configuration * cfg,
			 struct SocketHandle * sock);

/**
 * Close a GNUnet TCP socket for now (use to temporarily close
 * a TCP connection that will probably not be used for a long
 * time; the socket will still be auto-reopened by the
 * readFromSocket/writeToSocket methods if it is a client-socket).
 *
 * Also, you must still call connection_destroy to free all
 * resources associated with the connection.
 */
void connection_close_temporarily(struct ClientServerConnection * sock);

/**
 * Destroy connection between gnunetd and clients.
 * Also closes the connection if it is still active.
 */
void connection_destroy(struct ClientServerConnection * con);

/**
 * Check if a socket is open. Will ALWAYS return 'true' for a valid
 * client socket (even if the connection is closed), but will return
 * false for a closed server socket.
 *
 * @return 1 if open, 0 if closed
 */
int connection_test_open(struct ClientServerConnection * sock);

/**
 * Check a socket, open and connect if it is closed and it is a
 * client-socket.
 *
 * @return OK if the socket is now open, SYSERR if not
 */
int connection_ensure_connected(struct ClientServerConnection * sock);

/**
 * Read from a GNUnet client-server connection.
 *
 * @param sock the socket
 * @param buffer the buffer to write data to
 *        if NULL == *buffer, *buffer is allocated (caller frees)
 * @return OK if the read was successful, SYSERR if the socket
 *         was closed by the other side (if the socket is a
 *         client socket and is used again, the next
 *         read/write call will automatically attempt
 *         to re-establish the connection).
 */
int connection_read(struct ClientServerConnection * sock,
		    MESSAGE_HEADER ** buffer);

/**
 * Write to a GNUnet TCP socket.
 *
 * @param sock the socket to write to
 * @param buffer the buffer to write
 * @return OK if the write was sucessful, 
 *         NO if it would block and isBlocking was NO,
 *         SYSERR if the write failed (error will be logged)
 */
int connection_write(struct ClientServerConnection * sock,
		     const MESSAGE_HEADER * buffer);

/**
 * Obtain a simple return value from the connection.
 * Note that the protocol will automatically communicate
 * errors and pass those to the error context used when
 * the socket was created.  In that case, read_result
 * will return SYSERR for the corresponding communication.
 * 
 * @param sock the TCP socket
 * @param ret the return value from TCP
 * @return SYSERR on error, OK if the return value was
 *         read successfully
 */
int connection_read_result(struct ClientServerConnection * sock,
			   int * ret);

/**
 * Send a simple return value to the other side.
 *
 * @param sock the TCP socket
 * @param ret the return value to send via TCP
 * @return SYSERR on error, OK if the return value was
 *         send successfully
 */
int connection_write_result(struct ClientServerConnection * sock,
			    int ret);

/**
 * Send a return value that indicates
 * a serious error to the other side.
 *
 * @param sock the TCP socket
 * @param mask GE_MASK 
 * @param date date string
 * @param msg message string
 * @return SYSERR on error, OK if the error code was send
 *         successfully
 */
int connection_write_error(struct ClientServerConnection * sock,
			   GE_KIND mask,
			   const char * date,
			   const char * msg);

/**
 * Stop gnunetd
 *
 * Note that returning an error does NOT mean that
 * gnunetd will continue to run (it may have been
 * shutdown by something else in the meantime or
 * crashed).  Call connection_test_running() frequently
 * to check the status of gnunetd.
 *
 * Furthermore, note that this WILL potentially kill
 * gnunetd processes on remote machines that cannot
 * be restarted with startGNUnetDaemon!
 *
 * This function does NOT need the PID and will also
 * kill daemonized gnunetd's.
 *
 * @return OK successfully stopped, SYSERR: error
 */
int connection_request_shutdown(struct ClientServerConnection * sock);

/**
 * Checks if gnunetd is running
 *
 * Uses CS_PROTO_traffic_COUNT query to determine if gnunetd is
 * running.
 *
 * @return OK if gnunetd is running, SYSERR if not
 */
int connection_test_running(struct GE_Context * ectx,
			    struct GC_Configuration * cfg);

/**
 * Wait until the gnunet daemon is
 * running.
 *
 * @param timeout how long to wait at most in ms
 * @return OK if gnunetd is now running
 */
int connection_wait_for_running(struct GE_Context * ectx,
				struct GC_Configuration * cfg,
				cron_t timeout);

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

/**
 * Check if socket is valid
 * @return YES if valid, NO otherwise
 */
int socket_test_valid(struct SocketHandle * s);


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_UTIL_NETWORK_H */
#endif
/* end of gnunet_util_network.h */
