/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file transports/http.c
 * @brief Implementation of the HTTP transport service
 * @author Christian Grothoff
 *
 * The basic protocol looks like this:
 * - client sends:
 *   POST / HTTP/1.1 CRLF
 *   Host:IP CRLF
 *   Transfer-Encoding: chunked CRLF
 *   Content-Type: text/html CRLF
 *
 *   Then a first chunk of 24 bytes with the
 *   welcome-message.
 *
 *   And then an arbitrary number of chunks (CRLF HEX, CRLF, Data)
 *
 *
 * - server replies to the welcome-message:
 *   HTTP/1.1 200 OK CRLF
 *   Server: Apache/1.3.27 CRLF
 *   Transfer-Encoding: chunked CRLF
 *   Content-Type: text/html CRLF
 *
 *   And then transmits an arbitrary number of chunks (CRLF HEX, CRLF, Data)
 *
 * Todo:
 * - increase http compliancy; so far, the implementation of the
 *   protocol is very flawed (no good error-responses if non-peers
 *   connect, and even for the P2P basic protocol, I'm not sure how
 *   close it is to actual HTTP.
 * - the code is not really pretty
 */

#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_transport.h"
#include "gnunet_stats_service.h"
#include "platform.h"
#include "ip.h"

#define DEBUG_HTTP NO

/**
 * after how much time of the core not being associated with a http
 * connection anymore do we close it?
 */
#define HTTP_TIMEOUT (30 * cronSECONDS)

/**
 * Host-Address in a HTTP network.
 */
typedef struct {
  /**
   * claimed IP of the sender, network byte order
   */
  IPaddr ip;

  /**
   * claimed port of the sender, network byte order
   */
  unsigned short port;

  /**
   * reserved (set to 0 for signature verification)
   */
  unsigned short reserved;

} HostAddress;

/* How much do we read from a buffer at least? Answer: for now, at
   MOST the size of the message, since we MUST not read the next
   header(s) by accident! */
#define MIN_BUF_READ 4
/* how long do we allow an http-header to be at
   most? */
#define MAX_HTTP_HEADER 2048

/**
 * Initial handshake message.  Note that the beginning
 * must match the CS_MESSAGE_HEADER since we are using tcpio.
 */
typedef struct {
  /**
   * size of the handshake message, in nbo, value is 24
   */
  unsigned short size;

  /**
   * "message type", HTTP version number, always 0.
   */
  unsigned short version;

  /**
   * Identity of the node connecting (HTTP client)
   */
  PeerIdentity clientIdentity;
} HTTPWelcome;

/**
 * Transport Session handle.
 */
typedef struct {
  /**
   * the http socket
   */
  int sock;

  /**
   * IP & port of the remote host
   */
  unsigned int hostIP;
  unsigned int hostPort;

  /**
   * number of users of this session
   */
  unsigned int users;

  /**
   * Last time this connection was used
   */
  cron_t lastUse;

  /**
   * mutex for synchronized access to 'users'
   */
  Mutex lock;

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  PeerIdentity sender;

  /**
   * Are we still expecting the welcome? (YES/NO)
   */
  int expectingWelcome;

  /**
   * Current read position in rbuff.
   */
  unsigned int rpos;

  /**
   * Current size of the read buffer.
   */
  unsigned int rsize;

  /**
   * The read buffer (used only for the actual data).
   */
  char * rbuff;

  /**
   * Input buffer used for the http header lines.
   * Read fills this buffer until we hit the end of
   * the request header (CRLF).  Then we switch
   * to rbuff.
   */
  char * httpReadBuff;

  /**
   * Current write-position in httpReadBuff;
   */
  unsigned int httpRPos;

  /**
   * Space available in httpReadBuff
   */
  unsigned int httpRSize;

  /**
   * The write buffer.
   */
  char * wbuff;

  /**
   * Number of valid bytes in wbuff.
   */
  unsigned int wpos;

  /**
   * Size of the write buffer.
   */
  unsigned int wsize;

} HTTPSession;

/* *********** globals ************* */

/**
 * apis (our advertised API and the core api )
 */
static CoreAPIForTransport * coreAPI;
static TransportAPI httpAPI;

static Stats_ServiceAPI * stats;

static int stat_bytesReceived;

static int stat_bytesSent;

static int stat_bytesDropped;


/**
 * one thread for listening for new connections,
 * and for reading on all open sockets
 */
static PTHREAD_T listenThread;

/**
 * sock is the http socket that we listen on for new inbound
 * connections.
 */
static int http_sock;

/**
 * http_pipe is used to signal the thread that is
 * blocked in a select call that the set of sockets to listen
 * to has changed.
 */
static int http_pipe[2];

/**
 * Array of currently active HTTP sessions.
 */
static TSession ** tsessions = NULL;
static unsigned int tsessionCount;
static unsigned int tsessionArrayLength;

/* configuration */
static struct CIDRNetwork * filteredNetworks_;

/**
 * Lock for access to mutable state of the module,
 * that is the configuration and the tsessions array.
 * Note that we ONLY need to synchronize access to
 * the tsessions array when adding or removing sessions,
 * since removing is done only by one thread and we just
 * need to avoid another thread adding an element at the
 * same point in time. We do not need to synchronize at
 * every access point since adding new elements does not
 * prevent the select thread from operating and removing
 * is done by the only therad that reads from the array.
 */
static Mutex httplock;

/**
 * Semaphore used by the server-thread to signal that
 * the server has been started -- and later again to
 * signal that the server has been stopped.
 */
static Semaphore * serverSignal = NULL;
static int http_shutdown = YES;

/**
 * The HTTP proxy (optional)
 */
static struct sockaddr_in theProxy;

/* ******************** helper functions *********************** */

/**
 * Check if we are allowed to connect to the given IP.
 */
static int isBlacklisted(IPaddr ip) {
  int ret;

  MUTEX_LOCK(&httplock);
  ret = checkIPListed(filteredNetworks_,
		      ip);
  MUTEX_UNLOCK(&httplock);
  return ret;
}

/**
 * Write to the pipe to wake up the select thread (the set of
 * files to watch has changed).
 */
static void signalSelect() {
  char i = 0;
  int ret;

  ret = WRITE(http_pipe[1],
	      &i,
	      sizeof(char));
  if (ret != sizeof(char))
    LOG_STRERROR(LOG_ERROR, "write");
}

/**
 * Disconnect from a remote node. May only be called
 * on sessions that were aquired by the caller first.
 * For the core, aquiration means to call associate or
 * connect. The number of disconnects must match the
 * number of calls to connect+associate.
 *
 * @param tsession the session that is closed
 * @return OK on success, SYSERR if the operation failed
 */
static int httpDisconnect(TSession * tsession) {
  if (tsession->internal != NULL) {
    HTTPSession * httpsession = tsession->internal;

    MUTEX_LOCK(&httpsession->lock);
    httpsession->users--;
    if (httpsession->users > 0) {
      MUTEX_UNLOCK(&httpsession->lock);
      return OK;
    }
    MUTEX_UNLOCK(&httpsession->lock);
    MUTEX_DESTROY(&httpsession->lock);
    FREENONNULL(httpsession->rbuff);
    FREENONNULL(httpsession->httpReadBuff);
    GROW(httpsession->wbuff,
	 httpsession->wsize,
	 0);
    FREE(httpsession);
  }
  FREE(tsession);
  return OK;
}

/**
 * Remove a session, either the other side closed the connection
 * or we have otherwise reason to believe that it should better
 * be killed. Destroy session closes the session as far as the
 * HTTP layer is concerned, but since the core may still have
 * references to it, httpDisconnect may not instantly free all
 * the associated resources. <p>
 *
 * destroySession may only be called if the httplock is already
 * held.
 *
 * @param i index to the session handle
 */
static void destroySession(int i) {
  HTTPSession * httpSession;

  httpSession = tsessions[i]->internal;
  if (httpSession->sock != -1)
    if (0 != SHUTDOWN(httpSession->sock, SHUT_RDWR))
      LOG_STRERROR(LOG_EVERYTHING, "shutdown");
  closefile(httpSession->sock);
  httpSession->sock = -1;
  httpDisconnect(tsessions[i]);
  tsessions[i] = tsessions[--tsessionCount];
  tsessions[tsessionCount] = NULL;
}

/**
 * Get the GNUnet HTTP port from the configuration, or from
 * /etc/services if it is not specified in the config file.
 */
static unsigned short getGNUnetHTTPPort() {
  struct servent * pse;	/* pointer to service information entry	*/
  unsigned short port;

  port = (unsigned short) getConfigurationInt("HTTP",
					      "PORT");
  if (port == 0) { /* try lookup in services */
    if ((pse = getservbyname("tcp", "http")))
      port = htons(pse->s_port);
  }
  return port;
}

/**
 * A (core) Session is to be associated with a transport session. The
 * transport service may want to know in order to call back on the
 * core if the connection is being closed. Associate can also be
 * called to test if it would be possible to associate the session
 * later, in this case the argument session is NULL. This can be used
 * to test if the connection must be closed by the core or if the core
 * can assume that it is going to be self-managed (if associate
 * returns OK and session was NULL, the transport layer is responsible
 * for eventually freeing resources associated with the tesession). If
 * session is not NULL, the core takes responsbility for eventually
 * calling disconnect.
 *
 * @param tsession the session handle passed along
 *   from the call to receive that was made by the transport
 *   layer
 * @return OK if the session could be associated,
 *         SYSERR if not.
 */
static int httpAssociate(TSession * tsession) {
  HTTPSession * httpSession;

  if (tsession == NULL) {
    BREAK();
    return SYSERR;
  }
  httpSession = (HTTPSession*) tsession->internal;
  MUTEX_LOCK(&httpSession->lock);
  httpSession->users++;
  MUTEX_UNLOCK(&httpSession->lock);
  return OK;
}

/**
 * We have received more header-bytes.  Check if the HTTP header is
 * complete, and if yes allocate rbuff and move the data-portion that
 * was received over to rbuff (and reset the header-reader).
 */
static void checkHeaderComplete(HTTPSession * httpSession) {
  /* we expect 3 possible strings; either
     "HTTP/1.1 200 OK%c%c"
     "Server: Apache/1.3.27%c%c"
     "Transfer-Encoding: chunked%c%c"
     "Content-Type: application/octet-stream%c%c%"
     (which we ignore)

     or

     POST / HTTP/1.1 CRLF
     Host:IP CRLF
     Transfer-Encoding: chunked CRLF
     Content-Type: application/octet-stream CRLF
     (which we also ignore)

     or just "CRLF%xCRLF" where "%x" is the length of
     the next chunk (in hex); in this case, we grow rbuff to %x
     and copy the rest of the httpReadBuff to rbuff (and reset
     httpReadBuff to NULL).

     */
  unsigned int i;

  for (i=0;i+4<httpSession->httpRPos;i++) {
    if ( (httpSession->httpReadBuff[i] == '\r') &&
	 (httpSession->httpReadBuff[i+1] == '\n') ) {
      unsigned int k;

      k = i+2;
      while ( (k < httpSession->httpRPos-1) &&
	      (httpSession->httpReadBuff[k] != '\r') )
	k++;
      if ( (k < httpSession->httpRPos-1) &&
	   (k > i+2) &&
	   (httpSession->httpReadBuff[k] == '\r') &&
	   (httpSession->httpReadBuff[k+1] == '\n') ) {
	unsigned int len;
	char * endPtr;

	httpSession->httpReadBuff[k] = '\n';
	len = strtol(&httpSession->httpReadBuff[i+2],
		     &endPtr,
		     16);
	httpSession->httpReadBuff[k] = '\r';
	if ( (endPtr != &httpSession->httpReadBuff[k]) ||
	     (len == 0) )
	  continue;
#if DEBUG_HTTP
	LOG(LOG_DEBUG,
	    "http receiving chunk of %u bytes\n",
	    len);
#endif
	if (len >= MAX_BUFFER_SIZE) {
	  BREAK(); /* FIMXE: inline method and do proper
		      error handling! */
	  httpSession->httpRPos = 0;	
	} else {	
	  GROW(httpSession->rbuff,
	       httpSession->rsize,
	       len);
	  if (len > httpSession->httpRPos - (k+2))
	    len = httpSession->httpRPos - (k+2);
	  memcpy(httpSession->rbuff,
		 &httpSession->httpReadBuff[k+2],
		 len);
	  httpSession->rpos = len;	
	  memmove(httpSession->httpReadBuff,
		  &httpSession->httpReadBuff[k+2+len],
		  httpSession->httpRPos - (k+2+len));
	  httpSession->httpRPos -= (k+2+len);
	  return;
	} 	
      }
    }
  }
}

/**
 * The socket of session i has data waiting, process!
 *
 * This function may only be called if the httplock is
 * already held by the caller.
 */
static int readAndProcess(int i) {
  TSession * tsession;
  HTTPSession * httpSession;
  unsigned int len;
  int ret;
  P2P_PACKET * mp;

  tsession = tsessions[i];
  if (SYSERR == httpAssociate(tsession))
    return SYSERR;
  httpSession = tsession->internal;
  if (httpSession->rsize == 0) {
    /* chunk read mode */
    if (httpSession->httpRSize == httpSession->httpRPos) {
      httpDisconnect(tsession);
      return SYSERR; /* error! */
    }
    ret = READ(httpSession->sock,
	       &httpSession->httpReadBuff[httpSession->httpRPos],
	       httpSession->httpRSize - httpSession->httpRPos);
    if ( (ret > 0) &&
	 (stats != NULL) )
      stats->change(stat_bytesReceived,
		    ret);
    if (ret > 0) {
      httpSession->httpRPos += ret;
      incrementBytesReceived(ret);
    try_again:
      checkHeaderComplete(httpSession);
    } else {
#if DEBUG_HTTP
      LOG_STRERROR(LOG_DEBUG, "read");
#endif
      httpDisconnect(tsession);
      return SYSERR; /* error! */
    }
  } else {
    GNUNET_ASSERT(httpSession->rsize > httpSession->rpos);
    /* data read mode */
    ret = READ(httpSession->sock,
	       &httpSession->rbuff[httpSession->rpos],
	       httpSession->rsize - httpSession->rpos);
    if ( (ret > 0) &&
	 (stats != NULL) )
      stats->change(stat_bytesReceived,
		    ret);
    if (ret > 0) {
      httpSession->rpos += ret;
      incrementBytesReceived(ret);
    } else {
#if DEBUG_HTTP
      LOG_STRERROR(LOG_DEBUG, "read");
#endif
      httpDisconnect(tsession);
      return SYSERR; /* error! */
    }
  }
#if DEBUG_HTTP
  LOG(LOG_DEBUG,
      "Got message of %u out of %u bytes\n",
      httpSession->rpos,
      httpSession->rsize);
#endif
  if ( (httpSession->rsize == 0) ||
       (httpSession->rpos != httpSession->rsize) ) {
    /* only have partial message yet */
#if DEBUG_HTTP
    LOG(LOG_DEBUG,
	"Got partial message of %u out of %u bytes\n",
	httpSession->rpos,
	httpSession->rsize);
#endif
    httpDisconnect(tsession);
    return OK;
  }
  cronTime(&httpSession->lastUse);
  /* complete message received, let's check what it is */

  if (YES == httpSession->expectingWelcome) {
    HTTPWelcome * welcome;
#if DEBUG_HTTP
    EncName enc;
#endif

    welcome = (HTTPWelcome*) &httpSession->rbuff[0];
    if ( (ntohs(welcome->version) != 0) ||
	 (ntohs(welcome->size) != sizeof(HTTPWelcome)) ) {
      LOG(LOG_WARNING,
	  _("Expected welcome on http connection, got garbage. Closing connection.\n"));
      httpDisconnect(tsession);
      return SYSERR;
    }
    httpSession->expectingWelcome = NO;
    httpSession->sender = welcome->clientIdentity;
#if DEBUG_HTTP
    IFLOG(LOG_DEBUG,
	  hash2enc(&httpSession->sender.hashPubKey,
		   &enc));
    LOG(LOG_DEBUG,
	"Http welcome message from peer `%s' received.\n",
	&enc);
#endif
    GROW(httpSession->rbuff,
	 httpSession->rsize,
	 0);
    httpSession->rpos = 0;
    GNUNET_ASSERT(httpSession->wsize == 0);
    GROW(httpSession->wbuff,
	 httpSession->wsize,
	 256);
    len = SNPRINTF(httpSession->wbuff,
		   httpSession->wsize,
		   "HTTP/1.1 200 OK\r\n"
		   "Server: Apache/1.3.27\r\n"
		   "Transfer-Encoding: chunked\r\n"
		   "Content-Type: application/octet-stream\r\n"
		   "\r\n");
    httpSession->wpos = len;
    if (httpSession->httpRPos > 0)
      goto try_again;
    httpDisconnect(tsession);
    return OK;
  }

  /* Full normal message received; pass on to core! */
  mp      = MALLOC(sizeof(P2P_PACKET));
  mp->sender = httpSession->sender;
  mp->tsession = tsession;
  GNUNET_ASSERT(httpSession->rbuff != NULL);
  mp->msg = httpSession->rbuff;
  mp->size = httpSession->rsize;
  httpSession->rbuff = NULL;
  httpSession->rsize = 0;
  httpSession->rpos = 0;
#if DEBUG_HTTP
  LOG(LOG_DEBUG,
      "http transport received %d bytes, forwarding to core.\n",
      mp->size);
#endif
  coreAPI->receive(mp);
  if (httpSession->httpRPos > 0)
    goto try_again;
  httpDisconnect(tsession);
  return OK;
}

/**
 * Add a new session to the array watched by the select thread.  Grows
 * the array if needed.  If the caller wants to do anything useful
 * with the return value, it must have the lock on httplock before
 * calling.  It is ok to call this function without holding httplock if
 * the return value is ignored.
 */
static unsigned int addTSession(TSession * tsession) {
  unsigned int i;

  MUTEX_LOCK(&httplock);
  if (tsessionCount == tsessionArrayLength)
    GROW(tsessions,
	 tsessionArrayLength,
	 tsessionArrayLength * 2);
  i = tsessionCount;
  tsessions[tsessionCount++] = tsession;
  MUTEX_UNLOCK(&httplock);
  return i;
}

/**
 * Create a new session for an inbound connection on the given
 * socket. Adds the session to the array of sessions watched
 * by the select thread.
 */
static void createNewSession(int sock) {
  TSession * tsession;
  HTTPSession * httpSession;

  httpSession = MALLOC(sizeof(HTTPSession));
  httpSession->rpos = 0;
  httpSession->rsize = 0;
  httpSession->rbuff = NULL;
  httpSession->wsize = 0;
  httpSession->wpos = 0;
  httpSession->wbuff = NULL;
  httpSession->httpReadBuff = NULL;
  httpSession->httpRPos = 0;
  httpSession->httpRSize = 0;
  GROW(httpSession->httpReadBuff,
       httpSession->httpRSize,
       MAX_HTTP_HEADER);
  httpSession->sock = sock;
  /* fill in placeholder identity to mark that we
     are waiting for the welcome message */
  httpSession->sender = *(coreAPI->myIdentity);
  httpSession->expectingWelcome = YES;
  MUTEX_CREATE_RECURSIVE(&httpSession->lock);
  httpSession->users = 1; /* us only, core has not seen this tsession! */
  cronTime(&httpSession->lastUse);
  tsession = MALLOC(sizeof(TSession));
  tsession->ttype = HTTP_PROTOCOL_NUMBER;
  tsession->internal = httpSession;
  addTSession(tsession);
}					

/**
 * Main method for the thread listening on the http socket and all http
 * connections. Whenever a message is received, it is forwarded to the
 * core. This thread waits for activity on any of the HTTP connections
 * and processes deferred (async) writes and buffers reads until an
 * entire message has been received.
 */
static void * httpListenMain() {
  struct sockaddr_in clientAddr;
  fd_set readSet;
  fd_set errorSet;
  fd_set writeSet;
  struct stat buf;
  socklen_t lenOfIncomingAddr;
  int i;
  int max;
  int ret;

  if (http_sock != -1)
    if (0 != LISTEN(http_sock, 5))
      LOG_STRERROR(LOG_ERROR, "listen");
  SEMAPHORE_UP(serverSignal); /* we are there! */
  MUTEX_LOCK(&httplock);
  while (http_shutdown == NO) {
    FD_ZERO(&readSet);
    FD_ZERO(&errorSet);
    FD_ZERO(&writeSet);
    if (http_sock != -1) {
      if (isSocketValid(http_sock)) {
	FD_SET(http_sock, &readSet);
      } else {
	LOG_STRERROR(LOG_ERROR, "isSocketValid");
	http_sock = -1; /* prevent us from error'ing all the time */
      }
    } else
      LOG(LOG_DEBUG,
	  "HTTP server socket not open!\n");
    if (http_pipe[0] != -1) {
      if (-1 != FSTAT(http_pipe[0], &buf)) {
	FD_SET(http_pipe[0], &readSet);
      } else {
	LOG_STRERROR(LOG_ERROR, "fstat");
	http_pipe[0] = -1; /* prevent us from error'ing all the time */	
      }
    }
    max = http_pipe[0];
    if (http_sock > http_pipe[0])
      max = http_sock;
    for (i=0;i<tsessionCount;i++) {
      HTTPSession * httpSession = tsessions[i]->internal;
      int sock = httpSession->sock;
      if (sock != -1) {
	if (isSocketValid(sock)) {
	  FD_SET(sock, &readSet);
	  FD_SET(sock, &errorSet);
	  if (httpSession->wpos > 0)
	    FD_SET(sock, &writeSet); /* do we have a pending write request? */	
	} else {
	  LOG_STRERROR(LOG_ERROR, "isSocketValid");
	  destroySession(i);
	}
      } else {
	BREAK();
	destroySession(i);
      }
      if (sock > max)
	max = sock;
    }
    MUTEX_UNLOCK(&httplock);
    ret = SELECT(max+1, &readSet, &writeSet, &errorSet, NULL);
    MUTEX_LOCK(&httplock);
    if ( (ret == -1) &&
	 ( (errno == EAGAIN) || (errno == EINTR) ) )
      continue;
    if (ret == -1) {
      if (errno == EBADF) {
	LOG_STRERROR(LOG_ERROR, "select");
      } else {
	DIE_STRERROR("select");
      }
    }
    if (http_sock != -1) {
      if (FD_ISSET(http_sock, &readSet)) {
	int sock;
	
	lenOfIncomingAddr = sizeof(clientAddr);
	sock = ACCEPT(http_sock,
		      (struct sockaddr *)&clientAddr,
		      &lenOfIncomingAddr);
	if (sock != -1) {	
	  /* verify clientAddr for eligibility here (ipcheck-style,
	     user should be able to specify who is allowed to connect,
	     otherwise we just close and reject the communication! */
	  IPaddr ipaddr;
	  GNUNET_ASSERT(sizeof(struct in_addr) == sizeof(IPaddr));
	  memcpy(&ipaddr,
		 &clientAddr.sin_addr,
		 sizeof(struct in_addr));

	  if (YES == isBlacklisted(ipaddr)) {
	    LOG(LOG_INFO,
		_("%s: Rejected connection from blacklisted "
		  "address %u.%u.%u.%u.\n"),
		"HTTP",
		PRIP(ntohl(*(int*)&clientAddr.sin_addr)));
	    closefile(sock);
	  } else {
#if DEBUG_HTTP
	    LOG(LOG_INFO,
		"Accepted connection from %u.%u.%u.%u.\n",
		PRIP(ntohl(*(int*)&clientAddr.sin_addr)));
#endif
	    createNewSession(sock);
	  }
	} else {
	  LOG_STRERROR(LOG_INFO, "accept");
	}
      }
    }
    if (FD_ISSET(http_pipe[0], &readSet)) {
      /* allow reading multiple signals in one go in case we get many
	 in one shot... */
#define MAXSIG_BUF 128
      char buf[MAXSIG_BUF];
      /* just a signal to refresh sets, eat and continue */
      if (0 >= READ(http_pipe[0],
		    &buf[0],
		    MAXSIG_BUF)) {
	LOG_STRERROR(LOG_WARNING, "read");
      }
    }
    for (i=0;i<tsessionCount;i++) {
      HTTPSession * httpSession = tsessions[i]->internal;
      int sock = httpSession->sock;
      if (FD_ISSET(sock, &readSet)) {
	if (SYSERR == readAndProcess(i)) {
	  destroySession(i);
	  i--;
	  continue;
	}
      }
      if (FD_ISSET(sock, &writeSet)) {
	size_t ret;
	int success;

try_again_1:
	success = SEND_NONBLOCKING(sock,
				   httpSession->wbuff,
				   httpSession->wpos,
				   &ret);
	if ( (success == SYSERR) || (ret == (size_t) -1) ) {
	  LOG_STRERROR(LOG_WARNING, "send");
	  destroySession(i);
	  i--;
	  continue;
	} else if (success == NO) {
	  /* this should only happen under Win9x because
	     of a bug in the socket implementation (KB177346).
	     Let's sleep and try again. */
	  gnunet_util_sleep(20);
	  goto try_again_1;
	}
	if (stats != NULL)
	  stats->change(stat_bytesSent,
			ret);


	if (ret == 0) {
	  /* send only returns 0 on error (other side closed connection),
	   * so close the session */
	  destroySession(i);
	  i--;
	  continue;
	}
	GNUNET_ASSERT(ret <= httpSession->wpos);
	if (ret == httpSession->wpos) {
	  FREENONNULL(httpSession->wbuff);
	  httpSession->wbuff = NULL;
	  httpSession->wpos = 0;
	  httpSession->wsize = 0;
	} else {
	  memmove(httpSession->wbuff,
		  &httpSession->wbuff[ret],
		  httpSession->wpos - ret);
	  httpSession->wpos -= ret;
	}
      }
      if (FD_ISSET(sock, &errorSet)) {
	destroySession(i);
	i--;
	continue;
      }
      if ( ( httpSession->users == 1) &&
	   (cronTime(NULL) > httpSession->lastUse + HTTP_TIMEOUT) ) {
	destroySession(i);
	i--;
	continue;
      }
    }
  }
  /* shutdown... */
  if (http_sock != -1) {
    closefile(http_sock);
    http_sock = -1;
  }
  /* close all sessions */
  while (tsessionCount > 0)
    destroySession(0);
  MUTEX_UNLOCK(&httplock);
  SEMAPHORE_UP(serverSignal); /* we are there! */
  return NULL;
} /* end of http listen main */

/**
 * Send a message (already encapsulated if needed) via the
 * http socket (or enqueue if sending now would block).
 *
 * @param httpSession the session to use for sending
 * @param doPost should an HTTP post prefix be created?
 * @param mp the message to send
 * @param ssize the size of the message
 * @return OK if message send or queued, NO if queue is full and
 * message was dropped, SYSERR on error
 */
static int httpDirectSend(HTTPSession * httpSession,
			  int doPost,
			  const void * mp,
			  unsigned int ssize) {
  unsigned int len;
  int success;
  size_t ret;

  if (http_shutdown == YES)
    return SYSERR;
  if (httpSession->sock == -1) {
#if DEBUG_HTTP
    LOG(LOG_INFO,
	"httpDirectSend called, but socket is closed\n");
#endif
    return SYSERR;
  }
  if (ssize == 0) {
    BREAK(); /* size 0 not allowed */
    return SYSERR;
  }
  MUTEX_LOCK(&httplock);
  if (httpSession->wpos > 0) {
    MUTEX_UNLOCK(&httplock);
    return NO; /* already have msg pending */
  }
  if (doPost == YES) {
    IPaddr ip;

    if (SYSERR == getPublicIPAddress(&ip)) {
	  MUTEX_UNLOCK(&httplock);
      return SYSERR;
    }
    GROW(httpSession->wbuff,
	 httpSession->wsize,
	 256 + ssize);
    strcpy(httpSession->wbuff, "POST ");
    /* if we're talking to a proxy, we need an absolute URI */
    if (theProxy.sin_addr.s_addr != 0) {
      len = SNPRINTF(httpSession->wbuff + 5,
		     httpSession->wsize - 5,
		     "http://%u.%u.%u.%u:%u",
		     PRIP(ntohl(httpSession->hostIP)),
 		     ntohs(httpSession->hostPort)) + 5;
    } else {
      len = 5;
    }
    len += SNPRINTF(httpSession->wbuff + len,
		    httpSession->wsize - len,
		    "/ HTTP/1.1\r\n"
		    "Host: %u.%u.%u.%u\r\n"
		    "Transfer-Encoding: chunked\r\n"
		    "Content-Type: application/octet-stream\r\n"
		    "\r\n"
		    "%x\r\n",
		    PRIP(ntohl(*(int*)&ip)),
		    ssize);
  } else {
    GROW(httpSession->wbuff,
	 httpSession->wsize,
	 64 + ssize);
    len = SNPRINTF(httpSession->wbuff,
		   httpSession->wsize,
		   "\r\n%x\r\n",
		   ssize);
  }
  memcpy(&httpSession->wbuff[len],
	 mp,
	 ssize);
  len += ssize;
  incrementBytesSent(len);
#if DEBUG_HTTP
  LOG(LOG_DEBUG,
      "http sending chunk of %u bytes\n",
      ssize);
#endif
  success = SEND_NONBLOCKING(httpSession->sock,
			     httpSession->wbuff,
			     len,
			     &ret);
  if (success == SYSERR) {
#if DEBUG_HTTP
    LOG_STRERROR(LOG_INFO, "send");
#endif
    MUTEX_UNLOCK(&httplock);
    return SYSERR;
  }
  if (success == NO)
    ret = 0;
  if (stats != NULL)
    stats->change(stat_bytesSent,
		  ret);
  if (ret > 0) {
    if (ret < len) {
      memmove(httpSession->wbuff,
	      &httpSession->wbuff[ret],
	      len - ret);
      len -= ret;
    } else {
      GROW(httpSession->wbuff,
	   httpSession->wsize,
	   0);
      len = 0;
    }
  }

  httpSession->wpos = len;
  if (len > 0)
    signalSelect(); /* select set changed! */
  cronTime(&httpSession->lastUse);
  MUTEX_UNLOCK(&httplock);
  return OK;
}

/**
 * Verify that a hello-Message is correct (a node
 * is reachable at that address). Since the reply
 * will be asynchronous, a method must be called on
 * success.
 * @param helo the hello message to verify
 *        (the signature/crc have been verified before)
 * @return OK on success, SYSERR on error
 */
static int verifyHelo(const P2P_hello_MESSAGE * helo) {
  HostAddress * haddr;

  haddr = (HostAddress*) &helo[1];
  if ( (ntohs(helo->senderAddressSize) != sizeof(HostAddress)) ||
       (ntohs(helo->header.size) != P2P_hello_MESSAGE_size(helo)) ||
       (ntohs(helo->header.type) != p2p_PROTO_hello) ||
       (ntohs(helo->protocol) != HTTP_PROTOCOL_NUMBER) ||
       (YES == isBlacklisted(haddr->ip)) )
    return SYSERR; /* obviously invalid */
  else
    return OK;
}

/**
 * Create a hello-Message for the current node. The hello is
 * created without signature and without a timestamp. The
 * GNUnet core will sign the message and add an expiration time.
 *
 * @return hello on success, NULL on error
 */
static P2P_hello_MESSAGE * createhello() {
  P2P_hello_MESSAGE * msg;
  HostAddress * haddr;
  unsigned short port;

  port = getGNUnetHTTPPort();
  if (0 == port) {
    LOG(LOG_DEBUG,
	"HTTP port is 0, will only send using HTTP.\n");
    return NULL; /* HTTP transport is configured SEND-only! */
  }
  msg = (P2P_hello_MESSAGE *) MALLOC(sizeof(P2P_hello_MESSAGE) + sizeof(HostAddress));
  haddr = (HostAddress*) &msg[1];

  if (SYSERR == getPublicIPAddress(&haddr->ip)) {
    FREE(msg);
    LOG(LOG_WARNING,
	_("HTTP: Could not determine my public IP address.\n"));
    return NULL;
  }
#if DEBUG_HTTP
  LOG(LOG_DEBUG,
      "HTTP uses IP address %u.%u.%u.%u.\n",
      PRIP(ntohl(*(int*)&haddr->ip)));
#endif
  haddr->port = htons(port);
  haddr->reserved = htons(0);
  msg->senderAddressSize = htons(sizeof(HostAddress));
  msg->protocol = htons(HTTP_PROTOCOL_NUMBER);
  msg->MTU = htonl(httpAPI.mtu);
  return msg;
}

/**
 * Establish a connection to a remote node.
 *
 * @param helo the hello-Message for the target node
 * @param tsessionPtr the session handle that is set
 * @return OK on success, SYSERR if the operation failed
 */
static int httpConnect(const P2P_hello_MESSAGE * helo,
		       TSession ** tsessionPtr) {
  int i;
  HostAddress * haddr;
  HTTPWelcome welcome;
  int sock;
  TSession * tsession;
  HTTPSession * httpSession;
  struct sockaddr_in soaddr;

  if (http_shutdown == YES)
    return SYSERR;
  haddr = (HostAddress*) &helo[1];
#if DEBUG_HTTP
  LOG(LOG_DEBUG,
      "Creating HTTP connection to %u.%u.%u.%u:%u.\n",
      PRIP(ntohl(*(int*)&haddr->ip.addr)),
      ntohs(haddr->port));
#endif
  sock = SOCKET(PF_INET,
		SOCK_STREAM,
		6);/* 6: TCP */
  if (sock == -1) {
    LOG_STRERROR(LOG_FAILURE, "socket");
    return SYSERR;
  }
  if (0 != setBlocking(sock, NO)) {
    closefile(sock);
    LOG_STRERROR(LOG_FAILURE, "setBlocking");
    return SYSERR;
  }
  memset(&soaddr,
	 0,
	 sizeof(soaddr));
  soaddr.sin_family = AF_INET;

  /* Do we have to use a proxy? */
  if (theProxy.sin_addr.s_addr != 0) {
    soaddr.sin_addr = theProxy.sin_addr;
    soaddr.sin_port = theProxy.sin_port;
  } else {
    GNUNET_ASSERT(sizeof(struct in_addr) == sizeof(IPaddr));
    memcpy(&soaddr.sin_addr,
	   &haddr->ip,
	   sizeof(IPaddr));
    soaddr.sin_port = haddr->port;
  }
  i = CONNECT(sock,
	      (struct sockaddr*)&soaddr,
	      sizeof(soaddr));
  if ( (i < 0) &&
       (errno != EINPROGRESS) ) {
    LOG(LOG_ERROR,
	_("Cannot connect to %u.%u.%u.%u:%u: %s\n"),
	PRIP(ntohl(*(int*)&haddr->ip)),
	ntohs(haddr->port),
	STRERROR(errno));
    closefile(sock);
    return SYSERR;
  }
  httpSession = MALLOC(sizeof(HTTPSession));
  httpSession->sock = sock;
  httpSession->hostIP = haddr->ip.addr;
  httpSession->hostPort = haddr->port;
  httpSession->wsize = 0;
  httpSession->wpos = 0;
  httpSession->wbuff = NULL;
  httpSession->rsize = 0;
  httpSession->rbuff = NULL;
  httpSession->httpReadBuff = NULL;
  httpSession->httpRPos = 0;
  httpSession->httpRSize = 0;
  GROW(httpSession->httpReadBuff,
       httpSession->httpRSize,
       MAX_HTTP_HEADER);
  tsession = MALLOC(sizeof(TSession));
  tsession->internal = httpSession;
  tsession->ttype = httpAPI.protocolNumber;
  MUTEX_CREATE_RECURSIVE(&httpSession->lock);
  httpSession->users = 2; /* caller + us */
  httpSession->rpos = 0;
  cronTime(&httpSession->lastUse);
  httpSession->sender = helo->senderIdentity;
  httpSession->expectingWelcome = NO;
  MUTEX_LOCK(&httplock);
  i = addTSession(tsession);

  /* send our node identity to the other side to fully establish the
     connection! */

  welcome.size = htons(sizeof(HTTPWelcome));
  welcome.version = htons(0);
  welcome.clientIdentity = *(coreAPI->myIdentity);
  if (SYSERR == httpDirectSend(httpSession,
			       YES,
			       &welcome,
			       sizeof(HTTPWelcome))) {
    destroySession(i);
    httpDisconnect(tsession);
    MUTEX_UNLOCK(&httplock);
    return SYSERR;
  }
  MUTEX_UNLOCK(&httplock);
  signalSelect();

  *tsessionPtr = tsession;
  return OK;
}

/**
 * Send a message to the specified remote node.
 *
 * @param tsession the P2P_hello_MESSAGE identifying the remote node
 * @param msg the message
 * @param size the size of the message
 * @return SYSERR on error, OK on success, NO if queue is full
 */
static int httpSend(TSession * tsession,
		    const void * msg,
		    const unsigned int size) {
  int ok;

  if (size >= MAX_BUFFER_SIZE)
    return SYSERR;
  if (http_shutdown == YES)
    return SYSERR;
  if (size == 0) {
    BREAK();
    return SYSERR;
  }

  if (((HTTPSession*)tsession->internal)->sock == -1) {
    if (stats != NULL)
      stats->change(stat_bytesDropped,
		    size);
    return SYSERR; /* other side closed connection */
  }
  ok = httpDirectSend(tsession->internal,
		      NO,
		      msg,
		      size);
  if (ok != OK) {
    if (stats != NULL)
      stats->change(stat_bytesDropped,
		    size);
  }
  return ok;
}

/**
 * Start the server process to receive inbound traffic.
 * @return OK on success, SYSERR if the operation failed
 */
static int startTransportServer() {
  struct sockaddr_in serverAddr;
  const int on = 1;
  unsigned short port;

  if (serverSignal != NULL) {
    BREAK();
    return SYSERR;
  }
  serverSignal = SEMAPHORE_NEW(0);
  http_shutdown = NO;

  if (0 != PIPE(http_pipe)) {
    LOG_STRERROR(LOG_ERROR, "pipe");
    return SYSERR;
  }
  setBlocking(http_pipe[1], NO);

  port = getGNUnetHTTPPort();
  if (port != 0) { /* if port == 0, this is a read-only
		      business! */
    http_sock = SOCKET(PF_INET,
		       SOCK_STREAM,
		       0);
    if (http_sock < 0) {
      LOG_STRERROR(LOG_FAILURE, "socket");
      closefile(http_pipe[0]);
      closefile(http_pipe[1]);
      SEMAPHORE_FREE(serverSignal);
      serverSignal = NULL;
      http_shutdown = YES;
      return SYSERR;
    }
    if (SETSOCKOPT(http_sock,
		   SOL_SOCKET,
		   SO_REUSEADDR,
		   &on,
		   sizeof(on)) < 0 )
      DIE_STRERROR("setsockopt");
    memset((char *) &serverAddr,
	   0,
	   sizeof(serverAddr));
    serverAddr.sin_family      = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port        = htons(getGNUnetHTTPPort());
#if DEBUG_HTTP
    LOG(LOG_INFO,
	"starting %s peer server on port %d\n",
	"http",
	ntohs(serverAddr.sin_port));
#endif
    if (BIND(http_sock,
	     (struct sockaddr *) &serverAddr,
	     sizeof(serverAddr)) < 0) {
      LOG_STRERROR(LOG_ERROR, "bind");
      LOG(LOG_ERROR,
	  _("Could not bind the HTTP listener to port %d. "
	    "No transport service started.\n"),
	  getGNUnetHTTPPort());
      closefile(http_sock);
      SEMAPHORE_FREE(serverSignal);
      serverSignal = NULL;
      return SYSERR;
    }
  } else
    http_sock = -1;
  if (0 == PTHREAD_CREATE(&listenThread,
			  (PThreadMain) &httpListenMain,
			  NULL,
			  4092)) {
      SEMAPHORE_DOWN(serverSignal); /* wait for server to be up */
  } else {
    LOG_STRERROR(LOG_ERROR,
		 "pthread_create");
    closefile(http_sock);
    SEMAPHORE_FREE(serverSignal);
    serverSignal = NULL;
    return SYSERR;
  }
  return OK;
}

/**
 * Shutdown the server process (stop receiving inbound
 * traffic). Maybe restarted later!
 */
static int stopTransportServer() {
  void * unused;
  int haveThread;

  if (http_shutdown == YES)
    return OK;
  http_shutdown = YES;
  signalSelect();
  if (serverSignal != NULL) {
    haveThread = YES;
    SEMAPHORE_DOWN(serverSignal);
    SEMAPHORE_FREE(serverSignal);
  } else
    haveThread = NO;
  serverSignal = NULL;
  closefile(http_pipe[1]);
  closefile(http_pipe[0]);
  if (http_sock != -1) {
    closefile(http_sock);
    http_sock = -1;
  }
  if (haveThread == YES)
    PTHREAD_JOIN(&listenThread, &unused);
  return OK;
}

/**
 * Reload the configuration. Should never fail (keep old
 * configuration on error, syslog errors!)
 */
static void reloadConfiguration() {
  char * ch;

  MUTEX_LOCK(&httplock);
  FREENONNULL(filteredNetworks_);
  ch = getConfigurationString("HTTP",
			      "BLACKLIST");
  if (ch == NULL)
    filteredNetworks_ = parseRoutes("");
  else {
    filteredNetworks_ = parseRoutes(ch);
    FREE(ch);
  }
  MUTEX_UNLOCK(&httplock);
}

/**
 * Convert HTTP address to a string.
 */
static char * addressToString(const P2P_hello_MESSAGE * helo) {
  char * ret;
  HostAddress * haddr;
  size_t n;

  haddr = (HostAddress*) &helo[1];
  n = 4*4+6+16;
  ret = MALLOC(n);
  SNPRINTF(ret,
	   n,
	   "%u.%u.%u.%u:%u (HTTP)",
	   PRIP(ntohl(*(int*)&haddr->ip.addr)),
	   ntohs(haddr->port));
  return ret;
}


/* ******************** public API ******************** */

/**
 * The exported method. Makes the core api available
 * via a global and returns the udp transport API.
 */
TransportAPI * inittransport_http(CoreAPIForTransport * core) {
  IPaddr ip;
  char * proxy;
  char * proxyPort;

  MUTEX_CREATE_RECURSIVE(&httplock);
  reloadConfiguration();
  tsessionCount = 0;
  tsessionArrayLength = 0;
  GROW(tsessions,
       tsessionArrayLength,
       32);
  coreAPI = core;

  proxy = getConfigurationString("GNUNETD",
				 "HTTP-PROXY");
  if (proxy != NULL) {
    if (OK != GN_getHostByName(proxy,
			       &ip)) {
      LOG(LOG_ERROR,
	  _("Could not resolve name of HTTP proxy `%s'.\n"),
	  proxy);
      theProxy.sin_addr.s_addr = 0;
    } else {
      memcpy(&theProxy.sin_addr.s_addr,
	     &ip,
	     sizeof(IPaddr));
      proxyPort = getConfigurationString("GNUNETD",
					 "HTTP-PROXY-PORT");
      if (proxyPort == NULL) {
	theProxy.sin_port = htons(8080);
      } else {
	theProxy.sin_port = htons(atoi(proxyPort));
	FREE(proxyPort);
      }
    }
    FREE(proxy);
  } else {
    theProxy.sin_addr.s_addr = 0;
  }
  stats = coreAPI->requestService("stats");
  if (stats != NULL) {
    stat_bytesReceived
      = stats->create(gettext_noop("# bytes received via HTTP"));
    stat_bytesSent
      = stats->create(gettext_noop("# bytes sent via HTTP"));
    stat_bytesDropped
      = stats->create(gettext_noop("# bytes dropped by HTTP (outgoing)"));
  }

  httpAPI.protocolNumber       = HTTP_PROTOCOL_NUMBER;
  httpAPI.mtu                  = 0;
  httpAPI.cost                 = 20000; /* about equal to udp */
  httpAPI.verifyHelo           = &verifyHelo;
  httpAPI.createhello           = &createhello;
  httpAPI.connect              = &httpConnect;
  httpAPI.associate            = &httpAssociate;
  httpAPI.send                 = &httpSend;
  httpAPI.sendReliable         = &httpSend; /* FIXME: we should be able to increase reliability here (by growing wbuff over frame size, like in tcp code)! */
  httpAPI.disconnect           = &httpDisconnect;
  httpAPI.startTransportServer = &startTransportServer;
  httpAPI.stopTransportServer  = &stopTransportServer;
  httpAPI.reloadConfiguration  = &reloadConfiguration;
  httpAPI.addressToString      = &addressToString;

  return &httpAPI;
}

void donetransport_http() {
  int i;

  coreAPI->releaseService(stats);
  stats = NULL;
  for (i=tsessionCount-1;i>=0;i--)
    destroySession(i);
  GROW(tsessions,
       tsessionArrayLength,
       0);
  FREENONNULL(filteredNetworks_);
  MUTEX_DESTROY(&httplock);
}

/* end of http.c */
