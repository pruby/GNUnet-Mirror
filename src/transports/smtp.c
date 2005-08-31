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
 * @file transports/smtp.c
 * @brief Implementation of the SMTP transport service
 * @author Christian Grothoff
 * @author Renaldo Ferreira
 */

#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_transport.h"
#include "platform.h"

#define DEBUG_SMTP NO

#define FILTER_STRING_SIZE 64
#define CONTENT_TYPE_MULTIPART "Content-Type: Multipart/Mixed;"
#define BOUNDARY_SPECIFIER "-EL-GNUNET-"
/* how long can a line in base64 encoded
   mime text be? (in characters, excluding "\n") */
#define MAX_CHAR_PER_LINE 76


/**
 * Host-Address in a SMTP network.
 */
typedef struct {

  /**
   * Filter line that every sender must include in the E-mails such
   * that the receiver can effectively filter out the GNUnet traffic
   * from the E-mail.
   */
  char filter[FILTER_STRING_SIZE];

  /**
   * Claimed E-mail address of the sender.
   * Format is "foo@bar.com" with null termination, padded to be
   * of a multiple of 8 bytes long.
   */
  char senderAddress[0];

} EmailAddress;

/**
 * Encapsulation of a GNUnet message in the SMTP mail body (before
 * base64 encoding).
 */
typedef struct {
  /* this struct is always preceeded by n bytes of p2p messages
     that the GNUnet core will process */

  /**
   * size of the message, in bytes, including this header; max
   * 65536-header (network byte order)
   */
  unsigned short size;

  /**
   * What is the identity of the sender (hash of public key)
   */
  PeerIdentity sender;

} SMTPMessage;

/* *********** globals ************* */

/**
 * apis (our advertised API and the core api )
 */
static CoreAPIForTransport * coreAPI;
static TransportAPI smtpAPI;

/**
 * thread that listens for inbound messages
 */
static PTHREAD_T dispatchThread;

/**
 * Socket to talk to the SMTP server
 */
static int smtp_sock;

/**
 * Lock to guard access to smtp_sock
 */
static Mutex smtpLock;

/**
 *   Semaphore used to signal that server has
 *   been started -- and later again to
 *   signal that the server has been stopped.
 */
static Semaphore * serverSignal = NULL;
/**
 * Flag to indicate that server has been shut down.
 */
static int smtp_shutdown = YES;


/** ******************** Base64 encoding ***********/

#define FILLCHAR '='
static char * cvt = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"\
                    "abcdefghijklmnopqrstuvwxyz"\
                    "0123456789+/";

/**
 * Encode into Base64.
 *
 * @param data the data to encode
 * @param len the length of the input
 * @param output where to write the output (*output should be NULL,
 *   is allocated)
 * @return the size of the output
 */
static unsigned int base64_encode(char * data,
				  unsigned int len,
				  char ** output) {
  unsigned int i;
  char c;
  unsigned int ret;

/*    (*output)[ret++] = '\r'; \*/
#define CHECKLINE \
  if ( (ret % MAX_CHAR_PER_LINE) == 0) { \
    (*output)[ret++] = '\n'; \
  }
  ret = 0;
  *output = MALLOC( (((len * 4 / 3) + 8) * (MAX_CHAR_PER_LINE+2))/
		     MAX_CHAR_PER_LINE);
  for (i = 0; i < len; ++i) {
    c = (data[i] >> 2) & 0x3f;
    (*output)[ret++] = cvt[(int)c];
    CHECKLINE;
    c = (data[i] << 4) & 0x3f;
    if (++i < len)
      c |= (data[i] >> 4) & 0x0f;
    (*output)[ret++] = cvt[(int)c];
    CHECKLINE;
    if (i < len) {
      c = (data[i] << 2) & 0x3f;
      if (++i < len)
	c |= (data[i] >> 6) & 0x03;
      (*output)[ret++] = cvt[(int)c];
      CHECKLINE;
    } else {
      ++i;
      (*output)[ret++] = FILLCHAR;
      CHECKLINE;
    }
    if (i < len) {
      c = data[i] & 0x3f;
      (*output)[ret++] = cvt[(int)c];
      CHECKLINE;
    } else {
      (*output)[ret++] = FILLCHAR;
      CHECKLINE;
    }
  }
  (*output)[ret++] = FILLCHAR;
  return ret;
}

#define cvtfind(a)( (((a) >= 'A')&&((a) <= 'Z'))? (a)-'A'\
                   :(((a)>='a')&&((a)<='z')) ? (a)-'a'+26\
                   :(((a)>='0')&&((a)<='9')) ? (a)-'0'+52\
		   :((a) == '+') ? 62\
		   :((a) == '/') ? 63 : -1)
/**
 * Decode from Base64.
 *
 * @param data the data to encode
 * @param len the length of the input
 * @param output where to write the output (*output should be NULL,
 *   is allocated)
 * @return the size of the output
 */
static unsigned int base64_decode(char * data,
				  unsigned int len,
				  char ** output) {
  unsigned int i;
  char c;
  char c1;
  unsigned int ret=0;

#define CHECK_CRLF	while (data[i] == '\r' || data[i] == '\n') {\
				LOG(LOG_DEBUG, "ignoring CR/LF\n"); \
				i++; \
				if (i >= len) goto END;  \
			}

  *output = MALLOC((len * 3 / 4) + 8);
#if DEBUG_SMTP
  LOG(LOG_DEBUG, "base64_decode decoding len=%d\n", len);
#endif
  for (i = 0; i < len; ++i) {
    CHECK_CRLF;
    if (data[i] == FILLCHAR)
	      break;
    c = (char) cvtfind(data[i]);
    ++i;
    CHECK_CRLF;
    c1 = (char) cvtfind(data[i]);
    c = (c << 2) | ((c1 >> 4) & 0x3);
    (*output)[ret++] = c;
    if (++i < len) {
      CHECK_CRLF;
      c = data[i];
      if (FILLCHAR == c)
	break;
      c = (char) cvtfind(c);
      c1 = ((c1 << 4) & 0xf0) | ((c >> 2) & 0xf);
      (*output)[ret++] = c1;
    }
    if (++i < len) {
      CHECK_CRLF;
      c1 = data[i];
      if (FILLCHAR == c1)
	break;

      c1 = (char) cvtfind(c1);
      c = ((c << 6) & 0xc0) | c1;
      (*output)[ret++] = c;
    }
  }
 END:
  return ret;
}

/* ********************* the real stuff ******************* */

#define strAUTOncmp(a,b) strncmp(a,b,strlen(b))

/**
 * Get the GNUnet SMTP port from the configuration, or from
 * /etc/services if it is not specified in the config file.
 *
 * @return the port in host byte order
 */
static unsigned short getSMTPPort() {
  struct servent * pse;	/* pointer to service information entry	*/
  unsigned short port;

  port = (unsigned short) getConfigurationInt("SMTP",
					      "PORT");
  if (port == 0) { /* try lookup in services */
    if ((pse = getservbyname("gnunet", "smtp")))
      port = ntohs(pse->s_port);
    else
      errexit("Cannot determine port to bind to. "\
	      " Define in configuration file in section %s under %s "\
	      "or in /etc/services under smtp/gnunet.\n",
	      "SMTP", "PORT");
  }
  return port;
}

/**
 * Connect to the local SMTP server, return
 * the socket, -1 on error.
 */
static int connectToSMTPServer() {
  int res;
  struct sockaddr_in soaddr;
  char * hostname;
  struct hostent * ip; /* for the lookup of the IP in gnunet.conf */
  int one = 1;

  hostname = getConfigurationString("SMTP",
				    "SERVER");
  if (hostname == NULL)
    hostname = STRDUP("localhost");
  ip = GETHOSTBYNAME(hostname);
  if (ip == NULL) {
    LOG(LOG_ERROR,
	_("Could not resolve name of SMTP server `%s': %s"),
	hostname, hstrerror(h_errno));
    FREE(hostname);
    return -1;
  }
  FREE(hostname);
  res = SOCKET(PF_INET, SOCK_STREAM, 6);/* 6: TCP */
  if (res == -1) {
    LOG_STRERROR(LOG_FAILURE, "socket");
    return SYSERR;
  }
  SETSOCKOPT(res, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  soaddr.sin_family = AF_INET;
  memcpy(&soaddr.sin_addr,
	 &((struct in_addr*)ip->h_addr)->s_addr,
	 sizeof(struct in_addr));
  soaddr.sin_port = htons(getSMTPPort());
  if (0 > CONNECT(res,
		  (struct sockaddr*)&soaddr,
		  sizeof(soaddr))) {
    LOG_STRERROR(LOG_FAILURE, "connect");
    closefile(res);
    return -1;
  }
  return res;
}

#define MAX_SMTP_LINE 128

/**
 * Read a single line from the socket and check if
 * it starts with the expected string. If the server
 * sends more than one line, an arbitrary amount of
 * data from the next line may be read!
 * @param sock the socket to read from
 * @param expect the expected beginning of the line form the server,
 *        e.g. "250 ".
 * @return OK if the line matches the expectation, SYSERR if not
 */
static int readSMTPLine(int sock,
			char * expect) {
  int pos;
  char buff[MAX_SMTP_LINE];
  size_t i;

  pos = 0;

  while (pos < MAX_SMTP_LINE) {
    int success;

try_again:
    success = RECV_NONBLOCKING(sock,
			       &buff[pos],
			       MAX_SMTP_LINE - pos,
			       &i);
    if (success == NO) {
      gnunet_util_sleep(20);
      goto try_again;
    }
	
    if ( (i == 0) || (i == (size_t) -1) )
      return SYSERR;
    while (i > 0) {
      if (buff[pos++] == '\n')
	goto END;
      i--;
    }
  }
 END:
  buff[pos] = '\0';
  if (strncmp(expect,
	      &buff[0],
	      strlen(expect)) == 0)
    return OK;
  else
    return SYSERR;
}

/**
 * Build a string and write the result to the SMTP socket.
 */
static int writeSMTPLine(int sock,
			 char * format,
			 ...) {
  va_list args;
  char * target;
  int size;
  int ret;

  size = 256;
  ret = -1;
  target = MALLOC(size);
  while (ret == -1) {
    va_start(args, format);
    ret = vsnprintf(target, size, format, args);
    va_end(args);
    if (ret == -1) {
      FREE(target);
      size *= 2;
      target = MALLOC(size);
    }
  }
  if (ret == SEND_BLOCKING_ALL(sock, target, ret))
    ret = OK;
  FREE(target);
  return ret;
}

/**
 * Listen to the pipe, decode messages and send to core.
 */
static void * listenAndDistribute() {
  char * pipename;
  char * line;
  unsigned int LINESIZE;
  SMTPMessage * mp;

  pipename = getFileName("SMTP",
			 "PIPE",
			 _("You must specify the name of a "
			   "pipe for the SMTP transport in section `%s' under `%s'.\n"));
  GNUNET_ASSERT(pipename != NULL);
  UNLINK(pipename);
  if (0 != mkfifo(pipename,
		  S_IWUSR|S_IRUSR))
    DIE_STRERROR("mkfifo");
  LINESIZE = ((smtpAPI.mtu * 4 / 3) + 8) * (MAX_CHAR_PER_LINE+2)/
             MAX_CHAR_PER_LINE; /* maximum size of a line supported */
  line = MALLOC(LINESIZE + 2);  /* 2 bytes for off-by-one errors, just to be safe... */

#define READLINE(l,limit) \
  do { retl = fgets(l, limit, fdes); \
    if ( (retl == NULL) || (smtp_shutdown == YES)) {\
	goto END; \
    }\
    incrementBytesReceived(strlen(retl));\
  } while (0)


  SEMAPHORE_UP(serverSignal); /* we are there! */
  while ( smtp_shutdown == NO ) {
    FILE * fdes;
    char * retl;
    char * boundary;
    char * out;
    unsigned int size;
    P2P_PACKET * coreMP;
    int fd;

    fd = fileopen(pipename, O_RDONLY);
    if (fd == -1) {
      if (smtp_shutdown == NO)
	gnunet_util_sleep(5 * cronSECONDS);
      continue;
    }
    fdes = fdopen(fd, "r");
    while (smtp_shutdown == NO ) {
      do {
	READLINE(line, LINESIZE);
      } while (0 != strAUTOncmp(line, CONTENT_TYPE_MULTIPART));
      READLINE(line, LINESIZE);
      if (strlen(line) < strlen("  boundary=\"")) {
	goto END;
      }
      boundary = STRDUP(&line[strlen("  boundary=\"")-2]);
      if (boundary[strlen(boundary)-2] != '\"') {
	FREE(boundary);
	goto END; /* format error */
      } else {
	boundary[strlen(boundary)-2] = '\0';
	boundary[0] = boundary[1] = '-';
      }
      do {
	READLINE(line, LINESIZE);
      } while (0 != strAUTOncmp(line, boundary));
      do {
	READLINE(line, LINESIZE); /* content type, etc. */
      } while (0 != strAUTOncmp(line, ""));
      READLINE(line, LINESIZE); /* read base64 encoded message; decode, process */
      while ( (line[strlen(line)-2] != FILLCHAR) &&
	      (strlen(line) < LINESIZE) )
	READLINE(&line[strlen(line)-1], LINESIZE - strlen(line));
      size = base64_decode(line, strlen(line)-1, &out);
      if (size < sizeof(SMTPMessage)) {
	BREAK();
	FREE(out);
	goto END;
      }

      mp = (SMTPMessage*)&out[size-sizeof(SMTPMessage)];
      if (ntohs(mp->size) != size) {
	LOG(LOG_WARNING,
	    _("Received malformed message via SMTP (size mismatch).\n"));
#if DEBUG_SMTP
	LOG(LOG_DEBUG,
	    "Size returned by base64=%d, in the msg=%d.\n",
	    size,
	    ntohl(mp->size));
#endif
	goto END;
      }
      coreMP = MALLOC(sizeof(P2P_PACKET));
      coreMP->msg = out;
      coreMP->size = size - sizeof(SMTPMessage);
      coreMP->tsession = NULL;
      memcpy(&coreMP->sender,
	     &mp->sender,
	     sizeof(PeerIdentity));
#if DEBUG_SMTP
      LOG(LOG_DEBUG,
	  "SMTP message passed to the core.\n");
#endif

      coreAPI->receive(coreMP);
      READLINE(line, LINESIZE); /* new line at the end */
    }
  END:
#if DEBUG_SMTP
    LOG(LOG_DEBUG,
	"SMTP message processed.\n");
#endif
    if (fdes != NULL)
      fclose(fdes);
  }
  SEMAPHORE_UP(serverSignal); /* we are there! */
  return NULL;
}

/* *************** API implementation *************** */

/**
 * Verify that a hello-Message is correct (a node is reachable at that
 * address). Since the reply will be asynchronous, a method must be
 * called on success.
 *
 * @param helo the hello message to verify
 *        (the signature/crc have been verified before)
 * @return OK on success, SYSERR on error
 */
static int verifyHelo(const P2P_hello_MESSAGE * helo) {
  EmailAddress * maddr;

  maddr = (EmailAddress*) &helo[1];
  if ((ntohs(helo->header.size)!=
       sizeof(P2P_hello_MESSAGE)+ntohs(helo->senderAddressSize)) ||
      (maddr->senderAddress[ntohs(helo->senderAddressSize)-1-FILTER_STRING_SIZE]!='\0')) {
    BREAK();
    return SYSERR; /* obviously invalid */
  } else {
#if DEBUG_SMTP
    LOG(LOG_DEBUG,
	"Verified SMTP helo from `%s'.\n",
	&maddr->senderAddress[0]);
#endif
    return OK;
  }
}

/**
 * Create a hello-Message for the current node. The hello is created
 * without signature and without a timestamp. The GNUnet core will
 * sign the message and add an expiration time.
 *
 * @return hello on success, NULL on error
 */
static P2P_hello_MESSAGE * createhello() {
  P2P_hello_MESSAGE * msg;
  char * email;
  char * filter;
  EmailAddress * haddr;
  int i;

  email = getConfigurationString("SMTP",
				 "EMAIL");
  if (email == NULL) {
    static int once;
    if (once == 0) {
      LOG(LOG_WARNING,
	  "No email-address specified, cannot create SMTP advertisement.\n");
      once = 1;
    }
    return NULL;
  }
  filter = getConfigurationString("SMTP",
				  "FILTER");
  if (filter == NULL) {
    LOG(LOG_ERROR,
	_("No filter for E-mail specified, cannot create SMTP advertisement.\n"));
    FREE(email);
    return NULL;
  }
  if (strlen(filter) > FILTER_STRING_SIZE) {
    filter[FILTER_STRING_SIZE] = '\0';
    LOG(LOG_WARNING,
	_("SMTP filter string to long, capped to `%s'\n"),
	filter);
  }
  i = (strlen(email) + 8) & (~7); /* make multiple of 8 */
  msg = MALLOC(sizeof(P2P_hello_MESSAGE) + sizeof(EmailAddress) + i);
  memset(msg,
	 0,
	 sizeof(P2P_hello_MESSAGE) + sizeof(EmailAddress) + i);
  haddr = (EmailAddress*) &msg[1];
  memset(&haddr->filter[0],
	 0,
	 FILTER_STRING_SIZE);
  strcpy(&haddr->filter[0],
	 filter);
  memcpy(&haddr->senderAddress[0],
	 email,
	 strlen(email)+1);
  msg->senderAddressSize = htons(strlen(email)+1+sizeof(EmailAddress));
  msg->protocol          = htons(SMTP_PROTOCOL_NUMBER);
  msg->MTU               = htonl(smtpAPI.mtu);
  msg->header.size
      = htons(P2P_hello_MESSAGE_size(msg));
  FREE(email);
  if (verifyHelo(msg) == SYSERR)
    GNUNET_ASSERT(0);
  return msg;
}

/**
 * Establish a connection to a remote node.
 * @param helo the hello-Message for the target node
 * @param tsessionPtr the session handle that is to be set
 * @return OK on success, SYSERR if the operation failed
 */
static int smtpConnect(const P2P_hello_MESSAGE * helo,
		       TSession ** tsessionPtr) {
  TSession * tsession;

  tsession = MALLOC(sizeof(TSession));
  tsession->internal = MALLOC(P2P_hello_MESSAGE_size(helo));
  memcpy(tsession->internal,
	 helo,
	 P2P_hello_MESSAGE_size(helo));
  tsession->ttype = smtpAPI.protocolNumber;
  (*tsessionPtr) = tsession;
  return OK;
}

#define MIN(a,b) (((a)<(b))?(a):(b))

/**
 * A (core) Session is to be associated with a transport session. The
 * transport service may want to know in order to call back on the
 * core if the connection is being closed.
 *
 * @param tsession the session handle passed along
 *   from the call to receive that was made by the transport
 *   layer
 * @return OK if the session could be associated,
 *         SYSERR if not.
 */
int smtpAssociate(TSession * tsession) {
  return SYSERR; /* SMTP connections can never be associated */
}

/**
 * Send a message to the specified remote node.
 *
 * @param tsession the P2P_hello_MESSAGE identifying the remote node
 * @param message what to send
 * @param size the size of the message
 * @return SYSERR on error, OK on success
 */
static int smtpSend(TSession * tsession,
		    const void * message,
		    const unsigned int size) {
  char * msg;
  SMTPMessage * mp;
  P2P_hello_MESSAGE * helo;
  EmailAddress * haddr;
  char * ebody;
  int res;
  int ssize, ssize2;

  if (smtp_shutdown == YES)
    return SYSERR;
  if (size == 0) {
    BREAK();
    return SYSERR;
  }
  if (size > smtpAPI.mtu) {
    BREAK();
    return SYSERR;
  }
  helo = (P2P_hello_MESSAGE*)tsession->internal;
  if (helo == NULL)
    return SYSERR;

  haddr = (EmailAddress*) &helo[1];
  ssize2 = ssize = size + sizeof(SMTPMessage);
  msg = MALLOC(ssize);
  mp              = (SMTPMessage*) &msg[size];
  mp->size        = htons(ssize);
  memcpy(&mp->sender,
	 coreAPI->myIdentity,
	 sizeof(PeerIdentity));
  memcpy(msg,
	 message,
	 size);
  ebody = NULL;
#if DEBUG_SMTP
  LOG(LOG_DEBUG,
      "Base64-encoding %d byte message.\n",
      ssize);
#endif
  ssize = base64_encode(msg, ssize, &ebody);
#if DEBUG_SMTP
  LOG(LOG_DEBUG,
      "Base64-encoded message size is %d bytes.\n",
      ssize);
#endif
  FREE(msg);
  MUTEX_LOCK(&smtpLock);
  res = SYSERR;
  /*
    The mail from field is left empty, so mailing list servers
    will interpret the message as a bounce message.
    MAIL FROM: <>
    RCPT TO: recpient@www.example.com
    DATA
    FILTER
    ebody
    .
   */
  if (OK == writeSMTPLine(smtp_sock,
			  "MAIL FROM: <>\r\n"))
    if (OK == readSMTPLine(smtp_sock,
			   "250 "))
      if (OK == writeSMTPLine(smtp_sock,
			      "RCPT TO: <%s>\r\n",
			      &haddr->senderAddress[0]))
	if (OK == readSMTPLine(smtp_sock,
			       "250 "))
	  if (OK == writeSMTPLine(smtp_sock,
				  "DATA\r\n"))
	    if (OK == readSMTPLine(smtp_sock,
				   "354 "))
	      if (OK == writeSMTPLine(smtp_sock,
				      "%-*s\r\n",
				      MIN(FILTER_STRING_SIZE,
					  strlen(&haddr->filter[0])),
				      &haddr->filter[0]))
		if (OK == writeSMTPLine(smtp_sock,
					"%s\r\n  boundary=\"%s\"\r\n\r\n",
					CONTENT_TYPE_MULTIPART,
					BOUNDARY_SPECIFIER))
		  if (OK == writeSMTPLine(smtp_sock,
					  "--%s\r\n\r\n",
					  BOUNDARY_SPECIFIER))
		    if (SYSERR != SEND_BLOCKING_ALL(smtp_sock,
						    ebody,
						    ssize))
		      if (OK == writeSMTPLine(smtp_sock,
					      "\r\n--%s\r\n",
					      BOUNDARY_SPECIFIER))
			if (OK == writeSMTPLine(smtp_sock,
						"\r\n.\r\n"))
			  if (OK == readSMTPLine(smtp_sock,
						 "250 "))
			    res = OK;
  MUTEX_UNLOCK(&smtpLock);
  if (res != OK)
    LOG(LOG_WARNING,
	_("Sending E-mail to `%s' failed.\n"),
	&haddr->senderAddress[0]);
  incrementBytesSent(ssize);
  FREE(ebody);
  return res;
}

/**
 * Disconnect from a remote node.
 *
 * @param tsession the session that is closed
 * @return OK on success, SYSERR if the operation failed
 */
static int smtpDisconnect(TSession * tsession) {
  if (tsession != NULL) {
    if (tsession->internal != NULL)
      FREE(tsession->internal);
    FREE(tsession);
  }
  return OK;
}

/**
 * Start the server process to receive inbound traffic.
 * @return OK on success, SYSERR if the operation failed
 */
static int startTransportServer(void) {
  char * email;

  if (serverSignal != NULL) {
    BREAK();
    return SYSERR;
  }
  serverSignal = SEMAPHORE_NEW(0);
  smtp_shutdown = NO;

   /* initialize SMTP network */
  smtp_sock = connectToSMTPServer();
  if ( smtp_sock == -1) {
    LOG_STRERROR(LOG_ERROR, "connectToSMTPServer");
    closefile(smtp_sock);
    return SYSERR;
  }
#if DEBUG_SMTP
  LOG(LOG_DEBUG,
      "Checking SMTP server.\n");
#endif
  /* read welcome from SMTP server */
  if (SYSERR == readSMTPLine(smtp_sock,
			     "220 ")) {
    LOG(LOG_ERROR,
	_("SMTP server send unexpected response at %s:%d.\n"),
	__FILE__, __LINE__);
    closefile(smtp_sock);
    return SYSERR;
  }
  if (OK == writeSMTPLine(smtp_sock,
			  "helo %s\r\n",
			  getConfigurationString("SMTP",
						 "SENDERHOSTNAME"))) {
    if (OK == readSMTPLine(smtp_sock,
			   "250 ")) {
      email = getConfigurationString("SMTP",
				     "EMAIL");
      if (email == NULL) {
#if DEBUG_SMTP
	LOG(LOG_DEBUG,
	    "No email-address specified, will not advertise SMTP address.\n");
#endif
	return OK;
      }
      FREE(email);
    } else {
      LOG(LOG_ERROR,
	  _("SMTP server failed to respond with 250 confirmation code to `%s' request.\n"),
	  "helo");
      return OK;
    }
  } else {
    LOG(LOG_ERROR,
	_("Failed to send `%s' request to SMTP server.\n"),
	"helo");
    return OK;
  }
#if DEBUG_SMTP
  LOG(LOG_DEBUG,
      "creating listen thread\n");
#endif
  if (0 != PTHREAD_CREATE(&dispatchThread,
			  (PThreadMain) &listenAndDistribute,
			  NULL,
			  1024*4))
    DIE_STRERROR("pthread_create");
  SEMAPHORE_DOWN(serverSignal); /* wait for server to be up */
  return OK;
}

/**
 * Shutdown the server process (stop receiving inbound traffic). Maybe
 * restarted later!
 */
static int stopTransportServer() {
  void * unused;
  char * pipename;

  smtp_shutdown = YES;
  PTHREAD_KILL(&dispatchThread, SIGALRM);
  SEMAPHORE_DOWN(serverSignal);
  SEMAPHORE_FREE(serverSignal);
  closefile(smtp_sock);
  PTHREAD_JOIN(&dispatchThread, &unused);
  pipename = getFileName("SMTP",
			 "PIPE",
			 _("You must specify the name of a "
			   "pipe for the SMTP transport in section `%s' under `%s'.\n"));
  UNLINK(pipename);
  FREE(pipename);
  return OK;
}

/**
 * Reload the configuration. Should never fail.
 */
static void reloadConfiguration(void) {
}

/**
 * Convert TCP address to a string.
 */
static char * addressToString(const P2P_hello_MESSAGE * helo) {
  char * ret;
  EmailAddress * addr;
  size_t n;

  addr = (EmailAddress*) &helo[1];
  n = FILTER_STRING_SIZE + strlen(addr->senderAddress) + 16;
  ret = MALLOC(n);
  SNPRINTF(ret,
	   n,
	   _("%.*s filter %s (SMTP)"),
	   FILTER_STRING_SIZE,
	   addr->filter,
	   addr->senderAddress);
  return ret;
}

/**
 * The default maximum size of each outbound SMTP message.
 */
#define MESSAGE_SIZE 65528

/**
 * The exported method. Makes the core api available via a global and
 * returns the smtp transport API.
 */
TransportAPI * inittransport_smtp(CoreAPIForTransport * core) {
  int mtu;

  coreAPI = core;

  MUTEX_CREATE(&smtpLock);
  reloadConfiguration();
  mtu = getConfigurationInt("SMTP",
			    "MTU");
  if (mtu == 0)
    mtu = MESSAGE_SIZE;
  if (mtu < 1200)
    LOG(LOG_ERROR,
	_("MTU for `%s' is probably too low (fragmentation not implemented!)\n"),
	"SMTP");
  if (mtu > MESSAGE_SIZE)
    mtu = MESSAGE_SIZE;

  smtpAPI.protocolNumber       = SMTP_PROTOCOL_NUMBER;
  smtpAPI.mtu                  = mtu - sizeof(SMTPMessage);
  smtpAPI.cost                 = 50;
  smtpAPI.verifyHelo           = &verifyHelo;
  smtpAPI.createhello          = &createhello;
  smtpAPI.connect              = &smtpConnect;
  smtpAPI.send                 = &smtpSend;
  smtpAPI.sendReliable         = &smtpSend; /* is always blocking, so we can't really do better */
  smtpAPI.associate            = &smtpAssociate;
  smtpAPI.disconnect           = &smtpDisconnect;
  smtpAPI.startTransportServer = &startTransportServer;
  smtpAPI.stopTransportServer  = &stopTransportServer;
  smtpAPI.reloadConfiguration  = &reloadConfiguration;
  smtpAPI.addressToString      = &addressToString;

  return &smtpAPI;
}

void donetransport_smtp() {
  MUTEX_DESTROY(&smtpLock);
}

/* end of smtp.c */
