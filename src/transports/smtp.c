/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
#include <libesmtp.h>

#define DEBUG_SMTP GNUNET_NO

#define FILTER_STRING_SIZE 64

#define CONTENT_TYPE_MULTIPART "Content-Type: Multipart/Mixed;"

#define BOUNDARY_SPECIFIER "-EL-GNUNET-"

/* how long can a line in base64 encoded
   mime text be? (in characters, excluding "\n") */
#define MAX_CHAR_PER_LINE 76

#define EBUF_LEN 128

/**
 * Host-Address in a SMTP network.
 */
typedef struct
{

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
typedef struct
{
  /* this struct is always preceeded by n bytes of p2p messages
     that the GNUnet core will process */

  /**
   * size of the message, in bytes, including this header; max
   * 65536-header (network byte order)
   */
  unsigned short size;

  /**
   * What is the identity of the sender (GNUNET_hash of public key)
   */
  GNUNET_PeerIdentity sender;

} SMTPMessage;

/* *********** globals ************* */

/**
 * apis (our advertised API and the core api )
 */
static CoreAPIForTransport *coreAPI;

static struct GNUNET_GE_Context *ectx;

static TransportAPI smtpAPI;

/**
 * Thread that listens for inbound messages
 */
static struct GNUNET_ThreadHandle *dispatchThread;

/**
 * Flag to indicate that server has been shut down.
 */
static int smtp_shutdown = GNUNET_YES;


/** ******************** Base64 encoding ***********/

#define FILLCHAR '='
static char *cvt = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "abcdefghijklmnopqrstuvwxyz" "0123456789+/";

/**
 * Encode into Base64.
 *
 * @param data the data to encode
 * @param len the length of the input
 * @param output where to write the output (*output should be NULL,
 *   is allocated)
 * @return the size of the output
 */
static unsigned int
base64_encode (char *data, unsigned int len, char **output)
{
  unsigned int i;
  char c;
  unsigned int ret;

/*    (*output)[ret++] = '\r'; \*/
#define CHECKLINE \
  if ( (ret % MAX_CHAR_PER_LINE) == 0) { \
    (*output)[ret++] = '\n'; \
  }
  ret = 0;
  *output = GNUNET_malloc ((((len * 4 / 3) + 8) * (MAX_CHAR_PER_LINE + 2)) /
                           MAX_CHAR_PER_LINE);
  for (i = 0; i < len; ++i)
    {
      c = (data[i] >> 2) & 0x3f;
      (*output)[ret++] = cvt[(int) c];
      CHECKLINE;
      c = (data[i] << 4) & 0x3f;
      if (++i < len)
        c |= (data[i] >> 4) & 0x0f;
      (*output)[ret++] = cvt[(int) c];
      CHECKLINE;
      if (i < len)
        {
          c = (data[i] << 2) & 0x3f;
          if (++i < len)
            c |= (data[i] >> 6) & 0x03;
          (*output)[ret++] = cvt[(int) c];
          CHECKLINE;
        }
      else
        {
          ++i;
          (*output)[ret++] = FILLCHAR;
          CHECKLINE;
        }
      if (i < len)
        {
          c = data[i] & 0x3f;
          (*output)[ret++] = cvt[(int) c];
          CHECKLINE;
        }
      else
        {
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
static unsigned int
base64_decode (char *data, unsigned int len, char **output)
{
  unsigned int i;
  char c;
  char c1;
  unsigned int ret = 0;

#define CHECK_CRLF  while (data[i] == '\r' || data[i] == '\n') {\
  			GNUNET_GE_LOG(ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER, "ignoring CR/LF\n"); \
  			i++; \
  			if (i >= len) goto END;  \
  		}

  *output = GNUNET_malloc ((len * 3 / 4) + 8);
#if DEBUG_SMTP
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "base64_decode decoding len=%d\n", len);
#endif
  for (i = 0; i < len; ++i)
    {
      CHECK_CRLF;
      if (data[i] == FILLCHAR)
        break;
      c = (char) cvtfind (data[i]);
      ++i;
      CHECK_CRLF;
      c1 = (char) cvtfind (data[i]);
      c = (c << 2) | ((c1 >> 4) & 0x3);
      (*output)[ret++] = c;
      if (++i < len)
        {
          CHECK_CRLF;
          c = data[i];
          if (FILLCHAR == c)
            break;
          c = (char) cvtfind (c);
          c1 = ((c1 << 4) & 0xf0) | ((c >> 2) & 0xf);
          (*output)[ret++] = c1;
        }
      if (++i < len)
        {
          CHECK_CRLF;
          c1 = data[i];
          if (FILLCHAR == c1)
            break;

          c1 = (char) cvtfind (c1);
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
 * Listen to the pipe, decode messages and send to core.
 */
static void *
listenAndDistribute (void *unused)
{
  char *pipename;
  char *line;
  unsigned int LINESIZE;
  SMTPMessage *mp;

  pipename = getFileName ("SMTP",
                          "PIPE",
                          _("You must specify the name of a "
                            "pipe for the SMTP transport in section `%s' under `%s'.\n"));
  GNUNET_GE_ASSERT (ectx, pipename != NULL);
  UNLINK (pipename);
  if (0 != mkfifo (pipename, S_IWUSR | S_IRUSR))
    GNUNET_GE_DIE_STRERROR (ectx,
                            GNUNET_GE_ADMIN | GNUNET_GE_BULK |
                            GNUNET_GE_FATAL, "mkfifo");
  LINESIZE = ((smtpAPI.mtu * 4 / 3) + 8) * (MAX_CHAR_PER_LINE + 2) / MAX_CHAR_PER_LINE; /* maximum size of a line supported */
  line = GNUNET_malloc (LINESIZE + 2);  /* 2 bytes for off-by-one errors, just to be safe... */

#define READLINE(l,limit) \
  do { retl = fgets(l, limit, fdes); \
    if ( (retl == NULL) || (smtp_shutdown == GNUNET_YES)) {\
  goto END; \
    }\
    incrementBytesReceived(strlen(retl));\
  } while (0)


  while (smtp_shutdown == GNUNET_NO)
    {
      FILE *fdes;
      char *retl;
      char *boundary;
      char *out;
      unsigned int size;
      P2P_PACKET *coreMP;
      int fd;

      fd = GNUNET_disk_file_open (ectx, pipename, O_RDONLY);
      if (fd == -1)
        {
          if (smtp_shutdown == GNUNET_NO)
            GNUNET_thread_sleep (5 * GNUNET_CRON_SECONDS);
          continue;
        }
      fdes = fdopen (fd, "r");
      while (smtp_shutdown == GNUNET_NO)
        {
          do
            {
              READLINE (line, LINESIZE);
            }
          while (0 != strAUTOncmp (line, CONTENT_TYPE_MULTIPART));
          READLINE (line, LINESIZE);
          if (strlen (line) < strlen ("  boundary=\""))
            {
              goto END;
            }
          boundary = GNUNET_strdup (&line[strlen ("  boundary=\"") - 2]);
          if (boundary[strlen (boundary) - 2] != '\"')
            {
              GNUNET_free (boundary);
              goto END;         /* format error */
            }
          else
            {
              boundary[strlen (boundary) - 2] = '\0';
              boundary[0] = boundary[1] = '-';
            }
          do
            {
              READLINE (line, LINESIZE);
            }
          while (0 != strAUTOncmp (line, boundary));
          do
            {
              READLINE (line, LINESIZE);        /* content type, etc. */
            }
          while (0 != strAUTOncmp (line, ""));
          READLINE (line, LINESIZE);    /* read base64 encoded message; decode, process */
          while ((line[strlen (line) - 2] != FILLCHAR) &&
                 (strlen (line) < LINESIZE))
            READLINE (&line[strlen (line) - 1], LINESIZE - strlen (line));
          size = base64_decode (line, strlen (line) - 1, &out);
          if (size < sizeof (SMTPMessage))
            {
              GNUNET_GE_BREAK (ectx, 0);
              GNUNET_free (out);
              goto END;
            }

          mp = (SMTPMessage *) & out[size - sizeof (SMTPMessage)];
          if (ntohs (mp->size) != size)
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_WARNING | GNUNET_GE_BULK |
                             GNUNET_GE_USER,
                             _
                             ("Received malformed message via SMTP (size mismatch).\n"));
#if DEBUG_SMTP
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                             GNUNET_GE_USER,
                             "Size returned by base64=%d, in the msg=%d.\n",
                             size, ntohl (mp->size));
#endif
              goto END;
            }
          coreMP = GNUNET_malloc (sizeof (P2P_PACKET));
          coreMP->msg = out;
          coreMP->size = size - sizeof (SMTPMessage);
          coreMP->tsession = NULL;
          memcpy (&coreMP->sender, &mp->sender, sizeof (GNUNET_PeerIdentity));
#if DEBUG_SMTP
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "SMTP message passed to the core.\n");
#endif

          coreAPI->receive (coreMP);
          READLINE (line, LINESIZE);    /* new line at the end */
        }
    END:
#if DEBUG_SMTP
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "SMTP message processed.\n");
#endif
      if (fdes != NULL)
        fclose (fdes);
    }
  UNLINK (pipename);
  GNUNET_free (pipename);

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
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
verifyHelo (const GNUNET_MessageHello * helo)
{
  EmailAddress *maddr;

  maddr = (EmailAddress *) & helo[1];
  if ((ntohs (helo->header.size) !=
       sizeof (GNUNET_MessageHello) + ntohs (helo->senderAddressSize)) ||
      (maddr->
       senderAddress[ntohs (helo->senderAddressSize) - 1 -
                     FILTER_STRING_SIZE] != '\0'))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;     /* obviously invalid */
    }
  else
    {
#if DEBUG_SMTP
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Verified SMTP helo from `%s'.\n",
                     &maddr->senderAddress[0]);
#endif
      return GNUNET_OK;
    }
}

/**
 * Create a hello-Message for the current node. The hello is created
 * without signature and without a timestamp. The GNUnet core will
 * GNUNET_RSA_sign the message and add an expiration time.
 *
 * @return hello on success, NULL on error
 */
static GNUNET_MessageHello *
createhello ()
{
  GNUNET_MessageHello *msg;
  char *email;
  char *filter;
  EmailAddress *haddr;
  int i;

  email = getConfigurationString ("SMTP", "EMAIL");
  if (email == NULL)
    {
      static int once;
      if (once == 0)
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                         "No email-address specified, cannot create SMTP advertisement.\n");
          once = 1;
        }
      return NULL;
    }
  filter = getConfigurationString ("SMTP", "FILTER");
  if (filter == NULL)
    {
      GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("No filter for E-mail specified, cannot create SMTP advertisement.\n"));
      GNUNET_free (email);
      return NULL;
    }
  if (strlen (filter) > FILTER_STRING_SIZE)
    {
      filter[FILTER_STRING_SIZE] = '\0';
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("SMTP filter string to long, capped to `%s'\n"),
                     filter);
    }
  i = (strlen (email) + 8) & (~7);      /* make multiple of 8 */
  msg =
    GNUNET_malloc (sizeof (GNUNET_MessageHello) + sizeof (EmailAddress) + i);
  memset (msg, 0, sizeof (GNUNET_MessageHello) + sizeof (EmailAddress) + i);
  haddr = (EmailAddress *) & msg[1];
  memset (&haddr->filter[0], 0, FILTER_STRING_SIZE);
  strcpy (&haddr->filter[0], filter);
  memcpy (&haddr->senderAddress[0], email, strlen (email) + 1);
  msg->senderAddressSize = htons (strlen (email) + 1 + sizeof (EmailAddress));
  msg->protocol = htons (GNUNET_TRANSPORT_PROTOCOL_NUMBER_SMTP);
  msg->MTU = htonl (smtpAPI.mtu);
  msg->header.size = htons (GNUNET_sizeof_hello (msg));
  GNUNET_free (email);
  if (verifyHelo (msg) == GNUNET_SYSERR)
    GNUNET_GE_ASSERT (ectx, 0);
  return msg;
}

/**
 * Establish a connection to a remote node.
 * @param helo the hello-Message for the target node
 * @param tsessionPtr the session handle that is to be set
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
smtpConnect (const GNUNET_MessageHello * hello,
             GNUNET_TSession ** tsessionPtr)
{
  GNUNET_TSession *tsession;

  tsession = GNUNET_malloc (sizeof (GNUNET_TSession));
  tsession->internal = GNUNET_malloc (GNUNET_sizeof_hello (hello));
  tsession->peer = hello->senderIdentity;
  memcpy (tsession->internal, hello, GNUNET_sizeof_hello (hello));
  tsession->ttype = smtpAPI.protocolNumber;
  (*tsessionPtr) = tsession;
  return GNUNET_OK;
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
 * @return GNUNET_OK if the session could be associated,
 *         GNUNET_SYSERR if not.
 */
int
smtpAssociate (GNUNET_TSession * tsession)
{
  return GNUNET_SYSERR;         /* SMTP connections can never be associated */
}

/**
 * Send a message to the specified remote node.
 *
 * @param tsession the GNUNET_MessageHello identifying the remote node
 * @param message what to send
 * @param size the size of the message
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
static int
smtpSend (GNUNET_TSession * tsession,
          const void *message, const unsigned int size, int important)
{
  char *msg;
  SMTPMessage *mp;
  GNUNET_MessageHello *helo;
  EmailAddress *haddr;
  char *ebody;
  int res;
  int ssize;
  int ssize2;
  smtp_session_t smtp_sock;
  smtp_message_t message;
  smtp_recipient_t recipient;
  char ebuf[EBUF_LEN];
  char *smtpServer;

  if (smtp_shutdown == GNUNET_YES)
    return GNUNET_SYSERR;
  if ((size == 0) || (size > smtpAPI.mtu))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  helo = (GNUNET_MessageHello *) tsession->internal;
  if (helo == NULL)
    return GNUNET_SYSERR;

  smtp_sock = smtp_create_session ();
  if (smtp_sock == NULL)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_IMMEDIATE,
                     _("Failed to initialize libesmtp: %s.\n"),
                     smtp_strerror (smtp_errno (), ebuf, EBUF_LEN));
      return NULL;
    }
  smtpServer = "localhost:587"; /* fixme */
  smtp_set_server (smtp_sock, smtpServer);


  haddr = (EmailAddress *) & helo[1];
  ssize2 = ssize = size + sizeof (SMTPMessage);
  msg = GNUNET_malloc (ssize);
  mp = (SMTPMessage *) & msg[size];
  mp->size = htons (ssize);
  mp->sender = *coreAPI->myIdentity;
  memcpy (msg, message, size);
  ebody = NULL;
#if DEBUG_SMTP
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Base64-encoding %d byte message.\n", ssize);
#endif
  ssize = base64_encode (msg, ssize, &ebody);
#if DEBUG_SMTP
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Base64-encoded message size is %d bytes.\n", ssize);
#endif
  GNUNET_free (msg);
  res = GNUNET_SYSERR;

  message = smtp_add_message (smtp_sock);
  if (message == NULL)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK, "Failed to create smtp message: %s\n",
                     smtp_strerror (smtp_errno (), ebuf, EBUF_LEN));
      return GNUNET_SYSERR;
    }
  smtp_size_set_estimate (message, ssize);
  smtp_set_messagecb (message, &getMessage, &msg);

#if 0
  if (GNUNET_OK == writeSMTPLine (smtp_sock,
                                  "%-*s\r\n",
                                  MIN (FILTER_STRING_SIZE,
                                       strlen (&haddr->filter[0])),
                                  &haddr->filter[0]))
    {
    }
#endif
  recipient = smtp_add_recipient (message, haddr->senderAddress);
  if (recipient == NULL)
    {
      /* FIXME */
    }
  if (res != GNUNET_OK)
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                   _("Sending E-mail to `%s' failed.\n"),
                   &haddr->senderAddress[0]);
  incrementBytesSent (ssize);
  GNUNET_free (ebody);
  smtp_destroy_session (smtp_sock);


  return res;
}

/**
 * Disconnect from a remote node.
 *
 * @param tsession the session that is closed
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
smtpDisconnect (GNUNET_TSession * tsession)
{
  if (tsession != NULL)
    {
      if (tsession->internal != NULL)
        GNUNET_free (tsession->internal);
      GNUNET_free (tsession);
    }
  return GNUNET_OK;
}

/**
 * Start the server process to receive inbound traffic.
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
startTransportServer (void)
{
  smtp_shutdown = GNUNET_NO;
  /* initialize SMTP network */
  dispatchThread =
    GNUNET_thread_create (&listenAndDistribute, NULL, 1024 * 4);
  if (dispatchThread == NULL)
    GNUNET_GE_DIE_STRERROR (ectx,
                            GNUNET_GE_ADMIN | GNUNET_GE_BULK |
                            GNUNET_GE_FATAL, "pthread_create");
  return GNUNET_OK;
}

/**
 * Shutdown the server process (stop receiving inbound traffic). Maybe
 * restarted later!
 */
static int
stopTransportServer ()
{
  void *unused;

  smtp_shutdown = GNUNET_YES;
  GNUNET_thread_stop_sleep (dispatchThread);
  GNUNET_thread_join (dispatchThread, &unused);
  return GNUNET_OK;
}

/**
 * Convert TCP address to a string.
 */
static char *
addressToString (const GNUNET_MessageHello * helo)
{
  char *ret;
  EmailAddress *addr;
  size_t n;

  addr = (EmailAddress *) & helo[1];
  n = FILTER_STRING_SIZE + strlen (addr->senderAddress) + 16;
  ret = GNUNET_malloc (n);
  GNUNET_snprintf (ret,
                   n,
                   _("%.*s filter %s (SMTP)"),
                   FILTER_STRING_SIZE, addr->filter, addr->senderAddress);
  return ret;
}

/**
 * The default maximum size of each outbound SMTP message.
 */
#define MESSAGNUNET_GE_SIZE 65528

/**
 * The exported method. Makes the core api available via a global and
 * returns the smtp transport API.
 */
TransportAPI *
inittransport_smtp (CoreAPIForTransport * core)
{
  int mtu;

  coreAPI = core;
  ectx = core->ectx;
  mtu = getConfigurationInt ("SMTP", "MTU");
  if (mtu == 0)
    mtu = MESSAGNUNET_GE_SIZE;
  if (mtu < 1200)
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                   _
                   ("MTU for `%s' is probably too low (fragmentation not implemented!)\n"),
                   "SMTP");
  if (mtu > MESSAGNUNET_GE_SIZE)
    mtu = MESSAGNUNET_GE_SIZE;
  smtpAPI.protocolNumber = GNUNET_TRANSPORT_PROTOCOL_NUMBER_SMTP;
  smtpAPI.mtu = mtu - sizeof (SMTPMessage);
  smtpAPI.cost = 50;
  smtpAPI.verifyHelo = &verifyHelo;
  smtpAPI.createhello = &createhello;
  smtpAPI.connect = &smtpConnect;
  smtpAPI.send = &smtpSend;
  smtpAPI.associate = &smtpAssociate;
  smtpAPI.disconnect = &smtpDisconnect;
  smtpAPI.startTransportServer = &startTransportServer;
  smtpAPI.stopTransportServer = &stopTransportServer;
  smtpAPI.addressToString = &addressToString;
  return &smtpAPI;
}

void
donetransport_smtp ()
{
}

/* end of smtp.c */
