/**
 * @file test/tcpiotest.c
 * @brief testcase for util/tcpiotest.c
 */

#include "gnunet_util.h"
#include "platform.h"

static int openServerSocket() {
  int listenerFD;
  int listenerPort;
  struct sockaddr_in serverAddr;
  const int on = 1;

  listenerPort = getGNUnetPort();
  /* create the socket */
  while ( (listenerFD = SOCKET(PF_INET, SOCK_STREAM, 0)) < 0) {
    LOG(LOG_ERROR,
	"ERROR opening socket (%s).  "
	"No client service started.  "
	"Trying again in 30 seconds.\n",
	STRERROR(errno));
    sleep(30);
  }

  /* fill in the inet address structure */
  memset((char *) &serverAddr,
	 0,
	 sizeof(serverAddr));
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_addr.s_addr=htonl(INADDR_ANY);
  serverAddr.sin_port=htons(listenerPort);

  if ( SETSOCKOPT(listenerFD,
		  SOL_SOCKET,
		  SO_REUSEADDR,
		  &on, sizeof(on)) < 0 )
    perror("setsockopt");

  /* bind the socket */
  if (BIND (listenerFD,
	   (struct sockaddr *) &serverAddr,
	    sizeof(serverAddr)) < 0) {
    LOG(LOG_ERROR,
	"ERROR (%s) binding the TCP listener to port %d. "
	"Test failed.  Is gnunetd running?\n",
	STRERROR(errno),
	listenerPort);
    return -1;
  }

  /* start listening for new connections */
  if (0 != LISTEN(listenerFD, 5)) {
    LOG(LOG_ERROR,
	" listen failed: %s\n",
	STRERROR(errno));
    return -1;
  }
  return listenerFD;
}

static int doAccept(int serverSocket) {
  int incomingFD;
  int lenOfIncomingAddr;
  struct sockaddr_in clientAddr;

  incomingFD = -1;
  while (incomingFD < 0) {
    lenOfIncomingAddr = sizeof(clientAddr);
    incomingFD = ACCEPT(serverSocket,
			(struct sockaddr *)&clientAddr,
			&lenOfIncomingAddr);
    if (incomingFD < 0) {
      LOG(LOG_ERROR,
	  "ERROR accepting new connection (%s).\n",
	  STRERROR(errno));
      continue;
    }
  }
  return incomingFD;
}

/**
 * Perform option parsing from the command line.
 */
static int parseCommandLine(int argc,
			    char * argv[]) {
  char c;

  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      { "config",  1, 0, 'c' },
      { 0,0,0,0 }
    };

    c = GNgetopt_long(argc,
		      argv,
		      "c:",
		      long_options,
		      &option_index);

    if (c == -1)
      break;  /* No more flags to process */

    switch(c) {
    case 'c':
      FREENONNULL(setConfigurationString("FILES",
					 "gnunet.conf",
					 GNoptarg));
      break;
    } /* end of parsing commandline */
  }
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGLEVEL",
				     "DEBUG"));
  return OK;
}

static int testTransmission(GNUNET_TCP_SOCKET * a,
			    GNUNET_TCP_SOCKET * b) {
  CS_MESSAGE_HEADER * hdr;
  CS_MESSAGE_HEADER * buf;
  int i;
  int j;

  hdr = MALLOC(1024);
  for (i=0;i<1024-sizeof(CS_MESSAGE_HEADER);i+=7) {
    fprintf(stderr, ".");
    for (j=0;j<i;j++)
      ((char*)&hdr[1])[j] = (char)i+j;
    hdr->size = htons(i+sizeof(CS_MESSAGE_HEADER));
    hdr->type = 0;
    if (OK != writeToSocket(a, hdr)) {
      FREE(hdr);
      return 1;
    }
    buf = NULL;
    if (OK != readFromSocket(b, &buf)) {
      FREE(hdr);
      return 2;
    }
    if (0 != memcmp(buf, hdr, i+sizeof(CS_MESSAGE_HEADER))) {
      FREE(buf);
      FREE(hdr);
      return 4;
    }
    FREE(buf);
  }
  FREE(hdr);
  return 0;
}

static int testNonblocking(GNUNET_TCP_SOCKET * a,
			   GNUNET_TCP_SOCKET * b) {
  CS_MESSAGE_HEADER * hdr;
  CS_MESSAGE_HEADER * buf;
  int i;
  int cnt;

  hdr = MALLOC(1024);
  for (i=0;i<1024-sizeof(CS_MESSAGE_HEADER);i+=11)
    ((char*)&hdr[1])[i] = (char)i;
  hdr->size = htons(64+sizeof(CS_MESSAGE_HEADER));
  hdr->type = 0;
  while (OK == writeToSocketNonBlocking(a,
					hdr))
    hdr->type++;
  i = 0;
  cnt = hdr->type;
  /* printf("Reading %u messages.\n", cnt); */
  if (cnt < 2)
    return 8; /* could not write ANY data non-blocking!? */
  for (i=0;i<cnt;i++) {
    hdr->type = i;
    buf = NULL;
    if (OK != readFromSocket(b, &buf)) {
      FREE(hdr);
      return 16;
    }
    if (0 != memcmp(buf, hdr, 64+sizeof(CS_MESSAGE_HEADER))) {
      printf("Failure in message %u.  Headers: %d ? %d\n",
	     i,
	     buf->type,
	     hdr->type);
      FREE(buf);
      FREE(hdr);
      return 32;
    }
    FREE(buf);
    if (i == cnt - 2) {
      /* printf("Blocking write to flush last non-blocking message.\n"); */
      hdr->type = cnt;
      if (OK != writeToSocket(a,
			      hdr)) {
	FREE(hdr);
	return 64;
      }
    }
  }
  hdr->type = i;
  buf = NULL;
  if (OK != readFromSocket(b, &buf)) {
    FREE(hdr);
    return 128;
  }
  if (0 != memcmp(buf, hdr, 64+sizeof(CS_MESSAGE_HEADER))) {
    FREE(buf);
    FREE(hdr);
    return 256;
  }
  FREE(buf);
  FREE(hdr);
  return 0;
}

int main(int argc, char * argv[]){
  int i;
  int ret;
  int serverSocket;
  GNUNET_TCP_SOCKET * clientSocket;
  GNUNET_TCP_SOCKET acceptSocket;

  ret = 0;
  initUtil(argc, argv, &parseCommandLine);
  serverSocket = openServerSocket();
  clientSocket = getClientSocket();
  if (serverSocket == -1) {
    releaseClientSocket(clientSocket);
    doneUtil();
    return 1;
  }
  for (i=0;i<2;i++) {
    if (OK == checkSocket(clientSocket)) {
      if (OK == initGNUnetServerSocket(doAccept(serverSocket),
				       &acceptSocket)) {
	ret = ret | testTransmission(clientSocket, &acceptSocket);
	ret = ret | testTransmission(&acceptSocket, clientSocket);
	ret = ret | testNonblocking(clientSocket, &acceptSocket);
	ret = ret | testNonblocking(&acceptSocket, clientSocket);
	closeSocketTemporarily(clientSocket);
 	destroySocket(&acceptSocket);
	fprintf(stderr, "\n");
      } else {
	fprintf(stderr, "initGNUnetServerSocket failed.\n");
	ret = -1;
      }
    } else {
      fprintf(stderr, "checkSocket faild.\n");
      ret = -1;
    }
  }
  releaseClientSocket(clientSocket);
  doneUtil();
  if (ret > 0)
    fprintf(stderr, "Error %d\n", ret);
  return ret;
}
