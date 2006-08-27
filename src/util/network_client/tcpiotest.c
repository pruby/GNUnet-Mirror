/*
      This file is part of GNUnet
      (C) 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/network_client/tcpiotest.c
 * @brief testcase for util/network_client/tcpiotest.c
 */

#include "gnunet_util.h"
#include "gnunet_util_network_client.h"
#include "platform.h"

static int openServerSocket() {
  int listenerFD;
  int listenerPort;
  struct sockaddr_in serverAddr;
  const int on = 1;

  listenerPort = getGNUnetPort();
  /* create the socket */
  while ( (listenerFD = SOCKET(PF_INET, SOCK_STREAM, 0)) < 0) {
    GE_LOG(NULL,
	   GE_ERROR | GE_BULK | GE_USER,
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
    GE_LOG(NULL,
	   GE_ERROR | GE_BULK | GE_USER,
	   "ERROR (%s) binding the TCP listener to port %d. "
	   "Test failed.  Is gnunetd running?\n",
	   STRERROR(errno),
	   listenerPort);
    return -1;
  }

  /* start listening for new connections */
  if (0 != LISTEN(listenerFD, 5)) {
    GE_LOG(NULL,
	   GE_ERROR | GE_BULK | GE_USER,
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
      GE_LOG(NULL,
	     GE_ERROR | GE_BULK | GE_USER,
	     "ERROR accepting new connection (%s).\n",
	     STRERROR(errno));
      continue;
    }
  }
  return incomingFD;
}

static int testTransmission(struct ClientServerConnection * a,
			    struct ClientServerConnection * b) {
  MESSAGE_HEADER * hdr;
  MESSAGE_HEADER * buf;
  int i;
  int j;

  hdr = MALLOC(1024);
  for (i=0;i<1024-sizeof(MESSAGE_HEADER);i+=7) {
    fprintf(stderr, ".");
    for (j=0;j<i;j++)
      ((char*)&hdr[1])[j] = (char)i+j;
    hdr->size = htons(i+sizeof(MESSAGE_HEADER));
    hdr->type = 0;
    if (OK != connection_write(a, hdr)) {
      FREE(hdr);
      return 1;
    }
    buf = NULL;
    if (OK != connection_read(b, &buf)) {
      FREE(hdr);
      return 2;
    }
    if (0 != memcmp(buf, hdr, i+sizeof(MESSAGE_HEADER))) {
      FREE(buf);
      FREE(hdr);
      return 4;
    }
    FREE(buf);
  }
  FREE(hdr);
  return 0;
}

static int testNonblocking(struct ClientServerConnection * a,
			   struct ClientServerConnection * b) {
  MESSAGE_HEADER * hdr;
  MESSAGE_HEADER * buf;
  int i;
  int cnt;

  hdr = MALLOC(1024);
  for (i=0;i<1024-sizeof(MESSAGE_HEADER);i+=11)
    ((char*)&hdr[1])[i] = (char)i;
  hdr->size = htons(64+sizeof(MESSAGE_HEADER));
  hdr->type = 0;
  while (OK == connection_writeNonBlocking(a,
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
    if (OK != connection_read(b, &buf)) {
      FREE(hdr);
      return 16;
    }
    if (0 != memcmp(buf, hdr, 64+sizeof(MESSAGE_HEADER))) {
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
      if (OK != connection_write(a,
			      hdr)) {
	FREE(hdr);
	return 64;
      }
    }
  }
  hdr->type = i;
  buf = NULL;
  if (OK != connection_read(b, &buf)) {
    FREE(hdr);
    return 128;
  }
  if (0 != memcmp(buf, hdr, 64+sizeof(MESSAGE_HEADER))) {
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
  struct ClientServerConnection * clientSocket;
  struct ClientServerConnection acceptSocket;

  ret = 0;
  serverSocket = openServerSocket();
  clientSocket = getClientSocket();
  if (serverSocket == -1) {
    connection_destroy(clientSocket);
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
  connection_destroy(clientSocket);
  if (ret > 0)
    fprintf(stderr, "Error %d\n", ret);
  return ret;
}
