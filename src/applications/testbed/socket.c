/*
     This file is part of GNUnet.
     (C) 2003 Christian Grothoff (and other contributing authors)

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
 * @file applications/testbed/socket.c 
 * @brief socket operation for communication between the testbed processes
 * @author Ronaldo Alves Ferreira
 * @author Christian Grothoff
 * @author Murali Krishan Ramanathan
 */

#include "platform.h"
#include "socket.h"
#include "testbed.h"

/* ********* helper methods to implement primitive commands *********** */

#define DEBUG NO

int sock = -1;

static void writeAll(int fd, 
		     char * data, 
		     unsigned int len) {
  unsigned int pos;
  int ret;
  pos = 0;
  ret = 42;
  while ( (ret > 0) && (pos < len) ) {
    ret = WRITE(sock, &data[pos], len-pos);
    if (ret > 0) 
      pos += ret;
    else
      LOG_STRERROR(LOG_WARNING, "write");
  }
}

/* ************** socket operations (IPC) ************* */

typedef struct {
  unsigned int size;
  unsigned int type;
  char data[0];
} ExchangeBuffer;

void socketSend(unsigned int len, 
		unsigned int type, 
		void * data) {
  ExchangeBuffer * buf;
  unsigned int tlen;
#if DEBUG
  unsigned int i;
#endif
  
  tlen = len + sizeof(ExchangeBuffer); 
  buf = MALLOC(tlen);
  if (len > 0)
    memcpy(&buf->data[0], data, len);
  buf->size = htonl(tlen);
  buf->type = htonl(type);
  
#if DEBUG
  printf("Sending %u bytes: ", tlen);
  for (i=0;i<tlen;i++)
    printf("%d ", ((char*)buf)[i]);
  printf("\n");
#endif
  
  writeAll(sock, (void*)buf, tlen);
  FREE(buf);
}

/**
 * Read a message from the socket.
 * @return the type of the message
 */
unsigned int readSocket(char ** rbuf, 
			unsigned int * len) {
  unsigned int type;  
  ExchangeBuffer * buf;
  unsigned int pos;
  int ret;
  unsigned int mlen;
  
#if DEBUG
  unsigned int i;
#endif  
  
  pos = 0;
  ret = 42;
  while ( (pos < sizeof(unsigned int)) && (ret >= 0) ) {
    ret = READ(sock, &((char*)&mlen)[pos], sizeof(unsigned int)-pos);
    if (ret >= 0) 
      pos += ret;
    else
      DIE_STRERROR("read");
  }
  mlen = ntohl(mlen);
  
  buf = MALLOC(mlen);
  while ( (pos < mlen) && (ret >= 0) ) {
    ret = READ(sock, &((char*)buf)[pos], mlen-pos);
    if (ret >= 0) 
      pos += ret;
    else
      DIE_STRERROR("read");
  }
  
#if DEBUG
  buf->size = htonl(mlen);
  printf("Reading %u bytes: ", mlen);
  for (i=0;i<mlen;i++)
    printf("%d ", ((char*)buf)[i]);
  printf("\n");
#endif
  
  type = ntohl(buf->type);
  *rbuf = MALLOC(mlen - sizeof(ExchangeBuffer));
  memcpy(*rbuf, &buf->data[0], mlen - sizeof(ExchangeBuffer));
  FREE(buf);
  *len = mlen - sizeof(ExchangeBuffer);
  return type;
}

/**
 * Print a message in the testbed-shell.
 */
void PRINTF(char * fmt, ...) {  
  va_list	args;  
  int n;
  int size = 1024;
  char * p;
  
  p = MALLOC(size);
  while (1) {
    /* Try to print in the allocated space. */
    va_start(args, fmt);
    n = vsnprintf(p, size, fmt, args);
    va_end(args);
    /* If that worked, return the string. */
    if ( (n > -1) && (n < size) ) {
      socketSend(n, SOCKET_PRINTF, p);
      FREE(p);
      return;
    }
    /* Else try again with more space. */
    if (n > -1)    /* glibc 2.1 */
      GROW(p, size, n+1); /* precisely what is needed */
    else           /* glibc 2.0 */
      GROW(p, size, size*2);  /* twice the old size */
  }
}

/* end of socket communication primitives */
