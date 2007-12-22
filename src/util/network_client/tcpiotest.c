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
#include "platform.h"

static struct GNUNET_GC_Configuration *cfg;

static unsigned short
getGNUnetPort ()
{
  return 2087;
}

static int
openServerSocket ()
{
  int listenerFD;
  int listenerPort;
  struct sockaddr_in serverAddr;
  const int on = 1;

  listenerPort = getGNUnetPort ();
  /* create the socket */
  listenerFD = SOCKET (PF_INET, SOCK_STREAM, 0);
  if (listenerFD < 0)
    {
      GNUNET_GE_LOG_STRERROR (NULL,
                              GNUNET_GE_BULK | GNUNET_GE_ERROR |
                              GNUNET_GE_USER, "socket");
      return -1;
    }

  /* fill in the inet address structure */
  memset ((char *) &serverAddr, 0, sizeof (serverAddr));
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_addr.s_addr = htonl (INADDR_ANY);
  serverAddr.sin_port = htons (listenerPort);

  if (SETSOCKOPT (listenerFD, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) < 0)
    {
      GNUNET_GE_LOG_STRERROR (NULL,
                              GNUNET_GE_BULK | GNUNET_GE_ERROR |
                              GNUNET_GE_USER, "setsockopt");
      CLOSE (listenerFD);
      return -1;
    }

  /* bind the socket */
  if (BIND (listenerFD,
            (struct sockaddr *) &serverAddr, sizeof (serverAddr)) < 0)
    {
      GNUNET_GE_LOG_STRERROR (NULL,
                              GNUNET_GE_BULK | GNUNET_GE_ERROR |
                              GNUNET_GE_USER, "bind");
      CLOSE (listenerFD);
      return -1;
    }

  /* start listening for new connections */
  if (0 != LISTEN (listenerFD, 5))
    {
      GNUNET_GE_LOG_STRERROR (NULL,
                              GNUNET_GE_BULK | GNUNET_GE_ERROR |
                              GNUNET_GE_USER, "listen");
      CLOSE (listenerFD);
      return -1;
    }
  return listenerFD;
}

static int
doAccept (int serverSocket)
{
  int incomingFD;
  socklen_t lenOfIncomingAddr;
  struct sockaddr_in clientAddr;

  incomingFD = -1;
  while (incomingFD < 0)
    {
      lenOfIncomingAddr = sizeof (clientAddr);
      incomingFD = ACCEPT (serverSocket,
                           (struct sockaddr *) &clientAddr,
                           &lenOfIncomingAddr);
      if (incomingFD < 0)
        {
          GNUNET_GE_LOG_STRERROR (NULL,
                                  GNUNET_GE_BULK | GNUNET_GE_ERROR |
                                  GNUNET_GE_USER, "accept");
          continue;
        }
    }
  return incomingFD;
}

static int
testTransmission (struct GNUNET_ClientServerConnection *a,
                  struct GNUNET_SocketHandle *b)
{
  GNUNET_MessageHeader *hdr;
  GNUNET_MessageHeader *buf;
  int i;
  int j;
  size_t rd;
  size_t pos;

  hdr = GNUNET_malloc (1024);
  for (i = 0; i < 1024 - sizeof (GNUNET_MessageHeader); i += 7)
    {
      fprintf (stderr, ".");
      for (j = 0; j < i; j++)
        ((char *) &hdr[1])[j] = (char) i + j;
      hdr->size = htons (i + sizeof (GNUNET_MessageHeader));
      hdr->type = 0;
      if (GNUNET_OK != GNUNET_client_connection_write (a, hdr))
        {
          GNUNET_free (hdr);
          return 1;
        }
      buf = GNUNET_malloc (2048);
      pos = 0;
      while (pos < i + sizeof (GNUNET_MessageHeader))
        {
          rd = 0;
          if (GNUNET_SYSERR == GNUNET_socket_recv (b,
                                                   GNUNET_NC_NONBLOCKING,
                                                   &buf[pos], 2048 - pos,
                                                   &rd))
            {
              GNUNET_free (hdr);
              GNUNET_free (buf);
              return 2;
            }
          pos += rd;
        }
      if (pos != i + sizeof (GNUNET_MessageHeader))
        {
          GNUNET_free (buf);
          GNUNET_free (hdr);
          return 3;
        }
      if (0 != memcmp (buf, hdr, i + sizeof (GNUNET_MessageHeader)))
        {
          GNUNET_free (buf);
          GNUNET_free (hdr);
          return 4;
        }
      GNUNET_free (buf);
    }
  GNUNET_free (hdr);
  return 0;
}

int
main (int argc, char *argv[])
{
  int i;
  int ret;
  int serverSocket;
  struct GNUNET_ClientServerConnection *clientSocket;
  int acceptSocket;
  struct GNUNET_SocketHandle *sh;

  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  serverSocket = openServerSocket ();
  if (serverSocket == -1)
    return 1;
  clientSocket = GNUNET_client_connection_create (NULL, cfg);
  ret = 0;
  for (i = 0; i < 2; i++)
    {
      if (GNUNET_OK !=
          GNUNET_client_connection_ensure_connected (clientSocket))
        {
          ret = 42;
          break;
        }
      acceptSocket = doAccept (serverSocket);
      if (acceptSocket == -1)
        {
          ret = 43;
          break;
        }
      sh = GNUNET_socket_create (NULL, NULL, acceptSocket);
      ret = ret | testTransmission (clientSocket, sh);
      GNUNET_client_connection_close_temporarily (clientSocket);
      GNUNET_socket_destroy (sh);
    }
  GNUNET_client_connection_destroy (clientSocket);
  CLOSE (serverSocket);
  fprintf (stderr, "\n");
  if (ret > 0)
    fprintf (stderr, "Error %d\n", ret);
  GNUNET_GC_free (cfg);
  return ret;
}
