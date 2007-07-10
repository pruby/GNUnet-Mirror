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
#include "gnunet_util_config_impl.h"
#include "platform.h"

static struct GC_Configuration *cfg;

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
      GE_LOG_STRERROR (NULL, GE_BULK | GE_ERROR | GE_USER, "socket");
      return -1;
    }

  /* fill in the inet address structure */
  memset ((char *) &serverAddr, 0, sizeof (serverAddr));
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_addr.s_addr = htonl (INADDR_ANY);
  serverAddr.sin_port = htons (listenerPort);

  if (SETSOCKOPT (listenerFD, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) < 0)
    {
      GE_LOG_STRERROR (NULL, GE_BULK | GE_ERROR | GE_USER, "setsockopt");
      CLOSE (listenerFD);
      return -1;
    }

  /* bind the socket */
  if (BIND (listenerFD,
            (struct sockaddr *) &serverAddr, sizeof (serverAddr)) < 0)
    {
      GE_LOG_STRERROR (NULL, GE_BULK | GE_ERROR | GE_USER, "bind");
      CLOSE (listenerFD);
      return -1;
    }

  /* start listening for new connections */
  if (0 != LISTEN (listenerFD, 5))
    {
      GE_LOG_STRERROR (NULL, GE_BULK | GE_ERROR | GE_USER, "listen");
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
          GE_LOG_STRERROR (NULL, GE_BULK | GE_ERROR | GE_USER, "accept");
          continue;
        }
    }
  return incomingFD;
}

static int
testTransmission (struct ClientServerConnection *a, struct SocketHandle *b)
{
  MESSAGE_HEADER *hdr;
  MESSAGE_HEADER *buf;
  int i;
  int j;
  size_t rd;
  size_t pos;

  hdr = MALLOC (1024);
  for (i = 0; i < 1024 - sizeof (MESSAGE_HEADER); i += 7)
    {
      fprintf (stderr, ".");
      for (j = 0; j < i; j++)
        ((char *) &hdr[1])[j] = (char) i + j;
      hdr->size = htons (i + sizeof (MESSAGE_HEADER));
      hdr->type = 0;
      if (OK != connection_write (a, hdr))
        {
          FREE (hdr);
          return 1;
        }
      buf = MALLOC (2048);
      pos = 0;
      while (pos < i + sizeof (MESSAGE_HEADER))
        {
          rd = 0;
          if (SYSERR == socket_recv (b,
                                     NC_Nonblocking,
                                     &buf[pos], 2048 - pos, &rd))
            {
              FREE (hdr);
              FREE (buf);
              return 2;
            }
          pos += rd;
        }
      if (pos != i + sizeof (MESSAGE_HEADER))
        {
          FREE (buf);
          FREE (hdr);
          return 3;
        }
      if (0 != memcmp (buf, hdr, i + sizeof (MESSAGE_HEADER)))
        {
          FREE (buf);
          FREE (hdr);
          return 4;
        }
      FREE (buf);
    }
  FREE (hdr);
  return 0;
}

int
main (int argc, char *argv[])
{
  int i;
  int ret;
  int serverSocket;
  struct ClientServerConnection *clientSocket;
  int acceptSocket;
  struct SocketHandle *sh;

  cfg = GC_create_C_impl ();
  if (-1 == GC_parse_configuration (cfg, "check.conf"))
    {
      GC_free (cfg);
      return -1;
    }
  serverSocket = openServerSocket ();
  if (serverSocket == -1)
    return 1;
  clientSocket = client_connection_create (NULL, cfg);
  ret = 0;
  for (i = 0; i < 2; i++)
    {
      if (OK != connection_ensure_connected (clientSocket))
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
      sh = socket_create (NULL, NULL, acceptSocket);
      ret = ret | testTransmission (clientSocket, sh);
      connection_close_temporarily (clientSocket);
      socket_destroy (sh);
    }
  connection_destroy (clientSocket);
  CLOSE (serverSocket);
  if (ret > 0)
    fprintf (stderr, "Error %d\n", ret);
  GC_free (cfg);
  return ret;
}
