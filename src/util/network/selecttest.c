/*
     This file is part of GNUnet.
     (C) 2007 Christian Grothoff (and other contributing authors)

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
 * @file util/network/selecttest.c
 * @brief testcase for util/network/select.c
 */

#include "gnunet_util.h"
#include "platform.h"

#define PORT 10000

/**
 * With sleeping, the kbps throughput is kind-of meaningless;
 * without sleeping, the simulation is not as real-world
 * and performance is still erratic due to the sender
 * doing busy-waiting (and thus possibly burning CPU).
 */
#define DO_SLEEP YES

/**
 * The busy-waiting can be helped with yielding; while
 * this kills part of the test (proper select buffer
 * management) and is not always portable, it can be
 * useful to show the theoretical performance
 * (on my system about 100 mbps).
 */
#define DO_YIELD NO

#if DO_YIELD
void pthread_yield (void);
#endif

/**
 * How many iterations should we do?  Without
 * sleeping, we're much faster...
 */
#if DO_SLEEP
#define ITER 20000
#else
#define ITER 200000
#endif


static struct SocketHandle *out;

static struct SocketHandle *in;

static unsigned int recvPos;

static unsigned long long throughput;


/**
 * @brief callback for handling messages received by select
 *
 * @param sock socket on which the message was received
 *        (should ONLY be used to queue reply using select methods)
 * @return OK if message was valid, SYSERR if corresponding
 *  socket should be closed
 */
static int
test_smh (void *mh_cls,
          struct SelectHandle *sh,
          struct SocketHandle *sock,
          void *sock_ctx, const MESSAGE_HEADER * msg)
{
  static int sleeper;
  char *expect;
  unsigned short size;

  size = ntohs (msg->size);
  throughput += size;
  expect = MALLOC (size);
  memset (expect, (size - sizeof (MESSAGE_HEADER)) % 251, size);
  if (0 != memcmp (&msg[1], expect, size - sizeof (MESSAGE_HEADER)))
    {
      fprintf (stderr, "Message of size %u corrupt!\n", size);
      FREE (expect);
      return OK;
    }
  FREE (expect);
  while (msg->type != htons (recvPos))
    {
      fprintf (stderr, "Message %u lost!\n", recvPos);
      recvPos++;
    }
  recvPos++;
  if (sleeper % 128 == 0)
    fprintf (stderr, ".");
#if DO_SLEEP
  if (sleeper % 5 == 0)
    PTHREAD_SLEEP (50 * cronMILLIS);
#endif
  sleeper++;
  return OK;
}


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
static void *
test_sah (void *ah_cls,
          struct SelectHandle *sh,
          struct SocketHandle *sock, const void *addr, unsigned int addr_len)
{
  static int ret_addr;

  GE_BREAK (NULL, in == NULL);
  in = sock;
  return &ret_addr;             /* dummy value for accept */
}

/**
 * Select has been forced to close a connection.
 * Free the associated context.
 */
static void
test_sch (void *ch_cls,
          struct SelectHandle *sh, struct SocketHandle *sock, void *sock_ctx)
{
  if (sock == in)
    in = NULL;
  else if (sock == out)
    out = NULL;
  else
    GE_BREAK (NULL, 0);
}


static int
check ()
{
  static int zero = 0;
  struct sockaddr_in serverAddr;
  struct SelectHandle *sh;
  int listen_sock;
  int write_sock;
  int i;
  int msg;
  char *m;
  MESSAGE_HEADER *h;
  cron_t start;

  listen_sock = SOCKET (PF_INET, SOCK_STREAM, 6);       /* 6: TCP */
  if (listen_sock == -1)
    {
      GE_BREAK (NULL, 0);
      return 1;
    }
#if TCP_SYNCNT
  /* only try a single packet to establish connection,
     if that does not work, abort instantly */
  setsockopt (listen_sock, IPPROTO_TCP, TCP_SYNCNT, &zero, sizeof (zero));
#endif
  memset ((char *) &serverAddr, 0, sizeof (serverAddr));
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_addr.s_addr = htonl (INADDR_ANY);
  serverAddr.sin_port = htons (PORT);
  if (BIND (listen_sock,
            (struct sockaddr *) &serverAddr, sizeof (serverAddr)) < 0)
    {
      CLOSE (listen_sock);
      return 1;
    }
  LISTEN (listen_sock, 5);

  sh = select_create ("Select Tester", NO,      /* tcp */
                      NULL,     /* ectx */
                      NULL,     /* no load monitoring */
                      listen_sock, sizeof (IPaddr), 15 * cronSECONDS,   /* inactive timeout */
                      test_smh, NULL, test_sah, NULL, test_sch, NULL, 128 * 1024,       /* memory quota */
                      128 /* socket quota */ );

  write_sock = SOCKET (PF_INET, SOCK_STREAM, 6);

  memset ((char *) &serverAddr, 0, sizeof (serverAddr));
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_addr.s_addr = htonl (INADDR_ANY);
  serverAddr.sin_port = htons (PORT);
  i = CONNECT (write_sock,
               (struct sockaddr *) &serverAddr, sizeof (serverAddr));
  if ((i < 0) && (errno != EINPROGRESS) && (errno != EWOULDBLOCK))
    {
      CLOSE (write_sock);
      select_destroy (sh);
      return 1;
    }
  out = socket_create (NULL, NULL, write_sock);
  if (-1 == socket_set_blocking (out, NO))
    {
      socket_destroy (out);
      select_destroy (sh);
      return 1;
    }
  msg = 0;
  m = MALLOC (65536);
  h = (MESSAGE_HEADER *) m;
  select_connect (sh, out, NULL);
  start = get_time ();
  for (i = 0; i < ITER; i++)
    {
      if (GNUNET_SHUTDOWN_TEST () == YES)
        break;
      if (select_would_try (sh,
                            out,
                            (i % 60000) + sizeof (MESSAGE_HEADER), NO, NO))
        {
          h->size = htons ((i % 60000) + sizeof (MESSAGE_HEADER));
          h->type = htons (msg++);
          memset (&m[sizeof (MESSAGE_HEADER)], (i % 60000) % 251, i % 60000);
          select_write (sh, out, h, NO, NO);
        }
      else
        {
#if DO_YIELD
          pthread_yield ();
#endif
        }
#if DO_SLEEP
      if (i % 500 == 0)
        PTHREAD_SLEEP (500 * cronMILLIS);
#endif
    }
  /* give select time to send the rest... */
#if DO_SLEEP
  PTHREAD_SLEEP (2500 * cronMILLIS);
#endif
  select_disconnect (sh, out);
  select_destroy (sh);
  FREE (m);
  fprintf (stderr,
           "\nTransmitted %u test messages - received %u (performance: %llu kbps)\n",
           msg,
           recvPos,
           (throughput / 1024) * cronSECONDS / (get_time () - start));
#if DO_SLEEP
  if (msg - recvPos > 30)
    return 1;
#endif
  return 0;
}

int
main (int argc, char *argv[])
{
  int ret;
  ret = check ();
  if (ret != 0)
    fprintf (stderr, "ERROR %d.\n", ret);
  return ret;
}

/* end of selecttest.c */
