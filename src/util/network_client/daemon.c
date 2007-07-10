/*
     This file is part of GNUnet.
     (C) 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file src/util/network/daemon.c
 * @brief code for client-gnunetd interaction (stop, check running)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_network.h"
#include "gnunet_util_network_client.h"
#include "gnunet_protocols.h"
#include "gnunet_util_threads.h"

int
connection_test_running (struct GE_Context *ectx,
                         struct GC_Configuration *cfg)
{
  struct ClientServerConnection *sock;
  MESSAGE_HEADER csHdr;
  int ret;

  sock = client_connection_create (ectx, cfg);
  if (sock == NULL)
    return SYSERR;
  csHdr.size = htons (sizeof (MESSAGE_HEADER));
  csHdr.type = htons (CS_PROTO_traffic_COUNT);
  if (SYSERR == connection_write (sock, &csHdr))
    {
      connection_destroy (sock);
      return SYSERR;
    }
  if (SYSERR == connection_read_result (sock, &ret))
    {
      connection_destroy (sock);
      return SYSERR;
    }
  connection_destroy (sock);
  return OK;
}

int
connection_request_shutdown (struct ClientServerConnection *sock)
{
  MESSAGE_HEADER csHdr;
  int ret;

  csHdr.size = htons (sizeof (MESSAGE_HEADER));
  csHdr.type = htons (CS_PROTO_SHUTDOWN_REQUEST);
  if (SYSERR == connection_write (sock, &csHdr))
    {
      connection_close_temporarily (sock);
      return SYSERR;
    }
  if (SYSERR == connection_read_result (sock, &ret))
    {
      connection_close_temporarily (sock);
      return SYSERR;
    }
  return ret;
}

/**
 * Wait until the gnunet daemon is
 * running.
 *
 * @param timeout how long to wait at most
 * @return OK if gnunetd is now running
 */
int
connection_wait_for_running (struct GE_Context *ectx,
                             struct GC_Configuration *cfg, cron_t timeout)
{
  cron_t min;
  int ret;

  timeout += get_time ();
  while (GNUNET_SHUTDOWN_TEST () == 0)
    {
      ret = connection_test_running (ectx, cfg);
      if (ret == OK)
        return OK;
      if (timeout < get_time ())
        return SYSERR;
      min = timeout - get_time ();
      if (min > 100 * cronMILLIS)
        min = 100 * cronMILLIS;
      PTHREAD_SLEEP (min);
    }
  return SYSERR;
}

/* end of daemon.c */
