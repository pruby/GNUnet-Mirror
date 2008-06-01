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
GNUNET_test_daemon_running (struct GNUNET_GE_Context *ectx,
                            struct GNUNET_GC_Configuration *cfg)
{
  struct GNUNET_ClientServerConnection *sock;
  GNUNET_MessageHeader csHdr;
  int ret;

  sock = GNUNET_client_connection_create (ectx, cfg);
  if (sock == NULL)
    return GNUNET_SYSERR;
  csHdr.size = htons (sizeof (GNUNET_MessageHeader));
  csHdr.type = htons (GNUNET_CS_PROTO_TRAFFIC_COUNT);
  if (GNUNET_SYSERR == GNUNET_client_connection_write (sock, &csHdr))
    {
      GNUNET_client_connection_destroy (sock);
      return GNUNET_SYSERR;
    }
  if (GNUNET_SYSERR == GNUNET_client_connection_read_result (sock, &ret))
    {
      GNUNET_client_connection_destroy (sock);
      return GNUNET_SYSERR;
    }
  GNUNET_client_connection_destroy (sock);
  return GNUNET_OK;
}

int
GNUNET_client_connection_request_daemon_shutdown (struct
                                                  GNUNET_ClientServerConnection
                                                  *sock)
{
  GNUNET_MessageHeader csHdr;
  int ret;

  csHdr.size = htons (sizeof (GNUNET_MessageHeader));
  csHdr.type = htons (GNUNET_CS_PROTO_SHUTDOWN_REQUEST);
  if (GNUNET_SYSERR == GNUNET_client_connection_write (sock, &csHdr))
    {
      GNUNET_client_connection_close_temporarily (sock);
      return GNUNET_SYSERR;
    }
  if (GNUNET_SYSERR == GNUNET_client_connection_read_result (sock, &ret))
    {
      GNUNET_client_connection_close_temporarily (sock);
      return GNUNET_SYSERR;
    }
  return ret;
}

/**
 * Wait until the gnunet daemon is running.
 *
 * @param timeout how long to wait at most
 * @return GNUNET_OK if gnunetd is now running
 */
int
GNUNET_wait_for_daemon_running (struct GNUNET_GE_Context *ectx,
                                struct GNUNET_GC_Configuration *cfg,
                                GNUNET_CronTime timeout)
{
  GNUNET_CronTime min;
  int ret;

  timeout += GNUNET_get_time ();
  while (GNUNET_shutdown_test () == 0)
    {
      ret = GNUNET_test_daemon_running (ectx, cfg);
      if (ret == GNUNET_OK)
        return GNUNET_OK;
      if (timeout < GNUNET_get_time ())
        return GNUNET_SYSERR;
      min = timeout - GNUNET_get_time ();
      if (min > 100 * GNUNET_CRON_MILLISECONDS)
        min = 100 * GNUNET_CRON_MILLISECONDS;
      GNUNET_thread_sleep (min);
    }
  return GNUNET_SYSERR;
}

/* end of daemon.c */
