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
 * @file applications/tracekit/clientapi.c
 * @brief tool that sends a trace request and prints the received network topology
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_util.h"
#include "gnunet_tracekit_lib.h"
#include "tracekit.h"

/**
 * Ask gnunetd to perform a network topology trace
 *
 * @param sock socket to query gnunetd over -- close the socket
 *        to abort the trace
 * @param depth how deep should the probe go?
 * @param priority what priority should the probe have?
 * @param report callback function to call with the results
 * @param cls extra argument to report function
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_TRACEKIT_run (struct GNUNET_ClientServerConnection *sock,
                     unsigned int depth,
                     unsigned int priority,
                     GNUNET_TRACEKIT_ReportCallback report, void *cls)
{
  CS_tracekit_probe_MESSAGE probe;
  CS_tracekit_reply_MESSAGE *reply;
  int i;
  int count;

  probe.header.size = htons (sizeof (CS_tracekit_probe_MESSAGE));
  probe.header.type = htons (GNUNET_CS_PROTO_TRACEKIT_PROBE);
  probe.hops = htonl (depth);
  probe.priority = htonl (priority);
  if (GNUNET_SYSERR == GNUNET_client_connection_write (sock, &probe.header))
    return GNUNET_SYSERR;
  reply = NULL;
  while (GNUNET_OK ==
         GNUNET_client_connection_read (sock,
                                        (GNUNET_MessageHeader **) & reply))
    {
      count = ntohs (reply->header.size) - sizeof (CS_tracekit_reply_MESSAGE);
      if ((count < 0) || (0 != count % sizeof (GNUNET_PeerIdentity)))
        {
          GNUNET_GE_BREAK (NULL, 0);
          return GNUNET_SYSERR;
        }
      count = count / sizeof (GNUNET_PeerIdentity);
      if (count == 0)
        {
          if (GNUNET_OK != report (cls, &reply->responderId, NULL))
            {
              GNUNET_free (reply);
              return GNUNET_OK; /* application aborted */
            }
        }
      else
        {
          for (i = 0; i < count; i++)
            {
              if (GNUNET_OK !=
                  report (cls,
                          &reply->responderId,
                          &((GNUNET_PeerIdentity *) & reply[1])[i]))
                {
                  GNUNET_free (reply);
                  return GNUNET_OK;     /* application aborted */
                }
            }
        }
      GNUNET_free (reply);
      reply = NULL;
    }
  return GNUNET_OK;
}
