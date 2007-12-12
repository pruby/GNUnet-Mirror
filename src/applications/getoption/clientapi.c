/*
      This file is part of GNUnet

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

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_getoption_lib.h"

#include "getoption.h"

/**
 * @file getoption/clientapi.c
 * @brief library to make it easy for clients to obtain
 *        options from the GNUnet server (if it supports
 *        the getoption protocol)
 * @author Christian Grothoff
 */

/**
 * Obtain option from a peer.
 *
 * @return NULL on error (for both option not set and internal errors)
 */
char *
GNUNET_get_daemon_configuration_value (struct GNUNET_ClientServerConnection
                                       *sock, const char *section,
                                       const char *option)
{
  CS_getoption_request_MESSAGE req;
  CS_getoption_reply_MESSAGE *reply;
  int res;
  char *ret;

  memset (&req, 0, sizeof (CS_getoption_request_MESSAGE));
  req.header.type = htons (GNUNET_CS_PROTO_GET_OPTION_REQUEST);
  req.header.size = htons (sizeof (CS_getoption_request_MESSAGE));
  if ((strlen (section) >= CS_getoption_request_MESSAGE_OPT_LEN) ||
      (strlen (option) >= CS_getoption_request_MESSAGE_OPT_LEN))
    return NULL;
  strcpy (&req.section[0], section);
  strcpy (&req.option[0], option);
  res = GNUNET_client_connection_write (sock, &req.header);
  if (res != GNUNET_OK)
    return NULL;
  reply = NULL;
  res =
    GNUNET_client_connection_read (sock, (GNUNET_MessageHeader **) & reply);
  if (res != GNUNET_OK)
    return NULL;
  ret =
    GNUNET_malloc (ntohs (reply->header.size) -
                   sizeof (GNUNET_MessageHeader) + 1);
  memcpy (ret, &reply->value[0],
          ntohs (reply->header.size) - sizeof (GNUNET_MessageHeader));
  ret[ntohs (reply->header.size) - sizeof (GNUNET_MessageHeader)] = '\0';
  GNUNET_free (reply);
  return ret;
}
