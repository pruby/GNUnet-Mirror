 /*
    This file is part of GNUnet
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

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_core.h"
#include "gnunet_protocols.h"
#include "getoption.h"

/**
 * @file getoption/getoption.c
 * @brief protocol that allows clients to ask for the
 *        value of GNUnet options
 * @author Christian Grothoff
 */

static GNUNET_CoreAPIForPlugins *coreAPI;

static int
handleGetOption (struct GNUNET_ClientHandle *sock,
                 const GNUNET_MessageHeader * message)
{
  CS_getoption_request_MESSAGE *req;
  CS_getoption_reply_MESSAGE *rep;
  char *val;
  int ret;

  if (ntohs (message->size) != sizeof (CS_getoption_request_MESSAGE))
    return GNUNET_SYSERR;
  req = (CS_getoption_request_MESSAGE *) message;
  req->section[CS_getoption_request_MESSAGE_OPT_LEN - 1] = '\0';
  req->option[CS_getoption_request_MESSAGE_OPT_LEN - 1] = '\0';
  val = NULL;
  if (GNUNET_NO == GNUNET_GC_have_configuration_value (coreAPI->cfg,
                                                       req->section,
                                                       req->option))
    return GNUNET_SYSERR;       /* signal error: option not set */
  if ((0 != GNUNET_GC_get_configuration_value_string (coreAPI->cfg,
                                                      req->section,
                                                      req->option,
                                                      NULL, &val))
      || (val == NULL))
    return GNUNET_SYSERR;       /* signal error: option not set */

  rep = GNUNET_malloc (sizeof (GNUNET_MessageHeader) + strlen (val) + 1);
  rep->header.size = htons (sizeof (GNUNET_MessageHeader) + strlen (val) + 1);
  memcpy (rep->value, val, strlen (val) + 1);
  rep->header.type = htons (GNUNET_CS_PROTO_GET_OPTION_REPLY);
  ret = coreAPI->cs_send_to_client (sock, &rep->header, GNUNET_YES);
  GNUNET_free (rep);
  GNUNET_free (val);
  return ret;
}

int
initialize_module_getoption (GNUNET_CoreAPIForPlugins * capi)
{
  coreAPI = capi;
  GNUNET_GE_LOG (capi->ectx,
                 GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                 _("`%s' registering client handler %d\n"),
                 "getoption", GNUNET_CS_PROTO_GET_OPTION_REQUEST);
  capi->registerClientHandler (GNUNET_CS_PROTO_GET_OPTION_REQUEST,
                               &handleGetOption);
  GNUNET_GE_ASSERT (capi->ectx,
                    0 == GNUNET_GC_set_configuration_value_string (capi->cfg,
                                                                   capi->ectx,
                                                                   "ABOUT",
                                                                   "getoption",
                                                                   _
                                                                   ("allows clients to determine gnunetd's"
                                                                    " configuration")));
  return GNUNET_OK;
}

void
done_module_getoption ()
{
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_GET_OPTION_REQUEST,
                                    &handleGetOption);
  coreAPI = NULL;
}
