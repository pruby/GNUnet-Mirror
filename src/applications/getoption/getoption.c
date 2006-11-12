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

static CoreAPIForApplication * coreAPI;

static int handleGetOption(struct ClientHandle * sock,
			   const MESSAGE_HEADER * message) {
  CS_getoption_request_MESSAGE * req;
  CS_getoption_reply_MESSAGE * rep;
  char * val;
  int ret;

  if (ntohs(message->size) != sizeof(CS_getoption_request_MESSAGE))
    return SYSERR;
  req = (CS_getoption_request_MESSAGE*)message;
  req->section[CS_getoption_request_MESSAGE_OPT_LEN-1] = '\0';
  req->option[CS_getoption_request_MESSAGE_OPT_LEN-1] = '\0';
  val = NULL;
  if (NO == GC_have_configuration_value(coreAPI->cfg,
					req->section,
					req->option))
    return SYSERR; /* signal error: option not set */
  if ( (0 != GC_get_configuration_value_string(coreAPI->cfg,
					       req->section,
					       req->option,
					       NULL,
					       &val)) ||
       (val == NULL) )
    return SYSERR; /* signal error: option not set */

  rep = MALLOC(sizeof(MESSAGE_HEADER) + strlen(val) + 1);
  rep->header.size = htons(sizeof(MESSAGE_HEADER) + strlen(val) + 1);
  memcpy(rep->value,
	 val,
	 strlen(val)+1);
  rep->header.type = htons(CS_PROTO_GET_OPTION_REPLY);
  ret = coreAPI->sendToClient(sock,
			      &rep->header);
  FREE(rep);
  FREE(val);
  return ret;
}

int initialize_module_getoption(CoreAPIForApplication * capi) {
  coreAPI = capi;
  GE_LOG(capi->ectx,
	 GE_INFO | GE_USER | GE_REQUEST,
	 _("`%s' registering client handler %d\n"),
	 "getoption",
	 CS_PROTO_GET_OPTION_REQUEST);
  capi->registerClientHandler(CS_PROTO_GET_OPTION_REQUEST,
			      &handleGetOption);
  GE_ASSERT(capi->ectx,
	    0 == GC_set_configuration_value_string(capi->cfg,
						   capi->ectx,
						   "ABOUT",
						   "getoption",
						   _("allows clients to determine gnunetd's"
						     " configuration")));
  return OK;
}

void done_module_getoption() {
  coreAPI->unregisterClientHandler(CS_PROTO_GET_OPTION_REQUEST,
				   &handleGetOption);
  coreAPI = NULL;
}
