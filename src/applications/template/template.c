/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/template/template.c
 * @author Christian Grothoff
 * @brief template for a GNUnet module
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_core.h"
#include "gnunet_protocols.h"

static CoreAPIForApplication * coreAPI = NULL;
static ClientHandle client;
static Mutex lock;

static int handlep2pMSG(const PeerIdentity * sender,
		        const P2P_MESSAGE_HEADER * message) {
  return OK;
}

static int csHandle(ClientHandle client,
		    const CS_MESSAGE_HEADER * message) {
  return OK;
}

static void clientExitHandler(ClientHandle c) {
  MUTEX_LOCK(&lock);
  if (c == client)
    client = NULL;
  MUTEX_UNLOCK(&lock);
}

int initialize_module_template(CoreAPIForApplication * capi) {
  int ok = OK;

  MUTEX_CREATE(&lock);
  client = NULL;
  coreAPI = capi;

  LOG(LOG_DEBUG,
      _("`%s' registering client handler %d and %d\n"),
      "template",
      CS_PROTO_MAX_USED,
      P2P_PROTO_MAX_USED);
  if (SYSERR == capi->registerHandler(P2P_PROTO_MAX_USED,
				      &handlep2pMSG))
    ok = SYSERR;
  if (SYSERR == capi->registerClientExitHandler(&clientExitHandler))
    ok = SYSERR;
  if (SYSERR == capi->registerClientHandler(CS_PROTO_MAX_USED,
					    &csHandle))
    ok = SYSERR;
  return ok;
}

void done_module_template() {
  coreAPI->unregisterHandler(P2P_PROTO_MAX_USED,
			     &handlep2pMSG);
  coreAPI->unregisterClientExitHandler(&clientExitHandler);
  coreAPI->unregisterClientHandler(CS_PROTO_MAX_USED,
				   &csHandle);
  MUTEX_DESTROY(&lock);
  coreAPI = NULL;
}

/* end of template.c */
