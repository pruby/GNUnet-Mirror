/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2006 Christian Grothoff (and other contributing authors)

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

static CoreAPIForApplication *coreAPI = NULL;
static struct ClientHandle *client;
static struct GNUNET_Mutex *lock;

static int
handlep2pMSG (const GNUNET_PeerIdentity * sender,
              const GNUNET_MessageHeader * message)
{
  return GNUNET_OK;
}

static int
csHandle (struct ClientHandle *client, const GNUNET_MessageHeader * message)
{
  return GNUNET_OK;
}

static void
clientExitHandler (struct ClientHandle *c)
{
  GNUNET_mutex_lock (lock);
  if (c == client)
    client = NULL;
  GNUNET_mutex_unlock (lock);
}

int
initialize_module_template (CoreAPIForApplication * capi)
{
  int ok = GNUNET_OK;

  lock = GNUNET_mutex_create (GNUNET_NO);
  client = NULL;
  coreAPI = capi;

  GE_LOG (capi->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          _("`%s' registering client handler %d and %d\n"),
          "template", CS_PROTO_MAX_USED, P2P_PROTO_MAX_USED);
  if (GNUNET_SYSERR ==
      capi->registerHandler (P2P_PROTO_MAX_USED, &handlep2pMSG))
    ok = GNUNET_SYSERR;
  if (GNUNET_SYSERR == capi->registerClientExitHandler (&clientExitHandler))
    ok = GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerClientHandler (CS_PROTO_MAX_USED, &csHandle))
    ok = GNUNET_SYSERR;
  return ok;
}

void
done_module_template ()
{
  coreAPI->unregisterHandler (P2P_PROTO_MAX_USED, &handlep2pMSG);
  coreAPI->unregisterClientExitHandler (&clientExitHandler);
  coreAPI->unregisterClientHandler (CS_PROTO_MAX_USED, &csHandle);
  GNUNET_mutex_destroy (lock);
  coreAPI = NULL;
}

/* end of template.c */
