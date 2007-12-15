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

static GNUNET_CoreAPIForPlugins *coreAPI = NULL;
static struct GNUNET_ClientHandle *client;
static struct GNUNET_Mutex *lock;

static int
handlep2pMSG (const GNUNET_PeerIdentity * sender,
              const GNUNET_MessageHeader * message)
{
  return GNUNET_OK;
}

static int
csHandle (struct GNUNET_ClientHandle *client,
          const GNUNET_MessageHeader * message)
{
  return GNUNET_OK;
}

static void
clientExitHandler (struct GNUNET_ClientHandle *c)
{
  GNUNET_mutex_lock (lock);
  if (c == client)
    client = NULL;
  GNUNET_mutex_unlock (lock);
}

int
initialize_module_template (GNUNET_CoreAPIForPlugins * capi)
{
  int ok = GNUNET_OK;

  lock = GNUNET_mutex_create (GNUNET_NO);
  client = NULL;
  coreAPI = capi;

  GNUNET_GE_LOG (capi->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _("`%s' registering client handler %d and %d\n"),
                 "template", GNUNET_CS_PROTO_MAX_USED,
                 GNUNET_P2P_PROTO_MAX_USED);
  if (GNUNET_SYSERR ==
      capi->registerHandler (GNUNET_P2P_PROTO_MAX_USED, &handlep2pMSG))
    ok = GNUNET_SYSERR;
  if (GNUNET_SYSERR == capi->cs_exit_handler_register (&clientExitHandler))
    ok = GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerClientHandler (GNUNET_CS_PROTO_MAX_USED, &csHandle))
    ok = GNUNET_SYSERR;
  return ok;
}

void
done_module_template ()
{
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_MAX_USED, &handlep2pMSG);
  coreAPI->cs_exit_handler_unregister (&clientExitHandler);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_MAX_USED, &csHandle);
  GNUNET_mutex_destroy (lock);
  coreAPI = NULL;
}

/* end of template.c */
