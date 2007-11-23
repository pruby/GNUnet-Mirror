/*
      This file is part of GNUnet
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
 * @file include/gnunet_peerinfo_lib.h
 * @brief convenience API to get information about other peers
 * @author Christian Grothoff
 */

#ifndef GNUNET_PEERINFO_LIB_H
#define GNUNET_PEERINFO_LIB_H

#include "gnunet_util.h"
#include "gnunet_util_network_client.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#define PEERINFO_VERSION "0.0.0"

/**
 * @param name the name of the peer
 * @param id identity of the peer
 * @param trust trust we have in the peer
 *
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
typedef int (*PEERINFO_PeerProcessor) (const char *name,
                                       const GNUNET_PeerIdentity * id,
                                       unsigned int trust, void *cls);

/**
 * Request information about peers.
 *
 * @param sock the socket to use
 * @param processor function to call on each value
 * @param connected_only only list currently connected peers
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int PEERINFO_getInfo (struct GE_Context *ectx,
                      struct GNUNET_ClientServerConnection *sock,
                      int connected_only,
                      PEERINFO_PeerProcessor processor, void *cls);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
