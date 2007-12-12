/*
      This file is part of GNUnet
      (C) 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_tracekit_lib.h
 * @brief convenience API to the TRACEKIT service
 * @author Christian Grothoff
 */

#ifndef GNUNET_TRACEKIT_LIB_H
#define GNUNET_TRACEKIT_LIB_H

#include "gnunet_util.h"
#include "gnunet_util_network_client.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Function signature for data gathering callback
 *
 * @param reporter identity of the peer reporting a connection
 * @param link identity of another peer that the reporting peer
 *             is reported to be connected to, or NULL if the
 *             peer is reporting to have no connections at all
 * @return GNUNET_OK to continue data gathering,
 *         GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_TRACEKIT_ReportCallback) (void *cls,
                                               const GNUNET_PeerIdentity *
                                               reporter,
                                               const GNUNET_PeerIdentity *
                                               link);

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
int GNUNET_TRACEKIT_run (struct GNUNET_ClientServerConnection *sock,
                         unsigned int depth,
                         unsigned int priority,
                         GNUNET_TRACEKIT_ReportCallback report, void *cls);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
