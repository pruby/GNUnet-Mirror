/*
      This file is part of GNUnet
      (C) 2004, 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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
 * @file dht/tools/dht_api.h
 * @brief DHT-module's core API's implementation.
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "dht.h"
#include "gnunet_dht_lib.h"
#include "gnunet_util.h"


/**
 * Data exchanged between main thread and GET thread.
 */
struct GNUNET_DHT_Context
{

  /**
   * Connection with gnunetd.
   */
  struct GNUNET_ClientServerConnection *sock;

  /**
   * Callback to call for each result.
   */
  GNUNET_ResultProcessor processor;

  /**
   * Extra argument for processor.
   */
  void *closure;

  /**
   * Parent thread that is waiting for the
   * timeout (used to notify if we are exiting
   * early, i.e. because of gnunetd closing the
   * connection or the processor callback requesting
   * it).
   */
  struct GNUNET_ThreadHandle *poll_thread;      /*Poll thread instead.. */

  /**
   * Are we done (for whichever reason)?
   */
  int aborted;

};

/* end of dht_api.h */
