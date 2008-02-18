
/*
      This file is part of GNUnet
      (C) 2008 Christian Grothoff (and other contributing authors)

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
      Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
      Boston, MA 02110-1301, USA.
 */

/**
 * @file fs/gap/plan.h
 * @brief code to plan when to send requests where
 * @author Christian Grothoff
 */

#ifndef PLAN_H
#define PLAN_H

#include "gnunet_core.h"
#include "shared.h"

/**
 * Plan the transmission of the given request.
 * Use the history of the request and the client
 * to schedule the request for transmission.
 * @return GNUNET_YES if planning succeeded
 */
int
GNUNET_FS_PLAN_request (struct GNUNET_ClientHandle *client,
                        PID_INDEX peer, struct RequestList *request);

/**
 * Notify the plan that a request succeeded.
 */
void
GNUNET_FS_PLAN_success (PID_INDEX responder,
                        struct GNUNET_ClientHandle *client,
                        PID_INDEX peer, const struct RequestList *success);

int GNUNET_FS_PLAN_init (GNUNET_CoreAPIForPlugins * capi);

int GNUNET_FS_PLAN_done (void);

#endif
