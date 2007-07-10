/*
      This file is part of GNUnet
     (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file gap/pid_table.h
 * @brief peer-ID table that assigns integer IDs to peer-IDs to save memory
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_stats_service.h"

void init_pid_table (struct GE_Context *ectx, Stats_ServiceAPI * s);

void done_pid_table (void);

typedef unsigned int PID_INDEX;

PID_INDEX intern_pid (const PeerIdentity * pid);

void change_pid_rc (PID_INDEX id, int delta);

void decrement_pid_rcs (const PID_INDEX * ids, unsigned int count);

void resolve_pid (PID_INDEX id, PeerIdentity * pid);
