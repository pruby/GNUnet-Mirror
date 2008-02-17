/*
      This file is part of GNUnet
      (C) 2006, 2008 Christian Grothoff (and other contributing authors)

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

#ifndef GNUNET_PID_TABLE_H
#define GNUNET_PID_TABLE_H

#include "gnunet_util.h"
#include "gnunet_stats_service.h"

void GNUNET_FS_PT_init (struct GNUNET_GE_Context *ectx,
                        GNUNET_Stats_ServiceAPI * s);

void GNUNET_FS_PT_done (void);

typedef unsigned int PID_INDEX;

PID_INDEX GNUNET_FS_PT_intern (const GNUNET_PeerIdentity * pid);

void GNUNET_FS_PT_change_rc (PID_INDEX id, int delta);

void GNUNET_FS_PT_decrement_rcs (const PID_INDEX * ids, unsigned int count);

void GNUNET_FS_PT_resolve (PID_INDEX id, GNUNET_PeerIdentity * pid);

#endif
