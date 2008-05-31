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
 * @file fs/gap/pid_table.c
 * @brief peer-ID table that assigns integer IDs to peer-IDs to save memory
 * @author Christian Grothoff
 */

#include "platform.h"
#include "pid_table.h"
#include "shared.h"

/**
 * Statistics service.
 */
static GNUNET_Stats_ServiceAPI *stats;

static int stat_pid_entries;

static int stat_pid_rc;

static struct GNUNET_GE_Context *ectx;

typedef struct
{
  /**
   * the identifier itself
   */
  GNUNET_HashCode id;

  /**
   * reference counter
   */
  unsigned int rc;
} PID_Entry;

static unsigned int size;

static PID_Entry *table;


PID_INDEX
GNUNET_FS_PT_intern (const GNUNET_PeerIdentity * pid)
{
  PID_INDEX ret;
  PID_INDEX zero;

  if (pid == NULL)
    return 0;
  zero = size;
  GNUNET_mutex_lock (GNUNET_FS_lock);
  for (ret = 1; ret < size; ret++)
    {
      if (0 == memcmp (&pid->hashPubKey,
                       &table[ret].id, sizeof (GNUNET_HashCode)))
        {
          table[ret].rc++;
          if (stats != NULL)
            {
              stats->change (stat_pid_rc, 1);
              if (table[ret].rc == 1)
                stats->change (stat_pid_entries, 1);
            }
          GNUNET_mutex_unlock (GNUNET_FS_lock);
          return ret;
        }
      else if ((zero == size) && (table[ret].rc == 0))
        {
          zero = ret;
        }
    }
  ret = zero;
  if (ret == size)
    {
      GNUNET_array_grow (table, size, size + 16);
    }
  if (ret == 0)
    ret = 1;
  GNUNET_GE_ASSERT (ectx, ret < size);
  table[ret].id = pid->hashPubKey;
  table[ret].rc = 1;
  GNUNET_mutex_unlock (GNUNET_FS_lock);
  if (stats != NULL)
    {
      stats->change (stat_pid_rc, 1);
      stats->change (stat_pid_entries, 1);
    }
  return ret;
}

void
GNUNET_FS_PT_decrement_rcs (const PID_INDEX * ids, unsigned int count)
{
  int i;
  PID_INDEX id;
  if (count == 0)
    return;
  GNUNET_mutex_lock (GNUNET_FS_lock);
  for (i = count - 1; i >= 0; i--)
    {
      id = ids[i];
      GNUNET_GE_ASSERT (ectx, id < size);
      GNUNET_GE_ASSERT (ectx, table[id].rc > 0);
      table[id].rc--;
      if ((table[id].rc == 0) && (stats != NULL))
        stats->change (stat_pid_entries, -1);
    }
  GNUNET_mutex_unlock (GNUNET_FS_lock);
  if (stats != NULL)
    stats->change (stat_pid_rc, -count);
}

void
GNUNET_FS_PT_change_rc (PID_INDEX id, int delta)
{
  if (id == 0)
    return;
  GNUNET_mutex_lock (GNUNET_FS_lock);
  GNUNET_GE_ASSERT (ectx, id < size);
  GNUNET_GE_ASSERT (ectx, table[id].rc > 0);
  GNUNET_GE_ASSERT (ectx, (delta >= 0) || (table[id].rc >= -delta));
  table[id].rc += delta;
  if (stats != NULL)
    {
      stats->change (stat_pid_rc, delta);
      if (table[id].rc == 0)
        stats->change (stat_pid_entries, -1);
    }
  GNUNET_mutex_unlock (GNUNET_FS_lock);
}

void
GNUNET_FS_PT_resolve (PID_INDEX id, GNUNET_PeerIdentity * pid)
{
  if (id == 0)
    {
      memset (pid, 0, sizeof (GNUNET_PeerIdentity));
      GNUNET_GE_BREAK (ectx, 0);
      return;
    }
  GNUNET_mutex_lock (GNUNET_FS_lock);
  GNUNET_GE_ASSERT (ectx, id < size);
  GNUNET_GE_ASSERT (ectx, table[id].rc > 0);
  pid->hashPubKey = table[id].id;
  GNUNET_mutex_unlock (GNUNET_FS_lock);
}


void
GNUNET_FS_PT_init (struct GNUNET_GE_Context *e, GNUNET_Stats_ServiceAPI * s)
{
  ectx = e;
  stats = s;
  if (stats != NULL)
    {
      stat_pid_entries
        =
        stats->create (gettext_noop
                       ("# distinct interned peer IDs in pid table"));
      stat_pid_rc =
        stats->create (gettext_noop
                       ("# total RC of interned peer IDs in pid table"));
    }
}


void
GNUNET_FS_PT_done ()
{
  unsigned int i;

  for (i = 0; i < size; i++)
    GNUNET_GE_ASSERT (ectx, table[i].rc == 0);
  GNUNET_array_grow (table, size, 0);
  stats = NULL;
  ectx = NULL;
}

/* end of pid_table.c */
