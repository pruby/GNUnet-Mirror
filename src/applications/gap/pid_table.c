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
 * @file gap/pid_table.c
 * @brief peer-ID table that assigns integer IDs to peer-IDs to save memory
 * @author Christian Grothoff
 */

#include "platform.h"
#include "pid_table.h"

/**
 * Statistics service.
 */
static Stats_ServiceAPI *stats;

static int stat_pid_entries;

static int stat_pid_rc;

static struct GE_Context *ectx;

typedef struct
{
  /**
   * the identifier itself
   */
  HashCode512 id;

  /**
   * reference counter
   */
  unsigned int rc;
} PID_Entry;

static unsigned int size;

static PID_Entry *table;

static struct MUTEX *lock;


PID_INDEX
intern_pid (const PeerIdentity * pid)
{
  PID_INDEX ret;
  PID_INDEX zero;

  if (pid == NULL)
    return 0;
  zero = size;
  MUTEX_LOCK (lock);
  for (ret = 1; ret < size; ret++)
    {
      if (0 == memcmp (&pid->hashPubKey,
                       &table[ret].id, sizeof (HashCode512)))
        {
          table[ret].rc++;
          if (stats != NULL)
            {
              stats->change (stat_pid_rc, 1);
              if (table[ret].rc == 1)
                stats->change (stat_pid_entries, 1);
            }
          MUTEX_UNLOCK (lock);
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
      GROW (table, size, size + 16);
    }
  if (ret == 0)
    ret = 1;
  GE_ASSERT (ectx, ret < size);
  table[ret].id = pid->hashPubKey;
  table[ret].rc = 1;
  MUTEX_UNLOCK (lock);
  if (stats != NULL)
    {
      stats->change (stat_pid_rc, 1);
      stats->change (stat_pid_entries, 1);
    }
  return ret;
}

void
decrement_pid_rcs (const PID_INDEX * ids, unsigned int count)
{
  int i;
  PID_INDEX id;
  if (count == 0)
    return;
  MUTEX_LOCK (lock);
  for (i = count - 1; i >= 0; i--)
    {
      id = ids[i];
      GE_ASSERT (ectx, id < size);
      GE_ASSERT (ectx, table[id].rc > 0);
      table[id].rc--;
      if ((table[id].rc == 0) && (stats != NULL))
        stats->change (stat_pid_entries, -1);
    }
  MUTEX_UNLOCK (lock);
  if (stats != NULL)
    stats->change (stat_pid_rc, -count);
}

void
change_pid_rc (PID_INDEX id, int delta)
{
  if (id == 0)
    return;
  MUTEX_LOCK (lock);
  GE_ASSERT (ectx, id < size);
  GE_ASSERT (ectx, table[id].rc > 0);
  table[id].rc += delta;
  if (stats != NULL)
    {
      stats->change (stat_pid_rc, delta);
      if (table[id].rc == 0)
        stats->change (stat_pid_entries, -1);
    }
  MUTEX_UNLOCK (lock);
}

void
resolve_pid (PID_INDEX id, PeerIdentity * pid)
{
  if (id == 0)
    {
      memset (pid, 0, sizeof (PeerIdentity));
      GE_BREAK (ectx, 0);
      return;
    }
  MUTEX_LOCK (lock);
  GE_ASSERT (ectx, id < size);
  GE_ASSERT (ectx, table[id].rc > 0);
  pid->hashPubKey = table[id].id;
  MUTEX_UNLOCK (lock);
}


void
init_pid_table (struct GE_Context *e, Stats_ServiceAPI * s)
{
  ectx = e;
  stats = s;
  if (stats != NULL)
    {
      stat_pid_entries
        =
        stats->
        create (gettext_noop ("# distinct interned peer IDs in pid table"));
      stat_pid_rc =
        stats->
        create (gettext_noop
                ("# total RC of interned peer IDs in pid table"));
    }
  lock = MUTEX_CREATE (NO);
}


void
done_pid_table ()
{
  GROW (table, size, 0);
  stats = NULL;
  MUTEX_DESTROY (lock);
  lock = NULL;
  ectx = NULL;
}

/* end of pid_table.c */
