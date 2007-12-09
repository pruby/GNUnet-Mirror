/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file applications/datastore/filter.c
 * @brief filter for requests to avoid sqstore lookups
 * @author Christian Grothoff
 */

#include "gnunet_directories.h"
#include "gnunet_util.h"
#include "filter.h"
#include "platform.h"

/**
 * Filter.
 */
static struct GNUNET_BloomFilter *filter;

static char *
getFilterName (struct GNUNET_GE_Context *ectx,
               struct GNUNET_GC_Configuration *cfg)
{
  char *fn;
  char *bf;

  fn = NULL;
  if (-1 == GNUNET_GC_get_configuration_value_filename (cfg,
                                                        "FS",
                                                        "DIR",
                                                        GNUNET_DEFAULT_DAEMON_VAR_DIRECTORY
                                                        "/fs", &fn))
    return NULL;
  if (GNUNET_OK != GNUNET_disk_directory_create (ectx, fn))
    {
      GNUNET_free (fn);
      return NULL;
    }
  bf = GNUNET_malloc (strlen (fn) + strlen ("/bloomfilter") + 1);
  strcpy (bf, fn);
  strcat (bf, "/bloomfilter");
  GNUNET_free (fn);
  return bf;
}

int
initFilters (struct GNUNET_GE_Context *ectx,
             struct GNUNET_GC_Configuration *cfg)
{
  char *bf;
  unsigned long long quota;     /* in kb */
  unsigned int bf_size;

  if (-1 == GNUNET_GC_get_configuration_value_number (cfg,
                                                      "FS",
                                                      "QUOTA",
                                                      0,
                                                      ((unsigned long long)
                                                       -1) / 1024 / 1024,
                                                      1024, &quota))
    return GNUNET_SYSERR;
  quota *= 1024;
  bf_size = quota / 32;         /* 8 bit per entry, 1 bit per 32 kb in DB */
  bf = getFilterName (ectx, cfg);
  if (bf == NULL)
    return GNUNET_SYSERR;
  filter = GNUNET_bloomfilter_load (ectx, bf, bf_size, 5);      /* approx. 3% false positives at max use */
  GNUNET_free (bf);
  if (filter == NULL)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

void
doneFilters ()
{
  if (filter != NULL)
    GNUNET_bloomfilter_free (filter);
}

void
deleteFilter (struct GNUNET_GE_Context *ectx,
              struct GNUNET_GC_Configuration *cfg)
{
  char *fn;

  GNUNET_GE_ASSERT (ectx, filter == NULL);
  fn = getFilterName (ectx, cfg);
  UNLINK (fn);
  GNUNET_free (fn);
}

void
makeAvailable (const GNUNET_HashCode * key)
{
  GNUNET_bloomfilter_add (filter, key);
}

void
makeUnavailable (const GNUNET_HashCode * key)
{
  GNUNET_bloomfilter_remove (filter, key);
}

int
testAvailable (const GNUNET_HashCode * key)
{
  return GNUNET_bloomfilter_test (filter, key);
}

/* end of filter.c */
