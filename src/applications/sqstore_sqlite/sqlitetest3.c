/*
     This file is part of GNUnet.
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
/*
 * @file applications/sqstore_mysql/mysqltest3.c
 * @brief Profile sqstore iterators.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_util_cron.h"
#include "gnunet_util_crypto.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_protocols.h"
#include "gnunet_sqstore_service.h"
#include "core.h"

/**
 * Target datastore size (in bytes).  Realistic sizes are
 * more like 16 GB (not the default of 16 MB); however,
 * those take too long to run them in the usual "make check"
 * sequence.  Hence the value used for shipping is tiny.
 */
#define MAX_SIZE 1024LL * 1024 * 128

#define ITERATIONS 10

/**
 * Number of put operations equivalent to 1/10th of MAX_SIZE
 */
#define PUT_10 (MAX_SIZE / 32 / 1024 / ITERATIONS)

static unsigned long long stored_bytes;

static unsigned long long stored_entries;

static unsigned long long stored_ops;

static cron_t start_time;

static int
putValue (SQstore_ServiceAPI * api, int i)
{
  Datastore_Value *value;
  size_t size;
  static HashCode512 key;
  static int ic;

  /* most content is 32k */
  size = sizeof (Datastore_Value) + 32 * 1024;

  if (weak_randomi (16) == 0)   /* but some of it is less! */
    size = sizeof (Datastore_Value) + weak_randomi (32 * 1024);
  size = size - (size & 7);     /* always multiple of 8 */

  /* generate random key */
  key.bits[0] = (unsigned int) get_time ();
  hash (&key, sizeof (HashCode512), &key);
  value = MALLOC (size);
  value->size = htonl (size);
  value->type = htonl (i);
  value->prio = htonl (weak_randomi (100));
  value->anonymityLevel = htonl (i);
  value->expirationTime =
    htonll (get_time () + 60 * cronHOURS + weak_randomi (1000));
  memset (&value[1], i, size - sizeof (Datastore_Value));
  if (OK != api->put (&key, value))
    {
      FREE (value);
      fprintf (stderr, "E");
      return SYSERR;
    }
  ic++;
  stored_bytes += ntohl (value->size);
  stored_ops++;
  stored_entries++;
  FREE (value);
  return OK;
}

static int
iterateDummy (const HashCode512 * key, const Datastore_Value * val, void *cls,
              unsigned long long uid)
{
  if (GNUNET_SHUTDOWN_TEST () == YES)
    return SYSERR;
  return OK;
}

static int
test (SQstore_ServiceAPI * api)
{
  int i;
  int j;
  int ret;
  cron_t start;
  cron_t end;

  for (i = 0; i < ITERATIONS; i++)
    {
      /* insert data equivalent to 1/10th of MAX_SIZE */
      start = get_time ();
      for (j = 0; j < PUT_10; j++)
        {
          if (OK != putValue (api, j))
            break;
          if (GNUNET_SHUTDOWN_TEST () == YES)
            break;
        }
      end = get_time ();
      printf ("%3u insertion              took %20llums\n", i, end - start);
      if (GNUNET_SHUTDOWN_TEST () == YES)
        break;
      start = get_time ();
      ret = api->iterateLowPriority (0, &iterateDummy, api);
      end = get_time ();
      printf ("%3u low priority iteration took %20llums (%d)\n", i,
              end - start, ret);
      if (GNUNET_SHUTDOWN_TEST () == YES)
        break;
      start = get_time ();
      ret = api->iterateExpirationTime (0, &iterateDummy, api);
      end = get_time ();
      printf ("%3u expiration t iteration took %20llums (%d)\n", i,
              end - start, ret);
      if (GNUNET_SHUTDOWN_TEST () == YES)
        break;
      start = get_time ();
      ret = api->iterateNonAnonymous (0, &iterateDummy, api);
      end = get_time ();
      printf ("%3u non anonymou iteration took %20llums (%d)\n", i,
              end - start, ret);
      if (GNUNET_SHUTDOWN_TEST () == YES)
        break;
      start = get_time ();
      ret = api->iterateMigrationOrder (&iterateDummy, api);
      end = get_time ();
      printf ("%3u migration or iteration took %20llums (%d)\n", i,
              end - start, ret);
      if (GNUNET_SHUTDOWN_TEST () == YES)
        break;
      start = get_time ();
      ret = api->iterateAllNow (&iterateDummy, api);
      end = get_time ();
      printf ("%3u all now      iteration took %20llums (%d)\n", i,
              end - start, ret);
      if (GNUNET_SHUTDOWN_TEST () == YES)
        break;
    }
  api->drop ();
  return OK;
}

int
main (int argc, char *argv[])
{
  SQstore_ServiceAPI *api;
  int ok;
  struct GC_Configuration *cfg;
  struct CronManager *cron;

  cfg = GC_create_C_impl ();
  if (-1 == GC_parse_configuration (cfg, "check.conf"))
    {
      GC_free (cfg);
      return -1;
    }
  cron = cron_create (NULL);
  initCore (NULL, cfg, cron, NULL);
  api = requestService ("sqstore");
  if (api != NULL)
    {
      start_time = get_time ();
      ok = test (api);
      releaseService (api);
    }
  else
    ok = SYSERR;
  doneCore ();
  cron_destroy (cron);
  GC_free (cfg);
  if (ok == SYSERR)
    return 1;
  return 0;
}

/* end of mysqltest3.c */
