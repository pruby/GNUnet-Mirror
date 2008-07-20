/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/datastore/datastore.c
 * @brief This module is responsible to manage content, in particular
 *        it needs to decide what content to keep.  This module
 *        also uses the bloomfilter to reduce get operations on the
 *        database.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_directories.h"
#include "gnunet_protocols.h"
#include "gnunet_datastore_service.h"
#include "gnunet_sqstore_service.h"
#include "gnunet_state_service.h"
#include "gnunet_stats_service.h"
#include "filter.h"
#include "prefetch.h"

#define DEBUG_DATASTORE GNUNET_NO

#define MAINTENANCE_FREQUENCY (10 * GNUNET_CRON_SECONDS)

/**
 * SQ-store handle
 */
static GNUNET_SQstore_ServiceAPI *sq;

/**
 * Core API handle.
 */
static GNUNET_CoreAPIForPlugins *coreAPI;

/**
 * Minimum priority in the DB.
 */
static unsigned int minPriority;

/**
 * Available space (maybe negative!)
 */
static long long available;

/**
 * Quota from config file.
 */
static unsigned long long quota;

static struct GNUNET_CronManager *cron;

static struct GNUNET_Mutex *lock;

static GNUNET_Stats_ServiceAPI *stats;

static int stat_filtered;

static int stat_filter_failed;

/**
 * Time at which the database was created (used for
 * content aging).
 */
static GNUNET_Int32Time db_creation_time;

/**
 * Require 1/100th of quota to be 'free' space.
 */
#define MIN_GNUNET_free (quota / 100)

/**
 * One month of database uptime corresponds to one
 * priority point.
 */
static int
comp_priority ()
{
  GNUNET_Int32Time now;
  GNUNET_get_time_int32 (&now);
  if (db_creation_time < now)
    return 1;
  return 1 + (db_creation_time - now) / 60 / 60 / 24 / 30;
}

static unsigned long long
getSize ()
{
  return sq->getSize ();
}

static int
get (const GNUNET_HashCode * query,
     unsigned int type, GNUNET_DatastoreValueIterator iter, void *closure)
{
  int ret = 0;

  if (!testAvailable (query))
    {
#if DEBUG_DATASTORE
      GNUNET_EncName enc;

      IF_GELOG (coreAPI->ectx,
                GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                GNUNET_hash_to_enc (query, &enc));
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Datastore availability pre-test failed for `%s'.\n",
                     &enc);
#endif
      if (stats != NULL)
        stats->change (stat_filtered, 1);

#if 0
      /* this is just an extra check to validate that 
         the bloomfilter was corret; doing this check
         is very costly -- do not do in production! */
      ret = sq->get (query, NULL, type, iter, closure);
      GNUNET_GE_BREAK (NULL, ret == 0);
#endif
      return ret;
    }
  ret = sq->get (query, NULL, type, iter, closure);
  if ((ret == 0) && (stats != NULL))
    stats->change (stat_filter_failed, 1);
  return ret;
}


static int
deleteCB (const GNUNET_HashCode * key,
          const GNUNET_DatastoreValue * value, void *closure,
          unsigned long long uid)
{
  const GNUNET_DatastoreValue *have = closure;
  if (have == NULL)
    return GNUNET_NO;
  if ((value->size == have->size) &&
      (0 == memcmp (&have[1],
                    &value[1],
                    ntohl (value->size) - sizeof (GNUNET_DatastoreValue))))
    return GNUNET_NO;
  return GNUNET_OK;
}

/**
 * Explicitly remove some content from the database.
 */
static int
del (const GNUNET_HashCode * query, const GNUNET_DatastoreValue * value)
{
  int ok;
  int ret;
  GNUNET_EncName enc;
  GNUNET_HashCode vhc;

  if (!testAvailable (query))
    {
      IF_GELOG (coreAPI->ectx,
                GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                GNUNET_hash_to_enc (query, &enc));
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Availability test failed for `%s' at %s:%d.\n"), &enc,
                     __FILE__, __LINE__);
      return GNUNET_NO;
    }
  GNUNET_hash (&value[1],
               ntohl (value->size) - sizeof (GNUNET_DatastoreValue), &vhc);
  ok = sq->get (query, &vhc, ntohl (value->type), &deleteCB, (void *) value);
  if (ok == GNUNET_SYSERR)
    return GNUNET_SYSERR;
  if (ok == 0)
    {
      IF_GELOG (coreAPI->ectx,
                GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                GNUNET_hash_to_enc (query, &enc));
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Availability test failed for `%s' at %s:%d.\n"), &enc,
                     __FILE__, __LINE__);
      return GNUNET_NO;
    }
  ret = ok;
  while (ok-- > 0)
    {
      makeUnavailable (query);  /* update bloom filter! */
      available += ntohl (value->size);
    }
  return ret;
}

typedef struct
{
  int exists;
  const GNUNET_DatastoreValue *value;
  unsigned long long uid;
  GNUNET_CronTime expiration;
} CE;

static int
checkExists (const GNUNET_HashCode * key,
             const GNUNET_DatastoreValue * value, void *cls,
             unsigned long long uid)
{
  CE *ce = cls;

  if ((value->size != ce->value->size) ||
      (0 != memcmp (&value[1],
                    &ce->value[1],
                    ntohl (value->size) - sizeof (GNUNET_DatastoreValue))))
    return GNUNET_OK;           /* found another value, but different content! */
  ce->uid = uid;
  ce->expiration = GNUNET_ntohll (value->expiration_time);
  ce->exists = GNUNET_YES;
  return GNUNET_SYSERR;         /* abort iteration! */
}

/**
 * Store an item in the datastore.  If the item is already present,
 * the priorities are summed up and the higher expiration time and
 * lower anonymity level is used.
 *
 * @return GNUNET_YES on success, GNUNET_NO if the datastore is
 *   full and the priority of the item is not high enough
 *   to justify removing something else, GNUNET_SYSERR on
 *   other serious error (i.e. IO permission denied)
 */
static int
putUpdate (const GNUNET_HashCode * key, const GNUNET_DatastoreValue * value)
{
  CE cls;
  int ok;
  int comp_prio;
  GNUNET_DatastoreValue *nvalue;
  GNUNET_HashCode vhc;

  /* check if it already exists... */
  cls.exists = GNUNET_NO;
  cls.value = value;
  GNUNET_hash (&value[1],
               ntohl (value->size) - sizeof (GNUNET_DatastoreValue), &vhc);
  GNUNET_mutex_lock (lock);
  sq->get (key, &vhc, ntohl (value->type), &checkExists, &cls);
  if ((!cls.exists) && (ntohl (value->type) == GNUNET_ECRS_BLOCKTYPE_DATA))
    sq->get (key, &vhc, GNUNET_ECRS_BLOCKTYPE_ONDEMAND, &checkExists, &cls);
  if (cls.exists)
    {
      if ((ntohl (value->priority) == 0) &&
          (GNUNET_ntohll (value->expiration_time) <= cls.expiration))
        {
          GNUNET_mutex_unlock (lock);
          return GNUNET_OK;
        }
      /* update priority */
      sq->update (cls.uid,
                  ntohl (value->priority),
                  GNUNET_ntohll (value->expiration_time));
      GNUNET_mutex_unlock (lock);
      return GNUNET_OK;
    }
  comp_prio = comp_priority ();
#if DEBUG_DATASTORE
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Migration: available %llu (need %u), min priority %u have %u\n",
                 available, ntohl (value->size), minPriority,
                 ntohl (value->priority) + comp_prio);
#endif
  /* check if we have enough space / priority */
  if ((available < ntohl (value->size)) ||
      (minPriority >= ntohl (value->priority) + comp_prio))
    {
      /* new content either does not fit (for sure)
         or has such a low priority that we should
         not even bother! */
      GNUNET_mutex_unlock (lock);
      return GNUNET_NO;
    }
  if (ntohl (value->priority) + comp_prio < minPriority)
    minPriority = ntohl (value->priority) + comp_prio;
  /* construct new value with comp'ed priority */
  nvalue = GNUNET_malloc (ntohl (value->size));
  memcpy (nvalue, value, ntohl (value->size));
  nvalue->priority = htonl (comp_priority () + ntohl (value->priority));
  /* add the content */
  ok = sq->put (key, nvalue);
  GNUNET_free (nvalue);
  if (ok == GNUNET_YES)
    {
      makeAvailable (key);
      available -= ntohl (value->size);
    }
  GNUNET_mutex_unlock (lock);
  return ok;
}

/**
 * @return *closure if we are below quota,
 *         GNUNET_SYSERR if we have deleted all of the expired content
 *                       (or if we should briefly stop doing this to give
 *                        other work a chance to progress)
 *         GNUNET_OK if we deleted expired content and are above quota
 */
static int
freeSpaceExpired (const GNUNET_HashCode * key,
                  const GNUNET_DatastoreValue * value, void *closure,
                  unsigned long long uid)
{
  GNUNET_CronTime * start = closure;
  GNUNET_CronTime now;

  now = GNUNET_get_time();
  if ( (now - *start > MAINTENANCE_FREQUENCY / 2) ||
       (GNUNET_get_time () < GNUNET_ntohll (value->expiration_time)) )
    return GNUNET_SYSERR;       /* not expired */
  available += ntohl (value->size);
  minPriority = 0;
  return GNUNET_NO;
}

static int
freeSpaceLow (const GNUNET_HashCode * key,
              const GNUNET_DatastoreValue * value, void *closure,
              unsigned long long uid)
{
  if ((available > 0) && (available >= MIN_GNUNET_free))
    return GNUNET_SYSERR;
  if (ntohl (value->priority) > minPriority)
    minPriority = ntohl (value->priority);
  available += ntohl (value->size);
  return GNUNET_NO;
}

/**
 * Cron-job that deletes low-priority/expired content
 * if we are about to run out of space.
 *
 * Also updates available and minPriority.
 */
static void
cronMaintenance (void *unused)
{
  GNUNET_CronTime now = GNUNET_get_time();

  available = quota - sq->getSize ();
  sq->iterateExpirationTime (GNUNET_ECRS_BLOCKTYPE_ANY,
                             &freeSpaceExpired, &now);
  if ((available < 0) || (available < MIN_GNUNET_free))
    sq->iterateLowPriority (GNUNET_ECRS_BLOCKTYPE_ANY, &freeSpaceLow, NULL);
}

/**
 * Initialize the manager-module.
 */
GNUNET_Datastore_ServiceAPI *
provide_module_datastore (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_Datastore_ServiceAPI api;
  unsigned long long lquota;
  unsigned long long sqot;
  GNUNET_State_ServiceAPI *state;
  struct stat sbuf;
  char *fsdir;

  if (-1 == GNUNET_GC_get_configuration_value_number (capi->cfg,
                                                      "FS",
                                                      "QUOTA",
                                                      0,
                                                      ((unsigned long long)
                                                       -1) / 1024 / 1024,
                                                      1024, &lquota))
    {
      GNUNET_GE_BREAK (capi->ectx, 0);
      return NULL;              /* OOPS */
    }
  quota = lquota * 1024 * 1024; /* MB to bytes */
  stats = capi->service_request ("stats");
  if (stats != NULL)
    {
      stat_filtered =
        stats->create (gettext_noop ("# requests filtered by bloom filter"));
      stat_filter_failed =
        stats->create (gettext_noop ("# bloom filter false positives"));

      stats->set (stats->
                  create (gettext_noop ("# bytes allowed in datastore")),
                  quota);
    }
  state = capi->service_request ("state");
  if (state != NULL)
    {
      sqot = GNUNET_htonll (lquota);
      state->write (capi->ectx,
                    "FS-LAST-QUOTA", sizeof (unsigned long long), &sqot);
      capi->service_release (state);
    }
  else
    {
      GNUNET_GE_LOG (capi->ectx,
                     GNUNET_GE_USER | GNUNET_GE_ADMIN | GNUNET_GE_ERROR |
                     GNUNET_GE_BULK,
                     _
                     ("Failed to load state service. Trying to do without.\n"));
    }
  sq = capi->service_request ("sqstore");
  if (sq == NULL)
    {
      if (stats != NULL)
        {
          capi->service_release (stats);
          stats = NULL;
        }
      GNUNET_GE_BREAK (capi->ectx, 0);
      return NULL;
    }
  coreAPI = capi;
  initPrefetch (capi->ectx, capi->cfg, sq);
  if (GNUNET_OK != initFilters (capi->ectx, capi->cfg))
    {
      GNUNET_GE_BREAK (capi->ectx, 0);
      donePrefetch ();
      capi->service_release (sq);
      if (stats != NULL)
        {
          capi->service_release (stats);
          stats = NULL;
        }
      return NULL;
    }
  lock = GNUNET_mutex_create (GNUNET_NO);
  fsdir = NULL;
  GNUNET_GC_get_configuration_value_filename (capi->cfg,
                                              "FS",
                                              "DIR",
                                              GNUNET_DEFAULT_DAEMON_VAR_DIRECTORY
                                              "/data/fs/", &fsdir);
  /* just in case dir does not exist ... */
  GNUNET_disk_directory_create (NULL, fsdir);
  if (0 == STAT (fsdir, &sbuf))
    db_creation_time = sbuf.st_ctime;
  GNUNET_free (fsdir);

  available = quota - sq->getSize ();
  cron = GNUNET_cron_create (capi->ectx);
  GNUNET_cron_add_job (cron,
                       &cronMaintenance, 
		       MAINTENANCE_FREQUENCY,
                       MAINTENANCE_FREQUENCY, NULL);
  GNUNET_cron_start (cron);
  api.getSize = &getSize;
  api.fast_get = &testAvailable;
  api.putUpdate = &putUpdate;
  api.get = &get;
  api.getRandom = &getRandom;   /* in prefetch.c */
  api.del = &del;

  return &api;
}

/**
 * Shutdown the manager module.
 */
void
release_module_datastore ()
{
  GNUNET_cron_stop (cron);
  GNUNET_cron_del_job (cron, &cronMaintenance, 
		       MAINTENANCE_FREQUENCY,
                       NULL);
  GNUNET_cron_destroy (cron);
  cron = NULL;
  donePrefetch ();
  doneFilters ();
  coreAPI->service_release (sq);
  if (stats != NULL)
    {
      coreAPI->service_release (stats);
      stats = NULL;
    }
  GNUNET_mutex_destroy (lock);
  sq = NULL;
  coreAPI = NULL;
}

struct FAAProgressInfo
{
  unsigned long long pos;
  unsigned long long total;
  GNUNET_CronTime start;
};

/**
 * Callback that adds all element of the SQStore to the
 * bloomfilter.
 */
static int
filterAddAll (const GNUNET_HashCode * key,
              const GNUNET_DatastoreValue * value, void *closure,
              unsigned long long uid)
{
  struct FAAProgressInfo *pi = closure;
  unsigned int pct_old;
  unsigned int pct;

  makeAvailable (key);
  pct_old = (100 * pi->pos) / pi->total;
  pi->pos += ntohl (value->size);
  pct = (100 * pi->pos) / pi->total;
  if (pct != pct_old)
    {
      fprintf (stdout,
               _("Datastore conversion at approximately %u%%\n"), pct);
    }

  return GNUNET_OK;
}

/**
 * Update Datastore.  Currently only re-builds the bloomfilter.
 * At some point we'll want to add code to convert data between
 * different sqstore's here, too.
 */
void
update_module_datastore (GNUNET_UpdateAPI * uapi)
{
  unsigned long long quota;
  unsigned long long lastQuota;
  unsigned long long *lq;
  GNUNET_State_ServiceAPI *state;
  struct FAAProgressInfo pi;

  if (-1 == GNUNET_GC_get_configuration_value_number (uapi->cfg,
                                                      "FS",
                                                      "QUOTA",
                                                      0,
                                                      ((unsigned long long)
                                                       -1) / 1024 / 1024,
                                                      1024, &quota))
    return;                     /* OOPS */
  state = uapi->service_request ("state");
  lq = NULL;
  if ((state != NULL) &&
      (sizeof (unsigned long long) == state->read (uapi->ectx,
                                                   "FS-LAST-QUOTA",
                                                   (void **) &lq)) &&
      (GNUNET_ntohll (*lq) == quota))
    {
      uapi->service_release (state);
      GNUNET_free (lq);
      return;                   /* no change */
    }
  /* ok, need to convert! */
  deleteFilter (uapi->ectx, uapi->cfg);
  initFilters (uapi->ectx, uapi->cfg);
  sq = uapi->service_request ("sqstore");
  if (sq != NULL)
    {
      fprintf (stdout,
               _("Starting datastore conversion (this may take a while).\n"));
      pi.start = GNUNET_get_time ();
      pi.pos = 0;
      pi.total = (lq != NULL) ? GNUNET_ntohll (*lq) : 0;
      if (pi.total == 0)
        pi.total = 1;
      sq->iterateAllNow (&filterAddAll, &pi);
      uapi->service_release (sq);
      fprintf (stdout, _("Completed datastore conversion.\n"));
    }
  else
    {
      GNUNET_GE_LOG (uapi->ectx,
                     GNUNET_GE_USER | GNUNET_GE_ADMIN | GNUNET_GE_ERROR |
                     GNUNET_GE_BULK,
                     _
                     ("Failed to load sqstore service.  Check your configuration!\n"));
    }
  GNUNET_free_non_null (lq);
  sq = NULL;
  doneFilters ();
  if (state != NULL)
    {
      lastQuota = GNUNET_htonll (quota);
      state->write (uapi->ectx,
                    "FS-LAST-QUOTA", sizeof (unsigned long long), &lastQuota);
      uapi->service_release (state);
    }
}


/* end of datastore.c */
