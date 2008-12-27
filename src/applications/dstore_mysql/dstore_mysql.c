/*
     This file is part of GNUnet.
     (C) 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/dstore_mysql/dstore_mysql.c
 * @brief MySQL based implementation of the dstore service
 * @author Christian Grothoff
 *
 * Database: MySQL
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_dstore_service.h"
#include "gnunet_stats_service.h"
#include "gnunet_mysql.h"

#define DEBUG_DSTORE GNUNET_NO

/**
 * Maximum size for an individual item.
 */
#define MAX_CONTENT_SIZE 65536

/**
 * Bytes used
 */
static unsigned long long payload;

/**
 * Maximum bytes available
 */
static unsigned long long quota;

static GNUNET_CoreAPIForPlugins *coreAPI;

static struct GNUNET_Mutex *lock;

/**
 * Statistics service.
 */
static GNUNET_Stats_ServiceAPI *stats;

static unsigned int stat_dstore_size;

static unsigned int stat_dstore_quota;

/**
 * Estimate of the per-entry overhead (including indices).
 */
#define OVERHEAD ((4*2+4*2+8*2+8*2+sizeof(GNUNET_HashCode)*5+8))

struct GNUNET_BloomFilter *bloom;

static char *bloom_name;

/**
 * Handle for the MySQL database.
 */
static struct GNUNET_MysqlDatabaseHandle *db;


#define SELECT_VALUE_STMT "SELECT size, value FROM gn080dstore FORCE INDEX (hashidx) WHERE hash=? AND type=? AND expire >= ? LIMIT 1 OFFSET ?"
static struct GNUNET_MysqlStatementHandle *select_value;

#define COUNT_VALUE_STMT "SELECT count(*) FROM gn080dstore FORCE INDEX (hashidx) WHERE hash=? AND type=? AND expire >= ?"
static struct GNUNET_MysqlStatementHandle *count_value;

#define SELECT_OLD_VALUE_STMT "SELECT hash, vhash, type, size, value FROM gn080dstore FORCE INDEX (expireidx) ORDER BY puttime ASC LIMIT 1"
static struct GNUNET_MysqlStatementHandle *select_old_value;

#define DELETE_VALUE_STMT "DELETE FROM gn080dstore WHERE hash = ? AND vhash = ? AND type = ? AND "\
                          "size = ? AND value = ?"
static struct GNUNET_MysqlStatementHandle *delete_value;

#define INSERT_VALUE_STMT "INSERT INTO gn080dstore (size, type, puttime, expire, hash, vhash, value) "\
                          "VALUES (?, ?, ?, ?, ?, ?, ?)"
static struct GNUNET_MysqlStatementHandle *insert_value;

#define UPDATE_VALUE_STMT "UPDATE gn080dstore FORCE INDEX (allidx) SET puttime=?, expire=? "\
                          "WHERE hash=? AND vhash=? AND type=? AND size=?"
static struct GNUNET_MysqlStatementHandle *update_value;

static int
itable ()
{
#define MRUNS(a) (GNUNET_OK != GNUNET_MYSQL_run_statement (db, a) )
  if (MRUNS ("CREATE TEMPORARY TABLE gn080dstore ("
             "  size INT(11) UNSIGNED NOT NULL DEFAULT 0,"
             "  type INT(11) UNSIGNED NOT NULL DEFAULT 0,"
             "  puttime BIGINT UNSIGNED NOT NULL DEFAULT 0,"
             "  expire BIGINT UNSIGNED NOT NULL DEFAULT 0,"
             "  hash BINARY(64) NOT NULL DEFAULT '',"
             "  vhash BINARY(64) NOT NULL DEFAULT '',"
             "  value BLOB NOT NULL DEFAULT '',"
             "  INDEX hashidx (hash(64),type,expire),"
             "  INDEX allidx (hash(64),vhash(64),type,size),"
             "  INDEX expireidx (puttime)" ") ENGINE=InnoDB") ||
      MRUNS ("SET AUTOCOMMIT = 1"))
    return GNUNET_SYSERR;
  return GNUNET_OK;
#undef MRUNS
}

static int
iopen ()
{
  if (db != NULL)
    return GNUNET_OK;
  db = GNUNET_MYSQL_database_open (coreAPI->ectx, coreAPI->cfg);
  if (db == NULL)
    return GNUNET_SYSERR;
#define PINIT(a,b) (NULL == (a = GNUNET_MYSQL_prepared_statement_create(db, b)))
  if (PINIT (select_value, SELECT_VALUE_STMT) ||
      PINIT (count_value, COUNT_VALUE_STMT) ||
      PINIT (select_old_value, SELECT_OLD_VALUE_STMT) ||
      PINIT (delete_value, DELETE_VALUE_STMT) ||
      PINIT (insert_value, INSERT_VALUE_STMT) ||
      PINIT (update_value, UPDATE_VALUE_STMT))
    {
      GNUNET_MYSQL_database_close (db);
      db = NULL;
      return GNUNET_SYSERR;
    }
#undef PINIT
  return itable ();
}

static int
return_ok (void *cls, unsigned int num_values, MYSQL_BIND * values)
{
  return GNUNET_OK;
}

/**
 * Check that we are within quota.
 * @return GNUNET_OK if we are, GNUNET_NO if not, GNUNET_SYSERR if
 *         there was an internal error
 */
static int
checkQuota ()
{
  MYSQL_BIND rbind[5];
  unsigned int v_size;
  unsigned int v_type;
  GNUNET_HashCode v_key;
  GNUNET_HashCode vhash;
  unsigned long k_length;
  unsigned long h_length;
  unsigned long v_length;
  int ret;

  if (payload * 10 <= quota * 9)
    return GNUNET_OK;           /* we seem to be about 10% off */
#if DEBUG_DSTORE
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                 "DStore above qutoa (have %llu, allowed %llu), will delete some data.\n",
                 payload, quota);
#endif
  k_length = sizeof (GNUNET_HashCode);
  h_length = sizeof (GNUNET_HashCode);
  v_length = GNUNET_MAX_BUFFER_SIZE;

  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_BLOB;
  rbind[0].buffer_length = sizeof (GNUNET_HashCode);
  rbind[0].length = &k_length;
  rbind[0].buffer = &v_key;
  rbind[1].buffer_type = MYSQL_TYPE_BLOB;
  rbind[1].buffer_length = sizeof (GNUNET_HashCode);
  rbind[1].length = &h_length;
  rbind[1].buffer = &vhash;
  rbind[2].buffer_type = MYSQL_TYPE_LONG;
  rbind[2].is_unsigned = 1;
  rbind[2].buffer = &v_type;
  rbind[3].buffer_type = MYSQL_TYPE_LONG;
  rbind[3].is_unsigned = 1;
  rbind[3].buffer = &v_size;
  rbind[4].buffer_type = MYSQL_TYPE_BLOB;
  rbind[4].buffer_length = GNUNET_MAX_BUFFER_SIZE;
  rbind[4].length = &v_length;
  rbind[4].buffer = GNUNET_malloc (GNUNET_MAX_BUFFER_SIZE);
  if ((GNUNET_OK !=
       (ret = GNUNET_MYSQL_prepared_statement_run_select (select_old_value,
                                                          5,
                                                          rbind,
                                                          return_ok,
                                                          NULL,
                                                          -1))) ||
      (GNUNET_OK !=
       (ret = GNUNET_MYSQL_prepared_statement_run (delete_value,
                                                   NULL,
                                                   MYSQL_TYPE_BLOB,
                                                   &v_key,
                                                   sizeof (GNUNET_HashCode),
                                                   &k_length,
                                                   MYSQL_TYPE_BLOB,
                                                   &vhash,
                                                   sizeof (GNUNET_HashCode),
                                                   &h_length,
                                                   MYSQL_TYPE_LONG,
                                                   &v_type,
                                                   GNUNET_YES,
                                                   MYSQL_TYPE_LONG,
                                                   &v_size,
                                                   GNUNET_YES,
                                                   MYSQL_TYPE_BLOB,
                                                   rbind[4].buffer,
                                                   (unsigned long)
                                                   GNUNET_MAX_BUFFER_SIZE,
                                                   &v_length, -1))))
    {
      GNUNET_free (rbind[4].buffer);
      if (ret == GNUNET_SYSERR)
        itable ();
      return GNUNET_SYSERR;
    }
  GNUNET_free (rbind[4].buffer);
  GNUNET_mutex_lock (lock);
  payload -= v_length + OVERHEAD;
  GNUNET_mutex_unlock (lock);
  if (bloom != NULL)
    GNUNET_bloomfilter_remove (bloom, &v_key);
  if (payload * 10 > quota * 9)
    return GNUNET_NO;
  return GNUNET_OK;
}

/**
 * Store an item in the datastore.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
d_put (const GNUNET_HashCode * key,
       unsigned int type,
       GNUNET_CronTime discard_time, unsigned int size, const char *data)
{
  GNUNET_CronTime now;
  unsigned long k_length;
  unsigned long h_length;
  unsigned long v_length;
  GNUNET_HashCode vhash;
  int ret;

  if (size > MAX_CONTENT_SIZE)
    return GNUNET_SYSERR;
  GNUNET_hash (data, size, &vhash);
  now = GNUNET_get_time ();

  /* first try UPDATE */
  h_length = sizeof (GNUNET_HashCode);
  k_length = sizeof (GNUNET_HashCode);
  v_length = size;
  if (GNUNET_OK ==
      GNUNET_MYSQL_prepared_statement_run (update_value,
                                           NULL,
                                           MYSQL_TYPE_LONGLONG,
                                           &now,
                                           GNUNET_YES,
                                           MYSQL_TYPE_LONGLONG,
                                           &discard_time,
                                           GNUNET_YES,
                                           MYSQL_TYPE_BLOB,
                                           key,
                                           sizeof (GNUNET_HashCode),
                                           &k_length,
                                           MYSQL_TYPE_BLOB,
                                           &vhash,
                                           sizeof (GNUNET_HashCode),
                                           &h_length,
                                           MYSQL_TYPE_LONG,
                                           &type,
                                           GNUNET_YES,
                                           MYSQL_TYPE_LONG,
                                           &size, GNUNET_YES, -1))
    return GNUNET_OK;

  /* now try INSERT */
  h_length = sizeof (GNUNET_HashCode);
  k_length = sizeof (GNUNET_HashCode);
  v_length = size;
  if (GNUNET_OK !=
      (ret = GNUNET_MYSQL_prepared_statement_run (insert_value,
                                                  NULL,
                                                  MYSQL_TYPE_LONG,
                                                  &size,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &type,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &now,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &discard_time,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_BLOB,
                                                  key,
                                                  sizeof (GNUNET_HashCode),
                                                  &k_length,
                                                  MYSQL_TYPE_BLOB,
                                                  &vhash,
                                                  sizeof (GNUNET_HashCode),
                                                  &h_length,
                                                  MYSQL_TYPE_BLOB,
                                                  data,
                                                  (unsigned long) size,
                                                  &v_length, -1)))
    {
      if (ret == GNUNET_SYSERR)
        itable ();
      return GNUNET_SYSERR;
    }
  if (bloom != NULL)
    GNUNET_bloomfilter_add (bloom, key);
  GNUNET_mutex_lock (lock);
  payload += size + OVERHEAD;
  GNUNET_mutex_unlock (lock);
  checkQuota ();
  if (stats != NULL)
    stats->set (stat_dstore_size, payload);
  return GNUNET_OK;
}

/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param key
 * @param type entries of which type are relevant?
 * @param iter maybe NULL (to just count)
 * @return the number of results, GNUNET_SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int
d_get (const GNUNET_HashCode * key,
       unsigned int type, GNUNET_ResultProcessor handler, void *closure)
{
  MYSQL_BIND rbind[2];
  unsigned int v_size;
  unsigned long h_length;
  unsigned long v_length;
  GNUNET_CronTime now;
  unsigned int cnt;
  unsigned long long total;
  unsigned int off;
  int ret;

  if ((bloom != NULL) && (GNUNET_NO == GNUNET_bloomfilter_test (bloom, key)))
    return 0;
  now = GNUNET_get_time ();
  h_length = sizeof (GNUNET_HashCode);
  v_length = GNUNET_MAX_BUFFER_SIZE;
  total = -1;
  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[0].buffer = &total;
  rbind[0].is_unsigned = GNUNET_YES;
  if ((GNUNET_OK !=
       (ret = GNUNET_MYSQL_prepared_statement_run_select (count_value,
                                                          1,
                                                          rbind,
                                                          return_ok,
                                                          NULL,
                                                          MYSQL_TYPE_BLOB,
                                                          key,
                                                          sizeof
                                                          (GNUNET_HashCode),
                                                          &h_length,
                                                          MYSQL_TYPE_LONG,
                                                          &type, GNUNET_YES,
                                                          MYSQL_TYPE_LONGLONG,
                                                          &now, GNUNET_YES,
                                                          -1)))
      || (-1 == total))
    {
      if (ret == GNUNET_SYSERR)
        itable ();
      return GNUNET_SYSERR;
    }
  if ((handler == NULL) || (total == 0))
    return (int) total;

  off = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, total);
  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_LONG;
  rbind[0].is_unsigned = 1;
  rbind[0].buffer = &v_size;
  rbind[1].buffer_type = MYSQL_TYPE_BLOB;
  rbind[1].buffer_length = GNUNET_MAX_BUFFER_SIZE;
  rbind[1].length = &v_length;
  rbind[1].buffer = GNUNET_malloc (GNUNET_MAX_BUFFER_SIZE);
  cnt = 0;
  while (cnt < total)
    {
      off = (off + 1) % total;
      if ((GNUNET_OK !=
           (ret = GNUNET_MYSQL_prepared_statement_run_select (select_value,
                                                              2,
                                                              rbind,
                                                              return_ok,
                                                              NULL,
                                                              MYSQL_TYPE_BLOB,
                                                              key,
                                                              sizeof
                                                              (GNUNET_HashCode),
                                                              &h_length,
                                                              MYSQL_TYPE_LONG,
                                                              &type,
                                                              GNUNET_YES,
                                                              MYSQL_TYPE_LONGLONG,
                                                              &now,
                                                              GNUNET_YES,
                                                              MYSQL_TYPE_LONG,
                                                              &off,
                                                              GNUNET_YES,
                                                              -1)))
          || (v_length != v_size))
        {
          GNUNET_GE_BREAK (NULL, v_length == v_size);
          GNUNET_free (rbind[1].buffer);
          if (ret == GNUNET_SYSERR)
            itable ();
          return GNUNET_SYSERR;
        }
      cnt++;
      if (GNUNET_OK != handler (key, type, v_size, rbind[1].buffer, closure))
        break;
    }
  GNUNET_free (rbind[1].buffer);
  return cnt;
}

GNUNET_Dstore_ServiceAPI *
provide_module_dstore_mysql (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_Dstore_ServiceAPI api;
  int fd;

  coreAPI = capi;
#if DEBUG_SQLITE
  GNUNET_GE_LOG (capi->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "MySQL Dstore: initializing database\n");
#endif

  if (iopen () != GNUNET_OK)
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_IMMEDIATE | GNUNET_GE_USER,
                     _
                     ("Failed to initialize MySQL database connection for dstore.\n"));
      return NULL;
    }
  lock = GNUNET_mutex_create (GNUNET_NO);
  api.get = &d_get;
  api.put = &d_put;
  GNUNET_GC_get_configuration_value_number (coreAPI->cfg,
                                            "DSTORE", "QUOTA", 1, 1024, 1,
                                            &quota);
  if (quota == 0)               /* error */
    quota = 1;
  quota *= 1024 * 1024;
  bloom_name = GNUNET_strdup ("/tmp/dbloomXXXXXX");
  fd = mkstemp (bloom_name);
  if (fd != -1)
    {
      bloom = GNUNET_bloomfilter_load (coreAPI->ectx, bloom_name, quota / (OVERHEAD + 1024),    /* 8 bit per entry in DB, expect 1k entries */
                                       5);
      CLOSE (fd);
    }
  stats = capi->service_request ("stats");
  if (stats != NULL)
    {
      stat_dstore_size = stats->create (gettext_noop ("# bytes in dstore"));
      stat_dstore_quota =
        stats->create (gettext_noop ("# max bytes allowed in dstore"));
      stats->set (stat_dstore_quota, quota);
    }
  return &api;
}

/**
 * Shutdown the module.
 */
void
release_module_dstore_mysql ()
{
  if (bloom != NULL)
    {
      GNUNET_bloomfilter_free (bloom);
      bloom = NULL;
    }
  UNLINK (bloom_name);
  GNUNET_free (bloom_name);
  bloom_name = NULL;
  if (stats != NULL)
    {
      coreAPI->service_release (stats);
      stats = NULL;
    }
#if DEBUG_SQLITE
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "MySQL Dstore: database shutdown\n");
#endif
  GNUNET_MYSQL_database_close (db);
  db = NULL;
  GNUNET_mutex_destroy (lock);
  coreAPI = NULL;
}

/* end of dstore_mysql.c */
