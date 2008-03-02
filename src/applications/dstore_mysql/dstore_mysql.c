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
#include <mysql/mysql.h>

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
 * Path to MySQL configuration file.
 */
static char *cnffile;

/**
 * Handle for the MySQL database.
 */
static MYSQL *dbf;


#define SELECT_VALUE_STMT "SELECT size, value FROM gn080dstore FORCE INDEX (hashidx) WHERE hash=? AND type=? AND expire >= ? LIMIT 1 OFFSET ?"
static MYSQL_STMT *select_value;

#define COUNT_VALUE_STMT "SELECT count(*) FROM gn080dstore FORCE INDEX (hashidx) WHERE hash=? AND type=? AND expire >= ?"
static MYSQL_STMT *count_value;

#define SELECT_OLD_VALUE_STMT "SELECT hash, vhash, type, size, value FROM gn080dstore FORCE INDEX (expireidx) ORDER BY puttime ASC LIMIT 1"
static MYSQL_STMT *select_old_value;

#define DELETE_VALUE_STMT "DELETE FROM gn080dstore WHERE hash = ? AND vhash = ? AND type = ? AND "\
                          "size = ? AND value = ?"
static MYSQL_STMT *delete_value;

#define INSERT_VALUE_STMT "INSERT INTO gn080dstore (size, type, puttime, expire, hash, vhash, value) "\
                          "VALUES (?, ?, ?, ?, ?, ?, ?)"
static MYSQL_STMT *insert_value;

#define UPDATE_VALUE_STMT "UPDATE gn080dstore FORCE INDEX (allidx) SET puttime=?, expire=? "\
                          "WHERE hash=? AND vhash=? AND type=? AND size=?"
static MYSQL_STMT *update_value;

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define DIE_MYSQL(cmd, dbh) do { GNUNET_GE_LOG(coreAPI->ectx, GNUNET_GE_FATAL | GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, mysql_error((dbh)); abort(); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_MYSQL(level, cmd, dbh) do { GNUNET_GE_LOG(coreAPI->ectx, level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, mysql_error((dbh))); } while(0);


/**
 * Close the database connection.
 */
static int
iclose ()
{
#define PEND(h) if (h != NULL) { mysql_stmt_close(h); h = NULL; } else {}
  if (dbf == NULL)
    return GNUNET_SYSERR;
  PEND (select_value);
  PEND (count_value);
  PEND (select_old_value);
  PEND (delete_value);
  PEND (insert_value);
  PEND (update_value);
#undef PEND
  mysql_close (dbf);
  payload = 0;
  dbf = NULL;
  return GNUNET_OK;
}

/**
 * Initiate the database connection.
 *
 * @return GNUNET_OK on success
 */
static int
iopen ()
{
  char *dbname;
  my_bool reconnect = 0;
  unsigned int timeout = 60;    /* in seconds */

  if (dbf != NULL)
    return GNUNET_OK;
  if (cnffile == NULL)
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  dbf = mysql_init (NULL);
  if (dbf == NULL)
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  mysql_options (dbf, MYSQL_READ_DEFAULT_FILE, cnffile);
  mysql_options (dbf, MYSQL_READ_DEFAULT_GROUP, "client");
  mysql_options (dbf, MYSQL_OPT_RECONNECT, &reconnect);
  mysql_options (dbf, MYSQL_OPT_CONNECT_TIMEOUT, (const void *) &timeout);
  mysql_options (dbf, MYSQL_OPT_READ_TIMEOUT, (const void *) &timeout);
  mysql_options (dbf, MYSQL_OPT_WRITE_TIMEOUT, (const void *) &timeout);

  dbname = NULL;
  GNUNET_GC_get_configuration_value_string (coreAPI->cfg,
                                            "MYSQL", "DATABASE", "gnunet",
                                            &dbname);
  mysql_real_connect (dbf, NULL, NULL, NULL, dbname, 0, NULL, 0);
  GNUNET_free (dbname);
  if (mysql_error (dbf)[0])
    {
      LOG_MYSQL (GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                 "mysql_real_connect", dbf);
      iclose ();
      return GNUNET_SYSERR;
    }
  mysql_query (dbf,
               "SET SESSION net_read_timeout=60, SESSION net_write_timeout=60");
  if (mysql_error (dbf)[0])
    {
      LOG_MYSQL (GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                 "mysql_query", dbf);
      iclose ();
      return GNUNET_SYSERR;
    }

  mysql_query (dbf, "DROP TABLE gn080dstore");
  mysql_query (dbf,
               "CREATE TEMPORARY TABLE gn080dstore ("
               "  size INT(11) UNSIGNED NOT NULL DEFAULT 0,"
               "  type INT(11) UNSIGNED NOT NULL DEFAULT 0,"
               "  puttime BIGINT UNSIGNED NOT NULL DEFAULT 0,"
               "  expire BIGINT UNSIGNED NOT NULL DEFAULT 0,"
               "  hash BINARY(64) NOT NULL DEFAULT '',"
               "  vhash BINARY(64) NOT NULL DEFAULT '',"
               "  value BLOB NOT NULL DEFAULT '',"
               "  INDEX hashidx (hash(64),type,expire),"
               "  INDEX allidx (hash(64),vhash(64),type,size),"
               "  INDEX expireidx (puttime)" ") ENGINE=InnoDB");
  if (mysql_error (dbf)[0])
    {
      LOG_MYSQL (GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                 "mysql_query", dbf);
      iclose ();
      return GNUNET_SYSERR;
    }
  mysql_query (dbf, "SET AUTOCOMMIT = 1");
  if (mysql_error (dbf)[0])
    {
      LOG_MYSQL (GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                 "mysql_query", dbf);
      iclose ();
      return GNUNET_SYSERR;
    }
#define PINIT(a,b) a = mysql_stmt_init(dbf); if (a == NULL) { iclose(); return GNUNET_SYSERR; } else { \
    if (mysql_stmt_prepare (a, b, strlen(b))) { \
      GNUNET_GE_LOG (coreAPI->ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER, \
	      _("`%s' failed at %s:%d with error: %s"), "mysql_stmt_prepare", __FILE__, __LINE__, \
	      mysql_stmt_error (a));  iclose(); return GNUNET_SYSERR; } }
  PINIT (select_value, SELECT_VALUE_STMT);
  PINIT (count_value, COUNT_VALUE_STMT);
  PINIT (select_old_value, SELECT_OLD_VALUE_STMT);
  PINIT (delete_value, DELETE_VALUE_STMT);
  PINIT (insert_value, INSERT_VALUE_STMT);
  PINIT (update_value, UPDATE_VALUE_STMT);
#undef PINIT
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

  GNUNET_mutex_lock (lock);
  mysql_thread_init ();
  if (mysql_stmt_execute (select_old_value))
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "mysql_stmt_execute",
                     __FILE__, __LINE__, mysql_stmt_error (select_old_value));
      GNUNET_free (rbind[4].buffer);
      iclose ();
      mysql_thread_end ();
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  GNUNET_GE_ASSERT (coreAPI->ectx,
                    mysql_stmt_field_count (select_old_value) == 5);
  if (mysql_stmt_bind_result (select_old_value, rbind))
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "mysql_stmt_bind_result",
                     __FILE__, __LINE__, mysql_stmt_error (select_old_value));
      GNUNET_free (rbind[4].buffer);
      iclose ();
      mysql_thread_end ();
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  if (0 != mysql_stmt_fetch (select_old_value))
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "mysql_stmt_fetch",
                     __FILE__, __LINE__, mysql_stmt_error (select_old_value));
      GNUNET_free (rbind[4].buffer);
      mysql_stmt_reset (select_old_value);
      mysql_thread_end ();
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  mysql_stmt_reset (select_old_value);
  if (mysql_stmt_bind_param (delete_value, rbind))
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "mysql_stmt_bind_param",
                     __FILE__, __LINE__, mysql_stmt_error (delete_value));
      GNUNET_free (rbind[4].buffer);
      iclose ();
      mysql_thread_end ();
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  GNUNET_GE_BREAK (NULL, h_length == sizeof (GNUNET_HashCode));

  if (mysql_stmt_execute (delete_value))
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "mysql_stmt_execute",
                     __FILE__, __LINE__, mysql_stmt_error (delete_value));
      GNUNET_free (rbind[4].buffer);
      iclose ();
      mysql_thread_end ();
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  GNUNET_free (rbind[4].buffer);
  payload -= v_length + OVERHEAD;
  mysql_stmt_reset (delete_value);
  mysql_thread_end ();
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
  MYSQL_BIND rbind[7];
  GNUNET_CronTime now;
  unsigned long k_length;
  unsigned long h_length;
  unsigned long v_length;
  GNUNET_HashCode vhash;

  if (size > MAX_CONTENT_SIZE)
    return GNUNET_SYSERR;
  GNUNET_hash (data, size, &vhash);
  GNUNET_mutex_lock (lock);
  mysql_thread_init ();
  iopen ();
  now = GNUNET_get_time ();

  /* first try UPDATE */
  h_length = sizeof (GNUNET_HashCode);
  k_length = sizeof (GNUNET_HashCode);
  v_length = size;
  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[0].is_unsigned = 1;
  rbind[0].buffer = &now;
  rbind[1].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[1].is_unsigned = 1;
  rbind[1].buffer = &discard_time;
  rbind[2].buffer_type = MYSQL_TYPE_BLOB;
  rbind[2].buffer_length = sizeof (GNUNET_HashCode);
  rbind[2].length = &k_length;
  rbind[2].buffer = (void *) key;
  rbind[3].buffer_type = MYSQL_TYPE_BLOB;
  rbind[3].buffer_length = sizeof (GNUNET_HashCode);
  rbind[3].length = &h_length;
  rbind[3].buffer = &vhash;
  rbind[4].buffer_type = MYSQL_TYPE_LONG;
  rbind[4].is_unsigned = 1;
  rbind[4].buffer = &type;
  rbind[5].buffer_type = MYSQL_TYPE_LONG;
  rbind[5].is_unsigned = 1;
  rbind[5].buffer = &size;

  if (mysql_stmt_bind_param (update_value, rbind))
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "mysql_stmt_bind_param",
                     __FILE__, __LINE__, mysql_stmt_error (update_value));
      iclose ();
      mysql_thread_end ();
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  if (mysql_stmt_execute (update_value))
    {
      mysql_stmt_reset (update_value);
      mysql_thread_end ();
      GNUNET_mutex_unlock (lock);
      return GNUNET_OK;
    }
  mysql_stmt_reset (update_value);
  /* now try INSERT */

  h_length = sizeof (GNUNET_HashCode);
  k_length = sizeof (GNUNET_HashCode);
  v_length = size;
  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_LONG;
  rbind[0].is_unsigned = 1;
  rbind[0].buffer = &size;
  rbind[1].buffer_type = MYSQL_TYPE_LONG;
  rbind[1].is_unsigned = 1;
  rbind[1].buffer = &type;
  rbind[2].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[2].is_unsigned = 1;
  rbind[2].buffer = &now;
  rbind[3].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[3].is_unsigned = 1;
  rbind[3].buffer = &discard_time;
  rbind[4].buffer_type = MYSQL_TYPE_BLOB;
  rbind[4].buffer_length = sizeof (GNUNET_HashCode);
  rbind[4].length = &k_length;
  rbind[4].buffer = (void *) key;
  rbind[5].buffer_type = MYSQL_TYPE_BLOB;
  rbind[5].buffer_length = sizeof (GNUNET_HashCode);
  rbind[5].length = &h_length;
  rbind[5].buffer = &vhash;
  rbind[6].buffer_type = MYSQL_TYPE_BLOB;
  rbind[6].buffer_length = size;
  rbind[6].length = &v_length;
  rbind[6].buffer = (void *) data;

  if (mysql_stmt_bind_param (insert_value, rbind))
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "mysql_stmt_bind_param",
                     __FILE__, __LINE__, mysql_stmt_error (insert_value));
      iclose ();
      mysql_thread_end ();
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  if (mysql_stmt_execute (insert_value))
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "mysql_stmt_execute",
                     __FILE__, __LINE__, mysql_stmt_error (insert_value));
      iclose ();
      mysql_thread_end ();
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  mysql_stmt_reset (insert_value);
  mysql_thread_end ();
  if (bloom != NULL)
    GNUNET_bloomfilter_add (bloom, key);
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
  MYSQL_BIND qbind[4];
  MYSQL_BIND rbind[2];
  unsigned int v_size;
  unsigned long h_length;
  unsigned long v_length;
  GNUNET_CronTime now;
  unsigned int cnt;
  unsigned long long total;
  unsigned int off;

  GNUNET_mutex_lock (lock);
  if ((bloom != NULL) && (GNUNET_NO == GNUNET_bloomfilter_test (bloom, key)))
    {
      GNUNET_mutex_unlock (lock);
      return 0;
    }
#if DEBUG_DSTORE
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                 "dstore processes get\n");
#endif
  now = GNUNET_get_time ();

  h_length = sizeof (GNUNET_HashCode);
  v_length = GNUNET_MAX_BUFFER_SIZE;
  memset (qbind, 0, sizeof (qbind));
  qbind[0].buffer_type = MYSQL_TYPE_BLOB;
  qbind[0].buffer_length = sizeof (GNUNET_HashCode);
  qbind[0].length = &h_length;
  qbind[0].buffer = (void *) key;
  qbind[1].buffer_type = MYSQL_TYPE_LONG;
  qbind[1].is_unsigned = 1;
  qbind[1].buffer = &type;
  qbind[2].buffer_type = MYSQL_TYPE_LONGLONG;
  qbind[2].is_unsigned = 1;
  qbind[2].buffer = &now;

  total = -1;
  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[0].buffer = &total;
  rbind[0].is_unsigned = GNUNET_YES;

  mysql_thread_init ();
  iopen ();

  if (mysql_stmt_bind_param (count_value, qbind))
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "mysql_stmt_bind_param",
                     __FILE__, __LINE__, mysql_stmt_error (count_value));
      iclose ();
      mysql_thread_end ();
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  if (mysql_stmt_execute (count_value))
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "mysql_stmt_execute",
                     __FILE__, __LINE__, mysql_stmt_error (count_value));
      iclose ();
      GNUNET_mutex_unlock (lock);
      mysql_thread_end ();
      return GNUNET_SYSERR;
    }


  if (mysql_stmt_bind_result (count_value, rbind))
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "mysql_stmt_bind_result",
                     __FILE__, __LINE__, mysql_stmt_error (count_value));
      iclose ();
      mysql_thread_end ();
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  if (0 != mysql_stmt_fetch (count_value))
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "mysql_stmt_fetch",
                     __FILE__, __LINE__, mysql_stmt_error (count_value));
      mysql_stmt_reset (count_value);
      iclose ();
      GNUNET_mutex_unlock (lock);
      mysql_thread_end ();
      return GNUNET_SYSERR;
    }
  if (-1 == total)
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "mysql_stmt_fetch",
                     __FILE__, __LINE__, mysql_stmt_error (count_value));
      iclose ();
      GNUNET_mutex_unlock (lock);
      mysql_thread_end ();
      return GNUNET_SYSERR;
    }
  mysql_stmt_reset (count_value);
  if ((handler == NULL) || (total == 0))
    {
      GNUNET_mutex_unlock (lock);
      mysql_thread_end ();
      return (int) total;
    }

  off = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, total);
  qbind[3].buffer_type = MYSQL_TYPE_LONG;
  qbind[3].is_unsigned = 1;
  qbind[3].buffer = &off;

  cnt = 0;
  while (cnt < total)
    {
      off = (off + 1) % total;
      if (mysql_stmt_bind_param (select_value, qbind))
        {
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("`%s' failed at %s:%d with error: %s\n"),
                         "mysql_stmt_bind_param",
                         __FILE__, __LINE__, mysql_stmt_error (select_value));
          iclose ();
          mysql_thread_end ();
          GNUNET_mutex_unlock (lock);
          return GNUNET_SYSERR;
        }
      if (mysql_stmt_execute (select_value))
        {
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("`%s' failed at %s:%d with error: %s\n"),
                         "mysql_stmt_execute",
                         __FILE__, __LINE__, mysql_stmt_error (select_value));
          iclose ();
          GNUNET_mutex_unlock (lock);
          mysql_thread_end ();
          return GNUNET_SYSERR;
        }
      memset (rbind, 0, sizeof (rbind));
      rbind[0].buffer_type = MYSQL_TYPE_LONG;
      rbind[0].is_unsigned = 1;
      rbind[0].buffer = &v_size;
      rbind[1].buffer_type = MYSQL_TYPE_BLOB;
      rbind[1].buffer_length = GNUNET_MAX_BUFFER_SIZE;
      rbind[1].length = &v_length;
      rbind[1].buffer = GNUNET_malloc (GNUNET_MAX_BUFFER_SIZE);
      if (mysql_stmt_bind_result (select_value, rbind))
        {
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("`%s' failed at %s:%d with error: %s\n"),
                         "mysql_stmt_bind_result",
                         __FILE__, __LINE__, mysql_stmt_error (select_value));
          iclose ();
          mysql_thread_end ();
          GNUNET_mutex_unlock (lock);
          GNUNET_free (rbind[1].buffer);
          return GNUNET_SYSERR;
        }
      if (0 != mysql_stmt_fetch (select_value))
        {
          GNUNET_GE_BREAK (NULL, 0);
          break;
        }
      if (v_length != v_size)
        {
          GNUNET_GE_BREAK (NULL, 0);
          iclose ();
          mysql_thread_end ();
          GNUNET_mutex_unlock (lock);
          GNUNET_free (rbind[1].buffer);
          return cnt;
        }
      cnt++;
      if (GNUNET_OK != handler (key, type, v_size, rbind[1].buffer, closure))
        break;
    }
  mysql_stmt_reset (select_value);
  mysql_thread_end ();
  GNUNET_mutex_unlock (lock);
  GNUNET_free (rbind[1].buffer);
  return cnt;
}

GNUNET_Dstore_ServiceAPI *
provide_module_dstore_mysql (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_Dstore_ServiceAPI api;
  int fd;
#ifndef WINDOWS
  struct passwd *pw;
#endif
  size_t nX;
  char *home_dir;

  coreAPI = capi;
#if DEBUG_SQLITE
  GNUNET_GE_LOG (capi->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "MySQL Dstore: initializing database\n");
#endif

  /* verify that .my.cnf can be found */
#ifndef WINDOWS
  pw = getpwuid (getuid ());
  if (!pw)
    GNUNET_GE_DIE_STRERROR (coreAPI->ectx,
                            GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                            GNUNET_GE_IMMEDIATE, "getpwuid");
  home_dir = GNUNET_strdup (pw->pw_dir);
#else
  home_dir = (char *) GNUNET_malloc (_MAX_PATH + 1);
  plibc_conv_to_win_path ("~/", home_dir);
#endif
  nX = strlen (home_dir) + 10;
  cnffile = GNUNET_malloc (nX);
  GNUNET_snprintf (cnffile, nX, "%s/.my.cnf", home_dir);
  GNUNET_free (home_dir);
  GNUNET_GC_get_configuration_value_filename (capi->cfg,
                                              "MYSQL", "CONFIG", cnffile,
                                              &home_dir);
  GNUNET_free (cnffile);
  cnffile = home_dir;
  GNUNET_GE_ASSERT (NULL, cnffile != NULL);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _("Trying to use file `%s' for MySQL configuration.\n"),
                 cnffile);


  if (iopen () != GNUNET_OK)
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_IMMEDIATE | GNUNET_GE_USER,
                     _
                     ("Failed to initialize MySQL database connection for dstore.\n"),
                     cnffile);
      GNUNET_free (cnffile);
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
  stats = capi->request_service ("stats");
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
      coreAPI->release_service (stats);
      stats = NULL;
    }
#if DEBUG_SQLITE
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "MySQL Dstore: database shutdown\n");
#endif
  GNUNET_mutex_destroy (lock);
  coreAPI = NULL;
  GNUNET_free (cnffile);
  cnffile = NULL;
}

/* end of dstore_mysql.c */
