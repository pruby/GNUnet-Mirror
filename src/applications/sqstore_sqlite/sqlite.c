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
 * @file applications/sqstore_sqlite/sqlite.c
 * @brief SQLite based implementation of the sqstore service
 * @author Nils Durner
 * @author Christian Grothoff
 *
 * Database: SQLite
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_util.h"
#include "gnunet_sqstore_service.h"
#include "gnunet_protocols.h"
#include "gnunet_stats_service.h"
#include <sqlite3.h>

#define DEBUG_SQLITE GNUNET_NO

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define DIE_SQLITE(db, cmd) do { GNUNET_GE_LOG(ectx, GNUNET_GE_FATAL | GNUNET_GE_IMMEDIATE | GNUNET_GE_ADMIN, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db->dbh)); abort(); } while(0)

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_SQLITE(db, level, cmd) do { GNUNET_GE_LOG(ectx, level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db->dbh)); } while(0)

#define SELECT_IT_LOW_PRIORITY_1 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (prio = ? AND hash > ?) "\
  "ORDER BY hash ASC LIMIT 1"

#define SELECT_IT_LOW_PRIORITY_2 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (prio > ?) "\
  "ORDER BY prio ASC, hash ASC LIMIT 1"

#define SELECT_IT_NON_ANONYMOUS_1 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (prio = ? AND hash < ? AND anonLevel = 0) "\
  " ORDER BY hash DESC LIMIT 1"

#define SELECT_IT_NON_ANONYMOUS_2 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (prio < ? AND anonLevel = 0)"\
  " ORDER BY prio DESC, hash DESC LIMIT 1"

#define SELECT_IT_EXPIRATION_TIME_1 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (expire = ? AND hash > ?) "\
  " ORDER BY hash ASC LIMIT 1"

#define SELECT_IT_EXPIRATION_TIME_2 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (expire > ?) "\
  " ORDER BY expire ASC, hash ASC LIMIT 1"

#define SELECT_IT_MIGRATION_ORDER_1 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (expire = ? AND hash < ?) "\
  " ORDER BY hash DESC LIMIT 1"

#define SELECT_IT_MIGRATION_ORDER_2 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (expire < ?) "\
  " ORDER BY expire DESC, hash DESC LIMIT 1"

/**
 * After how many ms "busy" should a DB operation fail for good?
 * A low value makes sure that we are more responsive to requests
 * (especially PUTs).  A high value guarantees a higher success
 * rate (SELECTs in iterate can take several seconds despite LIMIT=1).
 *
 * The default value of 250ms should ensure that users do not experience
 * huge latencies while at the same time allowing operations to succeed
 * with reasonable probability.
 */
#define BUSY_TIMEOUT_MS 250

/**
 * @brief Wrapper for SQLite
 */
typedef struct
{

  /**
   * Native SQLite database handle - may not be shared between threads!
   */
  sqlite3 *dbh;

  /**
   * Thread ID owning this handle
   */
  struct GNUNET_ThreadHandle *tid;

  /**
   * Precompiled SQL
   */
  sqlite3_stmt *updPrio;

  sqlite3_stmt *insertContent;
} sqliteHandle;

static GNUNET_Stats_ServiceAPI *stats;

static GNUNET_CoreAPIForPlugins *coreAPI;

static unsigned int stat_size;

#if DEBUG_SQLITE
static unsigned int stat_mem;
#endif

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_Mutex *lock;

static char *fn;

static unsigned long long payload;

static unsigned int lastSync;

static unsigned int handle_count;

static sqliteHandle **handles;

/**
 * @brief Prepare a SQL statement
 */
static int
sq_prepare (sqlite3 * dbh, const char *zSql,    /* SQL statement, UTF-8 encoded */
            sqlite3_stmt ** ppStmt)
{                               /* OUT: Statement handle */
  char *dummy;
  return sqlite3_prepare (dbh,
                          zSql,
                          strlen (zSql), ppStmt, (const char **) &dummy);
}

#if 1
#define CHECK(a) GNUNET_GE_BREAK(ectx, a)
#define ENULL NULL
#else
#define ENULL &e
#define ENULL_DEFINED 1
#define CHECK(a) if (! a) { fprintf(stderr, "%s\n", e); sqlite3_free(e); }
#endif

static void
createIndices (sqlite3 * dbh)
{
  /* create indices */
  sqlite3_exec (dbh,
                "CREATE INDEX idx_hash ON gn080 (hash)", NULL, NULL, ENULL);
  sqlite3_exec (dbh,
                "CREATE INDEX idx_hash_vhash ON gn080 (hash,vhash)", NULL,
                NULL, ENULL);
  sqlite3_exec (dbh, "CREATE INDEX idx_prio ON gn080 (prio)", NULL, NULL,
                ENULL);
  sqlite3_exec (dbh, "CREATE INDEX idx_expire ON gn080 (expire)", NULL, NULL,
                ENULL);
  sqlite3_exec (dbh, "CREATE INDEX idx_comb3 ON gn080 (prio,anonLevel)", NULL,
                NULL, ENULL);
  sqlite3_exec (dbh, "CREATE INDEX idx_comb4 ON gn080 (prio,hash,anonLevel)",
                NULL, NULL, ENULL);
  sqlite3_exec (dbh, "CREATE INDEX idx_comb7 ON gn080 (expire,hash)", NULL,
                NULL, ENULL);
}

/**
 * @brief Get a database handle for this thread.
 * @note SQLite handles may no be shared between threads - see
 *        http://permalink.gmane.org/gmane.network.gnunet.devel/1377
 *       We therefore (re)open the database in each thread.
 * @return the native SQLite database handle
 */
static sqliteHandle *
getDBHandle ()
{
  unsigned int idx;
  sqliteHandle *ret;
  sqlite3_stmt *stmt;
#if ENULL_DEFINED
  char *e;
#endif

  /* Is the DB already open? */
  for (idx = 0; idx < handle_count; idx++)
    if (GNUNET_thread_test_self (handles[idx]->tid))
      return handles[idx];

  /* we haven't opened the DB for this thread yet */
  ret = GNUNET_malloc (sizeof (sqliteHandle));
  /* Open database and precompile statements */
  if (sqlite3_open (fn, &ret->dbh) != SQLITE_OK)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Unable to initialize SQLite: %s.\n"),
                     sqlite3_errmsg (ret->dbh));
      sqlite3_close (ret->dbh);
      GNUNET_free (ret);
      return NULL;
    }

  CHECK (SQLITE_OK ==
         sqlite3_exec (ret->dbh,
                       "PRAGMA temp_store=MEMORY", NULL, NULL, ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (ret->dbh,
                       "PRAGMA synchronous=OFF", NULL, NULL, ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (ret->dbh,
                       "PRAGMA count_changes=OFF", NULL, NULL, ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (ret->dbh, "PRAGMA page_size=4092", NULL, NULL, ENULL));

  CHECK (SQLITE_OK == sqlite3_busy_timeout (ret->dbh, BUSY_TIMEOUT_MS));


  /* We have to do it here, because otherwise precompiling SQL might fail */
  CHECK (SQLITE_OK ==
         sq_prepare (ret->dbh,
                     "SELECT 1 FROM sqlite_master WHERE tbl_name = 'gn080'",
                     &stmt));
  if (sqlite3_step (stmt) == SQLITE_DONE)
    {
      if (sqlite3_exec (ret->dbh,
                        "CREATE TABLE gn080 ("
                        "  size INTEGER NOT NULL DEFAULT 0,"
                        "  type INTEGER NOT NULL DEFAULT 0,"
                        "  prio INTEGER NOT NULL DEFAULT 0,"
                        "  anonLevel INTEGER NOT NULL DEFAULT 0,"
                        "  expire INTEGER NOT NULL DEFAULT 0,"
                        "  hash TEXT NOT NULL DEFAULT '',"
                        "  vhash TEXT NOT NULL DEFAULT '',"
                        "  value BLOB NOT NULL DEFAULT '')", NULL, NULL,
                        NULL) != SQLITE_OK)
        {
          LOG_SQLITE (ret,
                      GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                      GNUNET_GE_BULK, "sqlite_create");
          sqlite3_finalize (stmt);
          GNUNET_free (ret);
          return NULL;
        }
    }
  sqlite3_finalize (stmt);
  createIndices (ret->dbh);

  CHECK (SQLITE_OK ==
         sq_prepare (ret->dbh,
                     "SELECT 1 FROM sqlite_master WHERE tbl_name = 'gn071'",
                     &stmt));
  if (sqlite3_step (stmt) == SQLITE_DONE)
    {
      if (sqlite3_exec (ret->dbh,
                        "CREATE TABLE gn071 ("
                        "  key TEXT NOT NULL DEFAULT '',"
                        "  value INTEGER NOT NULL DEFAULT 0)", NULL, NULL,
                        NULL) != SQLITE_OK)
        {
          LOG_SQLITE (ret,
                      GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                      GNUNET_GE_BULK, "sqlite_create");
          sqlite3_finalize (stmt);
          GNUNET_free (ret);
          return NULL;
        }
    }
  sqlite3_finalize (stmt);

  if ((sq_prepare (ret->dbh,
                   "UPDATE gn080 SET prio = prio + ?, expire = MAX(expire,?) WHERE "
                   "_ROWID_ = ?",
                   &ret->updPrio) != SQLITE_OK) ||
      (sq_prepare (ret->dbh,
                   "INSERT INTO gn080 (size, type, prio, "
                   "anonLevel, expire, hash, vhash, value) VALUES "
                   "(?, ?, ?, ?, ?, ?, ?, ?)",
                   &ret->insertContent) != SQLITE_OK))
    {
      LOG_SQLITE (ret,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "precompiling");
      if (ret->updPrio != NULL)
        sqlite3_finalize (ret->updPrio);
      if (ret->insertContent != NULL)
        sqlite3_finalize (ret->insertContent);
      GNUNET_free (ret);
      return NULL;
    }
  ret->tid = GNUNET_thread_get_self ();
  GNUNET_array_append (handles, handle_count, ret);
  return ret;
}

/**
 * @brief Returns the storage needed for the specfied int
 */
static unsigned int
getIntSize (unsigned long long l)
{
  if ((l & 0x7FFFFFFFFFFFLL) == l)
    if ((l & 0x7FFFFFFF) == l)
      if ((l & 0x7FFFFF) == l)
        if ((l & 0x7FFF) == l)
          if ((l & 0x7F) == l)
            return 1;
          else
            return 2;
        else
          return 3;
      else
        return 4;
    else
      return 6;
  else
    return 8;
}

/**
 * Get a (good) estimate of the size of the given
 * value (and its key) in the datastore.<p>
 * <pre>
 * row length = GNUNET_hash length + block length + numbers + column count + estimated index size + 1
 * </pre>
 */
static unsigned int
getContentDatastoreSize (const GNUNET_DatastoreValue * value)
{
  return sizeof (GNUNET_HashCode) * 2 + ntohl (value->size) -
    sizeof (GNUNET_DatastoreValue) + getIntSize (ntohl (value->size)) +
    getIntSize (ntohl (value->type)) + getIntSize (ntohl (value->priority)) +
    getIntSize (ntohl (value->anonymity_level)) +
    getIntSize (GNUNET_ntohll (value->expiration_time)) + 7 + 245 + 1;
}



/**
 * Get the current on-disk size of the SQ store.  Estimates are fine,
 * if that's the only thing available.
 *
 * @return number of bytes used on disk
 */
static unsigned long long
getSize ()
{
  double ret;

  GNUNET_mutex_lock (lock);
  ret = payload;
  if (stats)
    {
      stats->set (stat_size, ret);
#if DEBUG_SQLITE
      stats->set (stat_mem, sqlite3_memory_used ());
#endif
    }
  GNUNET_mutex_unlock (lock);
  return (unsigned long long) (ret * 1.13);
  /* benchmarking shows 13% overhead */
}

static int
delete_by_rowid (sqliteHandle * handle, unsigned long long rid)
{
  sqlite3_stmt *stmt;

  if (sq_prepare (handle->dbh,
                  "DELETE FROM gn080 WHERE _ROWID_ = ?", &stmt) != SQLITE_OK)
    {
      LOG_SQLITE (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "sq_prepare");
      return GNUNET_SYSERR;
    }
  sqlite3_bind_int64 (stmt, 1, rid);
  if (SQLITE_DONE != sqlite3_step (stmt))
    {
      LOG_SQLITE (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "sqlite3_step");
      sqlite3_finalize (stmt);
      return GNUNET_SYSERR;
    }
  sqlite3_finalize (stmt);
  return GNUNET_OK;
}

/**
 * Given a full row from gn080 table (size,type,priority,anonLevel,expire,GNUNET_hash,value),
 * assemble it into a GNUNET_DatastoreValue representation.
 */
static GNUNET_DatastoreValue *
assembleDatum (sqliteHandle * handle, sqlite3_stmt * stmt,
               GNUNET_HashCode * key, unsigned long long *rowid)
{
  GNUNET_DatastoreValue *value;
  int contentSize;
  sqlite3 *dbh;
  unsigned int type;
  sqlite3_stmt *stmtd;

  *rowid = sqlite3_column_int64 (stmt, 7);
  type = sqlite3_column_int (stmt, 1);
  contentSize = sqlite3_column_int (stmt, 0) - sizeof (GNUNET_DatastoreValue);
  dbh = handle->dbh;
  if (contentSize < 0)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("Invalid data in %s.  Trying to fix (by deletion).\n"),
                     _("sqlite datastore"));
      if (SQLITE_OK != sqlite3_reset (stmt))
        LOG_SQLITE (handle,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "sqlite3_reset");
      if (sq_prepare (dbh, "DELETE FROM gn080 WHERE size < ?", &stmtd) !=
          SQLITE_OK)
        {
          LOG_SQLITE (handle,
                      GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                      GNUNET_GE_BULK, "sq_prepare");
          return NULL;
        }
      if (SQLITE_OK !=
          sqlite3_bind_int (stmtd, 1, sizeof (GNUNET_DatastoreValue)))
        LOG_SQLITE (handle,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "sqlite3_bind_int");
      if (SQLITE_DONE != sqlite3_step (stmtd))
        LOG_SQLITE (handle,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "sqlite3_step");
      if (SQLITE_OK != sqlite3_finalize (stmtd))
        LOG_SQLITE (handle,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "sqlite3_finalize");
      return NULL;              /* error */
    }

  if (sqlite3_column_bytes (stmt, 5) != sizeof (GNUNET_HashCode) ||
      sqlite3_column_bytes (stmt, 6) != contentSize)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Invalid data in %s.  Trying to fix (by deletion).\n"),
                     _("sqlite datastore"));
      if (SQLITE_OK != sqlite3_reset (stmt))
        LOG_SQLITE (handle,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "sqlite3_reset");
      if (sq_prepare
          (dbh,
           "DELETE FROM gn080 WHERE NOT ((LENGTH(hash) = ?) AND (size = LENGTH(value) + ?))",
           &stmtd) != SQLITE_OK)
        {
          LOG_SQLITE (handle,
                      GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                      GNUNET_GE_BULK, "sq_prepare");
          return NULL;
        }

      if (SQLITE_OK != sqlite3_bind_int (stmtd, 1, sizeof (GNUNET_HashCode)))
        LOG_SQLITE (handle,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "sqlite3_bind_int");
      if (SQLITE_OK !=
          sqlite3_bind_int (stmtd, 2, sizeof (GNUNET_DatastoreValue)))
        LOG_SQLITE (handle,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "sqlite3_bind_int");
      if (SQLITE_DONE != sqlite3_step (stmtd))
        LOG_SQLITE (handle,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "sqlite3_step");
      if (SQLITE_OK != sqlite3_finalize (stmtd))
        LOG_SQLITE (handle,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "sqlite3_finalize");
      return NULL;
    }

  value = GNUNET_malloc (sizeof (GNUNET_DatastoreValue) + contentSize);
  value->size = htonl (contentSize + sizeof (GNUNET_DatastoreValue));
  value->type = htonl (type);
  value->priority = htonl (sqlite3_column_int (stmt, 2));
  value->anonymity_level = htonl (sqlite3_column_int (stmt, 3));
  value->expiration_time = GNUNET_htonll (sqlite3_column_int64 (stmt, 4));
  memcpy (key, sqlite3_column_blob (stmt, 5), sizeof (GNUNET_HashCode));
  memcpy (&value[1], sqlite3_column_blob (stmt, 6), contentSize);
  return value;
}


/**
 * @brief Get database statistics
 * @param key kind of stat to retrieve
 * @return GNUNET_SYSERR on error, the value otherwise
 */
static unsigned long long
getStat (sqliteHandle * handle, const char *key)
{
  int i;
  sqlite3_stmt *stmt;
  unsigned long long ret = GNUNET_SYSERR;

  i = sq_prepare (handle->dbh,
                  "SELECT value FROM gn071 WHERE key = ?", &stmt);
  if (i == SQLITE_OK)
    {
      sqlite3_bind_text (stmt, 1, key, strlen (key), SQLITE_STATIC);
      i = sqlite3_step (stmt);

      if (i == SQLITE_DONE)
        {
          ret = 0;
          i = SQLITE_OK;
        }
      else if (i == SQLITE_ROW)
        {
          ret = sqlite3_column_int64 (stmt, 0);
          i = SQLITE_OK;
        }
      sqlite3_finalize (stmt);
    }
  if (i == SQLITE_BUSY)
    return GNUNET_SYSERR;
  if (i != SQLITE_OK)
    {
      LOG_SQLITE (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "sqlite_getStat");
      return GNUNET_SYSERR;
    }
  return ret;
}

/**
 * @brief set database statistics
 * @param key statistic to set
 * @param val value to set
 * @return GNUNET_SYSERR on error, GNUNET_OK otherwise
 */
static int
setStat (sqliteHandle * handle, const char *key, unsigned long long val)
{
  sqlite3_stmt *stmt;
  sqlite3 *dbh;

  dbh = handle->dbh;
  if (sq_prepare (dbh, "DELETE FROM gn071 where key = ?", &stmt) == SQLITE_OK)
    {
      sqlite3_bind_text (stmt, 1, key, strlen (key), SQLITE_STATIC);
      if (SQLITE_DONE != sqlite3_step (stmt))
        LOG_SQLITE (handle,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "sqlite3_step");

      sqlite3_finalize (stmt);
    }

  if (sq_prepare (dbh,
                  "INSERT INTO gn071(key, value) VALUES (?, ?)",
                  &stmt) != SQLITE_OK)
    return GNUNET_SYSERR;
  if ((SQLITE_OK !=
       sqlite3_bind_text (stmt, 1, key, strlen (key), SQLITE_STATIC))
      || (SQLITE_OK != sqlite3_bind_int64 (stmt, 2, val)))
    {
      LOG_SQLITE (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "sqlite3_bind_xxx");
      sqlite3_finalize (stmt);
      return GNUNET_SYSERR;
    }
  if (sqlite3_step (stmt) != SQLITE_DONE)
    {
      LOG_SQLITE (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "sqlite3_step");
      sqlite3_finalize (stmt);
      return GNUNET_SYSERR;
    }
  sqlite3_finalize (stmt);

  return GNUNET_OK;
}

/**
 * @brief write all statistics to the db
 */
static void
syncStats (sqliteHandle * handle)
{
  setStat (handle, "PAYLOAD", payload);
  lastSync = 0;
}

/**
 * Call a method for each key in the database and
 * call the callback method on it.
 *
 * @param type entries of which type should be considered?
 * @param iter maybe NULL (to just count); iter
 *     should return GNUNET_SYSERR to abort the
 *     iteration, GNUNET_NO to delete the entry and
 *     continue and GNUNET_OK to continue iterating
 * @return the number of results processed,
 *         GNUNET_SYSERR on error
 */
static int
sqlite_iterate (unsigned int type,
                int is_asc,
                int is_prio,
                int is_migr,
                int limit_nonanonymous,
                const char *stmt_str_1,
                const char *stmt_str_2,
                GNUNET_DatastoreValueIterator iter, void *closure)
{
  sqlite3_stmt *stmt_1;
  sqlite3_stmt *stmt_2;
  int count;
  GNUNET_DatastoreValue *datum_1;
  GNUNET_DatastoreValue *datum_2;
  GNUNET_DatastoreValue *last_datum_2;
  GNUNET_DatastoreValue *datum;
  unsigned int lastPrio;
  unsigned long long lastExp;
  GNUNET_HashCode key_1;
  GNUNET_HashCode key_2;
  GNUNET_HashCode key;
  sqlite3 *dbh;
  sqliteHandle *handle;
  int ret;
  GNUNET_CronTime now;
  unsigned long long rowid;
  unsigned long long rowid_1;
  unsigned long long rowid_2;

  GNUNET_mutex_lock (lock);
  handle = getDBHandle ();
  dbh = handle->dbh;
  if (sq_prepare (dbh, stmt_str_1, &stmt_1) != SQLITE_OK)
    {
      LOG_SQLITE (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "sqlite3_prepare");
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  if (sq_prepare (dbh, stmt_str_2, &stmt_2) != SQLITE_OK)
    {
      LOG_SQLITE (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "sqlite3_prepare");
      sqlite3_finalize (stmt_1);
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  count = 0;
  if (is_asc)
    {
      lastPrio = 0;
      lastExp = 0;
      memset (&key, 0, sizeof (GNUNET_HashCode));
    }
  else
    {
      lastPrio = 0x7FFFFFFF;
      lastExp = 0x7FFFFFFFFFFFFFFFLL;
      memset (&key, 255, sizeof (GNUNET_HashCode));
    }
  last_datum_2 = NULL;
  while (1)
    {
      if (is_prio)
        {
          sqlite3_bind_int (stmt_1, 1, lastPrio);
          sqlite3_bind_int (stmt_2, 1, lastPrio);
        }
      else
        {
          sqlite3_bind_int64 (stmt_1, 1, lastExp);
          sqlite3_bind_int64 (stmt_2, 1, lastExp);
        }
      sqlite3_bind_blob (stmt_1, 2, &key, sizeof (GNUNET_HashCode),
                         SQLITE_TRANSIENT);
      now = GNUNET_get_time ();
      datum_1 = NULL;
      datum_2 = last_datum_2;
      last_datum_2 = NULL;
      if ((ret = sqlite3_step (stmt_1)) == SQLITE_ROW)
        {
          if (is_migr && sqlite3_column_int64 (stmt_1, 4) < now)
            datum_1 = NULL;
          else
            datum_1 = assembleDatum (handle, stmt_1, &key_1, &rowid_1);
          if (SQLITE_OK != sqlite3_reset (stmt_1))
            LOG_SQLITE (handle,
                        GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                        GNUNET_GE_BULK, "sqlite3_reset");
        }
      else
        {
          if (ret != SQLITE_DONE)
            {
              LOG_SQLITE (handle,
                          GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                          GNUNET_GE_BULK, "sqlite3_step");
              sqlite3_finalize (stmt_1);
              sqlite3_finalize (stmt_2);
              GNUNET_mutex_unlock (lock);
              return GNUNET_SYSERR;
            }
          sqlite3_reset (stmt_1);
        }

      if (datum_2 == NULL)
        {
          if ((ret = sqlite3_step (stmt_2)) == SQLITE_ROW)
            {
              if (is_migr && sqlite3_column_int64 (stmt_2, 4) < now)
                datum_2 = NULL;
              else
                datum_2 = assembleDatum (handle, stmt_2, &key_2, &rowid_2);
              if (SQLITE_OK != sqlite3_reset (stmt_2))
                LOG_SQLITE (handle,
                            GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER
                            | GNUNET_GE_BULK, "sqlite3_reset");
            }
          else
            {
              if (ret != SQLITE_DONE)
                {
                  LOG_SQLITE (handle,
                              GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                              GNUNET_GE_USER | GNUNET_GE_BULK,
                              "sqlite3_step");
                  sqlite3_finalize (stmt_1);
                  sqlite3_finalize (stmt_2);
                  GNUNET_mutex_unlock (lock);
                  GNUNET_free_non_null (datum_1);
                  return GNUNET_SYSERR;
                }
              sqlite3_reset (stmt_2);
            }
        }
      datum = NULL;
      if (datum_1 == NULL)
        {
          datum = datum_2;
          rowid = rowid_2;
          key = key_2;
        }
      else if (datum_2 == NULL)
        {
          datum = datum_1;
          rowid = rowid_1;
          key = key_1;
        }
      else
        {
          /* have to pick between 1 and 2 */
          if (is_prio)
            {
              if ((ntohl (datum_1->priority) < ntohl (datum_2->priority)) ==
                  is_asc)
                {
                  datum = datum_1;
                  rowid = rowid_1;
                  key = key_1;
                  last_datum_2 = datum_2;
                }
              else
                {
                  datum = datum_2;
                  rowid = rowid_2;
                  key = key_2;
                  GNUNET_free (datum_1);
                }
            }
          else
            {
              if ((GNUNET_ntohll (datum_1->expiration_time) <
                   GNUNET_ntohll (datum_2->expiration_time)) == is_asc)
                {
                  datum = datum_1;
                  rowid = rowid_1;
                  key = key_1;
                  last_datum_2 = datum_2;
                }
              else
                {
                  datum = datum_2;
                  rowid = rowid_2;
                  key = key_2;
                  GNUNET_free (datum_1);
                }
            }
        }
      if (datum == NULL)
        break;
#if 0
      printf ("FOUND %4u prio %4u exp %20llu old: %4u, %20llu\n",
              (ntohl (datum->size) - sizeof (GNUNET_DatastoreValue)),
              ntohl (datum->priority),
              GNUNET_ntohll (datum->expiration_time), lastPrio, lastExp);
#endif
      if (((GNUNET_NO == limit_nonanonymous) ||
           (ntohl (datum->anonymity_level) == 0)) &&
          ((type == GNUNET_ECRS_BLOCKTYPE_ANY) ||
           (type == ntohl (datum->type))))
        {
          count++;
          if (iter != NULL)
            {
              GNUNET_mutex_unlock (lock);
              ret = iter (&key, datum, closure, rowid);
              GNUNET_mutex_lock (lock);
              if (ret == GNUNET_SYSERR)
                {
                  GNUNET_free (datum);
                  break;
                }
              if (ret == GNUNET_NO)
                {
                  payload -= getContentDatastoreSize (datum);
                  delete_by_rowid (handle, rowid);
                }
            }
        }
      lastPrio = ntohl (datum->priority);
      lastExp = GNUNET_ntohll (datum->expiration_time);
      GNUNET_free (datum);
    }
  sqlite3_finalize (stmt_1);
  sqlite3_finalize (stmt_2);
  GNUNET_free_non_null (last_datum_2);
  GNUNET_mutex_unlock (lock);
  return count;
}

/**
 * Call a method for each key in the database and
 * call the callback method on it.
 *
 * @param type limit the iteration to entries of this
 *   type. 0 for all entries.
 * @param iter the callback method
 * @param closure argument to all callback calls
 * @return the number of results, GNUNET_SYSERR on error
 */
static int
iterateLowPriority (unsigned int type, GNUNET_DatastoreValueIterator iter,
                    void *closure)
{
  return sqlite_iterate (type, GNUNET_YES, GNUNET_YES, GNUNET_NO, GNUNET_NO,
                         SELECT_IT_LOW_PRIORITY_1,
                         SELECT_IT_LOW_PRIORITY_2, iter, closure);
}

/**
 * Call a method on content with zero anonymity.
 *
 * @param type limit the iteration to entries of this
 *   type. 0 for all entries.
  * @param iter the callback method
 * @param closure argument to all callback calls
 * @return the number of results, GNUNET_SYSERR on error
 */
static int
iterateNonAnonymous (unsigned int type, GNUNET_DatastoreValueIterator iter,
                     void *closure)
{
  return sqlite_iterate (type, GNUNET_NO, GNUNET_YES, GNUNET_NO, GNUNET_YES,
                         SELECT_IT_NON_ANONYMOUS_1,
                         SELECT_IT_NON_ANONYMOUS_2, iter, closure);
}

/**
 * Call a method for each key in the database and
 * call the callback method on it.
 *
 * @param handle the database
 * @param callback the callback method
 * @param data second argument to all callback calls
 * @return the number of items stored in the content database
 */
static int
iterateExpirationTime (unsigned int type, GNUNET_DatastoreValueIterator iter,
                       void *closure)
{
  return sqlite_iterate (type, GNUNET_YES, GNUNET_NO, GNUNET_NO, GNUNET_NO,
                         SELECT_IT_EXPIRATION_TIME_1,
                         SELECT_IT_EXPIRATION_TIME_2, iter, closure);
}

/**
 * Iterate over the items in the datastore in migration
 * order.
 *
 * @param iter never NULL
 * @return the number of results, GNUNET_SYSERR on error
 */
static int
iterateMigrationOrder (GNUNET_DatastoreValueIterator iter, void *closure)
{
  return sqlite_iterate (0, GNUNET_NO, GNUNET_NO, GNUNET_YES, GNUNET_NO,
                         SELECT_IT_MIGRATION_ORDER_1,
                         SELECT_IT_MIGRATION_ORDER_2, iter, closure);
}

/**
 * Call a method for each key in the database and
 * do so quickly in any order (can lock the
 * database until iteration is complete).
 *
 * @param callback the callback method
 * @param data second argument to all callback calls
 * @return the number of items stored in the content database
 */
static int
iterateAllNow (GNUNET_DatastoreValueIterator iter, void *closure)
{
  sqlite3_stmt *stmt;
  int count;
  GNUNET_DatastoreValue *datum;
  sqlite3 *dbh;
  sqliteHandle *handle;
  int ret;
  unsigned long long newpayload;
  unsigned long long rowid;
  unsigned long long last_rowid;
  GNUNET_HashCode key;

  newpayload = 0;
  GNUNET_mutex_lock (lock);
  handle = getDBHandle ();
  dbh = handle->dbh;
  /* For the rowid trick see
     http://permalink.gmane.org/gmane.network.gnunet.devel/1363 */
  if (sq_prepare (dbh,
                  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_"
                  " FROM gn080 WHERE _ROWID_ > :1 ORDER BY _ROWID_ ASC LIMIT 1",
                  &stmt) != SQLITE_OK)
    {
      LOG_SQLITE (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "sqlite3_prepare");
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  count = 0;
  last_rowid = 0;
  while (1)
    {
      ret = sqlite3_bind_int64 (stmt, 1, last_rowid);
      if (ret != SQLITE_OK)
        break;
      if (sqlite3_step (stmt) != SQLITE_ROW)
        break;
      datum = assembleDatum (handle, stmt, &key, &rowid);
#if 0
      printf ("IA-FOUND %4u prio %4u exp %20llu RID %llu old-RID: %llu\n",
              (ntohl (datum->size) - sizeof (GNUNET_DatastoreValue)),
              ntohl (datum->priority),
              GNUNET_ntohll (datum->expiration_time), rowid, last_rowid);
#endif
      last_rowid = rowid;
      sqlite3_reset (stmt);
      if (datum == NULL)
        continue;
      newpayload += getContentDatastoreSize (datum);
      count++;
      if (iter != NULL)
        {
          GNUNET_mutex_unlock (lock);
          ret = iter (&key, datum, closure, rowid);
          GNUNET_mutex_lock (lock);
        }
      else
        ret = GNUNET_OK;
      if (ret == GNUNET_SYSERR)
        {
          GNUNET_free (datum);
          break;
        }
      if (ret == GNUNET_NO)
        {
          newpayload -= getContentDatastoreSize (datum);
          delete_by_rowid (handle, rowid);
        }
      GNUNET_free (datum);
    }
  sqlite3_reset (stmt);
  sqlite3_finalize (stmt);
  if (count != GNUNET_SYSERR)
    {
      /* re-computed payload! */
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_IMMEDIATE | GNUNET_GE_USER |
                     GNUNET_GE_ADMIN,
                     "SQLite database size recomputed.  New estimate is %llu, old estimate was %llu\n",
                     newpayload, payload);
      payload = newpayload;
      syncStats (handle);
    }
  GNUNET_mutex_unlock (lock);
  return count;
}




static void
sqlite_shutdown ()
{
  unsigned int idx;

  if (fn == NULL)
    return;                     /* already down */
#if DEBUG_SQLITE
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "SQLite: closing database\n");
#endif
  syncStats (getDBHandle ());

  for (idx = 0; idx < handle_count; idx++)
    {
      sqliteHandle *h = handles[idx];

      GNUNET_thread_release_self (h->tid);
      sqlite3_finalize (h->updPrio);
      sqlite3_finalize (h->insertContent);
      if (sqlite3_close (h->dbh) != SQLITE_OK)
        LOG_SQLITE (h,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "sqlite_close");
      GNUNET_free (h);
    }
  GNUNET_free (handles);
  handles = NULL;
  handle_count = 0;
  GNUNET_free (fn);
  fn = NULL;
}

/**
 * Delete the database.  The next operation is
 * guaranteed to be unloading of the module.
 */
static void
drop ()
{
  char *n = GNUNET_strdup (fn);
  sqlite_shutdown ();
  UNLINK (n);
  GNUNET_free (n);
}


/**
 * Iterate over all entries matching a particular key and
 * type.
 *
 * @param key maybe NULL (to match all entries)
 * @param vhash hash of the value; maybe NULL (to match all entries)
 * @param type entries of which type are relevant?
 *     Use 0 for any type.
 * @param iter maybe NULL (to just count); iter
 *     should return GNUNET_SYSERR to abort the
 *     iteration, GNUNET_NO to delete the entry and
 *     continue and GNUNET_OK to continue iterating
 * @return the number of results processed,
 *         GNUNET_SYSERR on error
 */
static int
get (const GNUNET_HashCode * key,
     const GNUNET_HashCode * vhash,
     unsigned int type, GNUNET_DatastoreValueIterator iter, void *closure)
{
  int ret;
  int count;
  int total;
  int off;
  int limit_off;
  sqlite3_stmt *stmt;
  char scratch[256];
  GNUNET_DatastoreValue *datum;
  sqlite3 *dbh;
  sqliteHandle *handle;
  GNUNET_HashCode rkey;
  unsigned long long last_rowid;
  unsigned long long rowid;
  int sqoff;

  if (key == NULL)
    return iterateLowPriority (type, iter, closure);
  GNUNET_mutex_lock (lock);
  handle = getDBHandle ();
  dbh = handle->dbh;

  GNUNET_snprintf (scratch, 256,
                   "SELECT count(*) FROM gn080 WHERE hash=:1%s%s",
                   vhash == NULL ? "" : " AND vhash=:2",
                   type == 0 ? "" : (vhash ==
                                     NULL) ? " AND type=:2" : " AND type=:3");
  if (sq_prepare (dbh, scratch, &stmt) != SQLITE_OK)
    {
      LOG_SQLITE (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "sqlite_prepare");
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  sqoff = 1;
  ret = sqlite3_bind_blob (stmt,
                           sqoff++,
                           key, sizeof (GNUNET_HashCode), SQLITE_TRANSIENT);
  if ((vhash != NULL) && (ret == SQLITE_OK))
    ret = sqlite3_bind_blob (stmt,
                             sqoff++,
                             vhash,
                             sizeof (GNUNET_HashCode), SQLITE_TRANSIENT);
  if ((type != 0) && (ret == SQLITE_OK))
    ret = sqlite3_bind_int (stmt, sqoff++, type);
  if (ret != SQLITE_OK)
    {
      LOG_SQLITE (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "sqlite_bind");
      sqlite3_reset (stmt);
      sqlite3_finalize (stmt);
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;

    }
  ret = sqlite3_step (stmt);
  if (ret != SQLITE_ROW)
    {
      LOG_SQLITE (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "sqlite_step");
      sqlite3_reset (stmt);
      sqlite3_finalize (stmt);
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;

    }
  total = sqlite3_column_int (stmt, 0);
  sqlite3_reset (stmt);
  sqlite3_finalize (stmt);
  if ((iter == NULL) || (total == 0))
    {
      GNUNET_mutex_unlock (lock);
      return total;
    }

  GNUNET_snprintf (scratch, 256,
                   "SELECT size, type, prio, anonLevel, expire, hash, value, _ROWID_ "
                   "FROM gn080 WHERE hash=:1%s%s AND _ROWID_ >= :%d "
                   "ORDER BY _ROWID_ ASC LIMIT 1 OFFSET :d",
                   vhash == NULL ? "" : " AND vhash=:2",
                   type == 0 ? "" : (vhash ==
                                     NULL) ? " AND type=:2" : " AND type=:3",
                   sqoff, sqoff + 1);
  if (sq_prepare (dbh, scratch, &stmt) != SQLITE_OK)
    {
      LOG_SQLITE (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "sqlite_prepare");
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  count = 0;
  last_rowid = 0;
  off = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, total);
  while (1)
    {
      if (count == 0)
        limit_off = off;
      else
        limit_off = 0;
      sqoff = 1;
      ret = sqlite3_bind_blob (stmt,
                               sqoff++,
                               key, sizeof (GNUNET_HashCode),
                               SQLITE_TRANSIENT);
      if ((vhash != NULL) && (ret == SQLITE_OK))
        ret = sqlite3_bind_blob (stmt,
                                 sqoff++,
                                 vhash,
                                 sizeof (GNUNET_HashCode), SQLITE_TRANSIENT);
      if ((type != 0) && (ret == SQLITE_OK))
        ret = sqlite3_bind_int (stmt, sqoff++, type);
      if (ret == SQLITE_OK)
        ret = sqlite3_bind_int64 (stmt, sqoff++, last_rowid);
      if (ret == SQLITE_OK)
        ret = sqlite3_bind_int (stmt, sqoff++, limit_off);
      if (ret == SQLITE_OK)
        {
          ret = sqlite3_step (stmt);
          if (ret != SQLITE_ROW)
            break;
          datum = assembleDatum (handle, stmt, &rkey, &rowid);
          last_rowid = rowid + 1;
          sqlite3_reset (stmt);
          if (datum == NULL)
            continue;
          if ((key != NULL) &&
              (0 != memcmp (&rkey, key, sizeof (GNUNET_HashCode))))
            {
              GNUNET_GE_BREAK (NULL, 0);
              GNUNET_free (datum);
              continue;
            }
          GNUNET_mutex_unlock (lock);
          count++;
          ret = iter (&rkey, datum, closure, rowid);
          GNUNET_mutex_lock (lock);
          if (ret == GNUNET_SYSERR)
            {
              GNUNET_free (datum);
              ret = SQLITE_DONE;
              break;
            }
          if (ret == GNUNET_NO)
            {
              payload -= getContentDatastoreSize (datum);
              delete_by_rowid (handle, rowid);
            }
          GNUNET_free (datum);
        }
      if (count + off == total)
        last_rowid = 0;         /* back to start */
      if (count == total)
        break;
    }
  sqlite3_reset (stmt);
  sqlite3_finalize (stmt);
  GNUNET_mutex_unlock (lock);
  return count;
}

/**
 * Write content to the db.  Always adds a new record
 * (does NOT overwrite existing data).
 *
 * @return GNUNET_SYSERR on error, GNUNET_NO on temporary error, GNUNET_OK if ok.
 */
static int
put (const GNUNET_HashCode * key, const GNUNET_DatastoreValue * value)
{
  int n;
  sqlite3_stmt *stmt;
  unsigned int contentSize;
  unsigned int size, type, prio, anon;
  unsigned long long expir;
  GNUNET_HashCode vhash;
  sqliteHandle *dbh;
#if DEBUG_SQLITE
  GNUNET_EncName enc;

  IF_GELOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_USER,
            GNUNET_hash_to_enc (key, &enc));
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_USER,
                 "Storing in database block with type %u/key `%s'/priority %u/expiration %llu.\n",
                 ntohl (*(int *) &value[1]), &enc, ntohl (value->priority),
                 GNUNET_ntohll (value->expiration_time));
#endif

  if ((ntohl (value->size) < sizeof (GNUNET_DatastoreValue)))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  size = ntohl (value->size);
  type = ntohl (value->type);
  prio = ntohl (value->priority);
  anon = ntohl (value->anonymity_level);
  expir = GNUNET_ntohll (value->expiration_time);
  contentSize = size - sizeof (GNUNET_DatastoreValue);
  GNUNET_hash (&value[1], contentSize, &vhash);
  GNUNET_mutex_lock (lock);
  dbh = getDBHandle ();
  if (lastSync > 1000)
    syncStats (dbh);
  stmt = dbh->insertContent;
  if ((SQLITE_OK != sqlite3_bind_int (stmt, 1, size)) ||
      (SQLITE_OK != sqlite3_bind_int (stmt, 2, type)) ||
      (SQLITE_OK != sqlite3_bind_int (stmt, 3, prio)) ||
      (SQLITE_OK != sqlite3_bind_int (stmt, 4, anon)) ||
      (SQLITE_OK != sqlite3_bind_int64 (stmt, 5, expir)) ||
      (SQLITE_OK !=
       sqlite3_bind_blob (stmt, 6, key, sizeof (GNUNET_HashCode),
                          SQLITE_TRANSIENT)) ||
      (SQLITE_OK !=
       sqlite3_bind_blob (stmt, 7, &vhash, sizeof (GNUNET_HashCode),
                          SQLITE_TRANSIENT))
      || (SQLITE_OK !=
          sqlite3_bind_blob (stmt, 8, &value[1], contentSize,
                             SQLITE_TRANSIENT)))
    {
      LOG_SQLITE (dbh,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "sqlite3_bind_XXXX");
      if (SQLITE_OK != sqlite3_reset (stmt))
        LOG_SQLITE (dbh,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "sqlite3_reset");
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }

  n = sqlite3_step (stmt);
  if (n != SQLITE_DONE)
    {
      if (n == SQLITE_BUSY)
        {
          sqlite3_reset (stmt);
          GNUNET_mutex_unlock (lock);
          GNUNET_GE_BREAK (NULL, 0);
          return GNUNET_NO;
        }
      LOG_SQLITE (dbh,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "sqlite3_step");
      sqlite3_reset (stmt);
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  if (SQLITE_OK != sqlite3_reset (stmt))
    LOG_SQLITE (dbh,
                GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                GNUNET_GE_BULK, "sqlite3_reset");
  lastSync++;
  payload += getContentDatastoreSize (value);
#if DEBUG_SQLITE
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "SQLite: done writing content\n");
#endif
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

/**
 * Update the priority for a particular key
 * in the datastore.
 */
static int
update (unsigned long long uid, int delta, GNUNET_CronTime expire)
{
  int n;
  sqliteHandle *dbh;

  GNUNET_mutex_lock (lock);
  dbh = getDBHandle ();
  sqlite3_bind_int (dbh->updPrio, 1, delta);
  sqlite3_bind_int64 (dbh->updPrio, 2, expire);
  sqlite3_bind_int64 (dbh->updPrio, 3, uid);
  n = sqlite3_step (dbh->updPrio);
  if (n != SQLITE_DONE)
    LOG_SQLITE (dbh,
                GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                GNUNET_GE_BULK, "sqlite3_step");

  sqlite3_reset (dbh->updPrio);

#if DEBUG_SQLITE
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "SQLite: block updated\n");
#endif
  GNUNET_mutex_unlock (lock);
  if (n == SQLITE_BUSY)
    return GNUNET_NO;
  return n == SQLITE_OK ? GNUNET_OK : GNUNET_SYSERR;
}

GNUNET_SQstore_ServiceAPI *
provide_module_sqstore_sqlite (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_SQstore_ServiceAPI api;

  char *dir;
  char *afsdir;
  sqliteHandle *dbh;

  ectx = capi->ectx;
#if DEBUG_SQLITE
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "SQLite: initializing database\n");
#endif

  payload = 0;
  lastSync = 0;

  afsdir = NULL;
  GNUNET_GC_get_configuration_value_filename (capi->cfg,
                                              "FS",
                                              "DIR",
                                              GNUNET_DEFAULT_DAEMON_VAR_DIRECTORY
                                              "/data/fs/", &afsdir);
  dir = GNUNET_malloc (strlen (afsdir) + strlen ("/content/gnunet.dat") + 2);
  strcpy (dir, afsdir);
  strcat (dir, "/content/gnunet.dat");
  GNUNET_free (afsdir);
  if (GNUNET_OK != GNUNET_disk_directory_create_for_file (ectx, dir))
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_free (dir);
      return NULL;
    }
  fn = GNUNET_convert_string_to_utf8 (ectx, dir, strlen (dir),
#ifdef ENABLE_NLS
                                      nl_langinfo (CODESET)
#else
                                      "UTF-8"   /* good luck */
#endif
    );
  GNUNET_free (dir);
  dbh = getDBHandle ();
  if (dbh == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_free (fn);
      fn = NULL;
      return NULL;
    }

  payload = getStat (dbh, "PAYLOAD");
  if (payload == GNUNET_SYSERR)
    {
      GNUNET_GE_BREAK (ectx, 0);
      LOG_SQLITE (dbh,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "sqlite_payload");
      GNUNET_mutex_destroy (lock);
      GNUNET_free (fn);
      fn = NULL;
      return NULL;
    }
  lock = GNUNET_mutex_create (GNUNET_NO);
  coreAPI = capi;
  stats = coreAPI->service_request ("stats");
  if (stats)
    {
      stat_size = stats->create (gettext_noop ("# bytes in datastore"));
#if DEBUG_SQLITE
      stat_mem = stats->create (gettext_noop ("# bytes allocated by SQLite"));
#endif
    }

  api.getSize = &getSize;
  api.put = &put;
  api.get = &get;
  api.iterateLowPriority = &iterateLowPriority;
  api.iterateNonAnonymous = &iterateNonAnonymous;
  api.iterateExpirationTime = &iterateExpirationTime;
  api.iterateMigrationOrder = &iterateMigrationOrder;
  api.iterateAllNow = &iterateAllNow;
  api.drop = &drop;
  api.update = &update;
  return &api;
}

/**
 * Shutdown the module.
 */
void
release_module_sqstore_sqlite ()
{
  if (stats != NULL)
    coreAPI->service_release (stats);
  sqlite_shutdown ();
#if DEBUG_SQLITE
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "SQLite: database shutdown\n");
#endif
  GNUNET_mutex_destroy (lock);
  lock = NULL;
  coreAPI = NULL;
}



/**
 * Update sqlite database module.
 *
 * Currently only makes sure that the sqlite indices are created.
 */
void
update_module_sqstore_sqlite (GNUNET_UpdateAPI * uapi)
{
  sqliteHandle *dbh;
  char *dir;
  char *afsdir;

  payload = 0;
  lastSync = 0;
  afsdir = NULL;
  GNUNET_GC_get_configuration_value_filename (uapi->cfg,
                                              "FS",
                                              "DIR",
                                              GNUNET_DEFAULT_DAEMON_VAR_DIRECTORY
                                              "/data/fs/", &afsdir);
  dir = GNUNET_malloc (strlen (afsdir) + 8 + 2);        /* 8 = "content/" */
  strcpy (dir, afsdir);
  strcat (dir, "/content/");
  GNUNET_free (afsdir);
  if (GNUNET_OK != GNUNET_disk_directory_create (ectx, dir))
    {
      GNUNET_free (dir);
      return;
    }
  fn = dir;
  lock = GNUNET_mutex_create (GNUNET_NO);
  dbh = getDBHandle ();
  if (dbh == NULL)
    {
      GNUNET_mutex_destroy (lock);
      GNUNET_free (fn);
      fn = NULL;
      return;
    }
  createIndices (dbh->dbh);
  sqlite_shutdown ();
  GNUNET_mutex_destroy (lock);
}

/* end of sqlite.c */
