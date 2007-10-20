/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @todo Estimation of DB size
 * @todo get/iterateAll: use ORDER-BY ROWID and LIMIT 1!
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

#define DEBUG_SQLITE NO

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define DIE_SQLITE(db, cmd) do { GE_LOG(ectx, GE_FATAL | GE_IMMEDIATE | GE_ADMIN, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db->dbh)); abort(); } while(0)

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_SQLITE(db, level, cmd) do { GE_LOG(ectx, level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db->dbh)); } while(0)

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
  struct PTHREAD *tid;

  /**
   * Precompiled SQL
   */
  sqlite3_stmt *exists;

  sqlite3_stmt *countContent;

  sqlite3_stmt *updPrio;

  sqlite3_stmt *insertContent;
} sqliteHandle;

static Stats_ServiceAPI *stats;

static CoreAPIForApplication *coreAPI;

static unsigned int stat_size;

static struct GE_Context *ectx;

static struct MUTEX *lock;

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
#define CHECK(a) GE_BREAK(ectx, a)
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
  CHECK (SQLITE_OK ==
         sqlite3_exec (dbh,
                       "CREATE INDEX idx_hash ON gn070 (hash)",
                       NULL, NULL, ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (dbh,
                       "CREATE INDEX idx_prio ON gn070 (prio)",
                       NULL, NULL, ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (dbh,
                       "CREATE INDEX idx_expire ON gn070 (expire)",
                       NULL, NULL, ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (dbh,
                       "CREATE INDEX idx_comb1 ON gn070 (prio,expire,hash)",
                       NULL, NULL, ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (dbh,
                       "CREATE INDEX idx_comb2 ON gn070 (expire,prio,hash)",
                       NULL, NULL, ENULL));
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
    if (PTHREAD_TEST_SELF (handles[idx]->tid))
      return handles[idx];

  /* we haven't opened the DB for this thread yet */
  ret = MALLOC (sizeof (sqliteHandle));
  /* Open database and precompile statements */
  if (sqlite3_open (fn, &ret->dbh) != SQLITE_OK)
    {
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("Unable to initialize SQLite: %s.\n"),
              sqlite3_errmsg (ret->dbh));
      sqlite3_close (ret->dbh);
      FREE (ret);
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
                     "Select 1 from sqlite_master where tbl_name = 'gn070'",
                     &stmt));
  if (sqlite3_step (stmt) == SQLITE_DONE)
    {
      if (sqlite3_exec (ret->dbh,
                        "CREATE TABLE gn070 ("
                        "  size INTEGER NOT NULL DEFAULT 0,"
                        "  type INTEGER NOT NULL DEFAULT 0,"
                        "  prio INTEGER NOT NULL DEFAULT 0,"
                        "  anonLevel INTEGER NOT NULL DEFAULT 0,"
                        "  expire INTEGER NOT NULL DEFAULT 0,"
                        "  hash TEXT NOT NULL DEFAULT '',"
                        "  value BLOB NOT NULL DEFAULT '')", NULL, NULL,
                        NULL) != SQLITE_OK)
        {
          LOG_SQLITE (ret,
                      GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
                      "sqlite_create");
          sqlite3_finalize (stmt);
          FREE (ret);
          return NULL;
        }
      createIndices (ret->dbh);
    }
  sqlite3_finalize (stmt);

  if ((sq_prepare (ret->dbh,
                   "SELECT COUNT(*) FROM gn070 WHERE hash=?",
                   &ret->countContent) != SQLITE_OK) ||
      (sq_prepare (ret->dbh,
                   "SELECT LENGTH(hash), LENGTH(value), size, type, prio, anonLevel, expire, _ROWID_ "
                   "FROM gn070 WHERE hash=?",
                   &ret->exists) != SQLITE_OK) ||
      (sq_prepare (ret->dbh,
                   "UPDATE gn070 SET prio = prio + ?, expire = MAX(expire,?) WHERE "
                   "_ROWID_ = ?",
                   &ret->updPrio) != SQLITE_OK) ||
      (sq_prepare (ret->dbh,
                   "INSERT INTO gn070 (size, type, prio, "
                   "anonLevel, expire, hash, value) VALUES "
                   "(?, ?, ?, ?, ?, ?, ?)",
                   &ret->insertContent) != SQLITE_OK))
    {
      LOG_SQLITE (ret,
                  GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "precompiling");
      if (ret->countContent != NULL)
        sqlite3_finalize (ret->countContent);
      if (ret->exists != NULL)
        sqlite3_finalize (ret->exists);
      if (ret->updPrio != NULL)
        sqlite3_finalize (ret->updPrio);
      if (ret->insertContent != NULL)
        sqlite3_finalize (ret->insertContent);
      FREE (ret);
      return NULL;
    }
  ret->tid = PTHREAD_GET_SELF ();
  APPEND (handles, handle_count, ret);
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
 * row length = hash length + block length + numbers + column count + estimated index size + 1
 * </pre>
 */
static unsigned int
getContentDatastoreSize (const Datastore_Value * value)
{
  return sizeof (HashCode512) + ntohl (value->size) - sizeof (Datastore_Value)
    + getIntSize (ntohl (value->size)) + getIntSize (ntohl (value->type)) +
    getIntSize (ntohl (value->prio)) +
    getIntSize (ntohl (value->anonymityLevel)) +
    getIntSize (ntohll (value->expirationTime)) + 7 + 245 + 1;
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

  MUTEX_LOCK (lock);
  ret = payload;
  if (stats)
    stats->set (stat_size, ret);
  MUTEX_UNLOCK (lock);
  return (unsigned long long) (ret * 1.13);
  /* benchmarking shows 13% overhead */
}

static int
delete_by_rowid (sqliteHandle * handle, unsigned long long rid)
{
  sqlite3_stmt *stmt;

  if (sq_prepare (handle->dbh,
                  "DELETE FROM gn070 WHERE _ROWID_ = ?", &stmt) != SQLITE_OK)
    {
      LOG_SQLITE (handle,
                  GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "sq_prepare");
      return SYSERR;
    }
  sqlite3_bind_int64 (stmt, 1, rid);
  if (SQLITE_DONE != sqlite3_step (stmt))
    {
      LOG_SQLITE (handle,
                  GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "sqlite3_step");
      sqlite3_finalize (stmt);
      return SYSERR;
    }
  sqlite3_finalize (stmt);
  return OK;
}

/**
 * Given a full row from gn070 table (size,type,prio,anonLevel,expire,hash,value),
 * assemble it into a Datastore_Value representation.
 */
static Datastore_Value *
assembleDatum (sqliteHandle * handle, sqlite3_stmt * stmt,
               HashCode512 * key, unsigned long long *rowid)
{
  Datastore_Value *value;
  int contentSize;
  sqlite3 *dbh;
  unsigned int type;

  *rowid = sqlite3_column_int64 (stmt, 7);
  type = sqlite3_column_int (stmt, 1);
  if (type == RESERVED_BLOCK)
    return NULL;

  contentSize = sqlite3_column_int (stmt, 0) - sizeof (Datastore_Value);

  dbh = handle->dbh;
  if (contentSize < 0)
    {
      sqlite3_stmt *stmtd;

      GE_LOG (ectx,
              GE_WARNING | GE_BULK | GE_USER,
              _("Invalid data in %s (NCS).  Trying to fix (by deletion).\n"),
              _("sqlite datastore"));
      if (1)
        abort ();
      if (SQLITE_OK != sqlite3_reset (stmt))
        LOG_SQLITE (handle,
                    GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "sqlite3_reset");
      if (sq_prepare (dbh,
                      "DELETE FROM gn070 WHERE size < ?",
                      &stmtd) == SQLITE_OK)
        {
          if (SQLITE_OK !=
              sqlite3_bind_int (stmtd, 1, sizeof (Datastore_Value)))
            LOG_SQLITE (handle, GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
                        "sqlite3_bind_int");
          if (SQLITE_DONE != sqlite3_step (stmtd))
            LOG_SQLITE (handle,
                        GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
                        "sqlite3_step");
          if (SQLITE_OK != sqlite3_finalize (stmtd))
            LOG_SQLITE (handle,
                        GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
                        "sqlite3_finalize");
        }
      else
        LOG_SQLITE (handle,
                    GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "sq_prepare");
      return NULL;              /* error */
    }

  if (sqlite3_column_bytes (stmt, 5) != sizeof (HashCode512) ||
      sqlite3_column_bytes (stmt, 6) != contentSize)
    {
      sqlite3_stmt *stmtd;

      GE_LOG (ectx,
              GE_WARNING | GE_BULK | GE_USER,
              _("Invalid data in %s.  Trying to fix (by deletion).\n"),
              _("sqlite datastore"));
      if (SQLITE_OK != sqlite3_reset (stmt))
        LOG_SQLITE (handle,
                    GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "sqlite3_reset");
      if (sq_prepare (dbh,
                      "DELETE FROM gn070 WHERE NOT ((LENGTH(hash) = ?) AND (size = LENGTH(value) + ?))",
                      &stmtd) == SQLITE_OK)
        {
          if (SQLITE_OK != sqlite3_bind_int (stmtd, 1, sizeof (HashCode512)))
            LOG_SQLITE (handle,
                        GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
                        "sqlite3_bind_int");
          if (SQLITE_OK !=
              sqlite3_bind_int (stmtd, 2, sizeof (Datastore_Value)))
            LOG_SQLITE (handle, GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
                        "sqlite3_bind_int");
          if (SQLITE_DONE != sqlite3_step (stmtd))
            LOG_SQLITE (handle,
                        GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
                        "sqlite3_step");
          if (SQLITE_OK != sqlite3_finalize (stmtd))
            LOG_SQLITE (handle,
                        GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
                        "sqlite3_finalize");
        }
      else
        LOG_SQLITE (handle,
                    GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "sq_prepare");

      return NULL;
    }

  value = MALLOC (sizeof (Datastore_Value) + contentSize);
  value->size = htonl (contentSize + sizeof (Datastore_Value));
  value->type = htonl (type);
  value->prio = htonl (sqlite3_column_int (stmt, 2));
  value->anonymityLevel = htonl (sqlite3_column_int (stmt, 3));
  value->expirationTime = htonll (sqlite3_column_int64 (stmt, 4));
  memcpy (key, sqlite3_column_blob (stmt, 5), sizeof (HashCode512));
  memcpy (&value[1], sqlite3_column_blob (stmt, 6), contentSize);
  return value;
}


/**
 * @brief Get database statistics
 * @param key kind of stat to retrieve
 * @return SYSERR on error, the value otherwise
 */
static unsigned long long
getStat (sqliteHandle * handle, const char *key)
{
  int i;
  sqlite3_stmt *stmt;
  unsigned long long ret = SYSERR;

  i = sq_prepare (handle->dbh,
                  "SELECT expire FROM gn070 WHERE hash = ?", &stmt);
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
    return SYSERR;
  if (i != SQLITE_OK)
    {
      LOG_SQLITE (handle,
                  GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "sqlite_getStat");
      return SYSERR;
    }
  return ret;
}

/**
 * @brief set database statistics
 * @param key statistic to set
 * @param val value to set
 * @return SYSERR on error, OK otherwise
 */
static int
setStat (sqliteHandle * handle, const char *key, unsigned long long val)
{
  sqlite3_stmt *stmt;
  sqlite3 *dbh;

  dbh = handle->dbh;
  if (sq_prepare (dbh,
                  "DELETE FROM gn070 where hash = ?", &stmt) == SQLITE_OK)
    {
      sqlite3_bind_text (stmt, 1, key, strlen (key), SQLITE_STATIC);
      if (SQLITE_DONE != sqlite3_step (stmt))
        LOG_SQLITE (handle,
                    GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "sqlite3_step");

      sqlite3_finalize (stmt);
    }

  if (sq_prepare (dbh,
                  "INSERT INTO gn070(hash, expire, type) VALUES (?, ?, ?)",
                  &stmt) != SQLITE_OK)
    return SYSERR;
  if ((SQLITE_OK !=
       sqlite3_bind_text (stmt, 1, key, strlen (key), SQLITE_STATIC))
      || (SQLITE_OK != sqlite3_bind_int64 (stmt, 2, val))
      || (SQLITE_OK != sqlite3_bind_int (stmt, 3, RESERVED_BLOCK)))
    {
      LOG_SQLITE (handle,
                  GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
                  "sqlite3_bind_xxx");
      sqlite3_finalize (stmt);
      return SYSERR;
    }
  if (sqlite3_step (stmt) != SQLITE_DONE)
    {
      LOG_SQLITE (handle,
                  GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "sqlite3_step");
      sqlite3_finalize (stmt);
      return SYSERR;
    }
  sqlite3_finalize (stmt);

  return OK;
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
 *        Use 0 for any type.
 * @param callback the callback method
 * @param data second argument to all callback calls
 * @param sortByPriority 0 to order by expiration, 1 to order by prio
 * @return the number of items stored in the content database
 */
static int
sqlite_iterate (unsigned int type,
                Datum_Iterator iter,
                void *closure,
                int sortByPriority,
                int inverseOrder,
                int include_expired,
                int limit_nonanonymous, int limit_ondemand)
{
  sqlite3_stmt *stmt;
  int count;
  char scratch[512];
  Datastore_Value *datum;
  unsigned int lastPrio;
  unsigned long long lastExp;
  HashCode512 key;
  sqlite3 *dbh;
  sqliteHandle *handle;
  int ret;
  cron_t now;
  unsigned long long rowid;

  MUTEX_LOCK (lock);
  handle = getDBHandle ();
  dbh = handle->dbh;
  /* For the rowid trick see
     http://permalink.gmane.org/gmane.network.gnunet.devel/1363 */
  strcpy (scratch,
          "SELECT size, type, prio, anonLevel, expire, hash, value, _ROWID_ FROM gn070"
          " WHERE rowid IN (SELECT rowid FROM gn070"
          " WHERE ((hash > :1 AND expire == :2 AND prio == :3) OR ");
  if (sortByPriority)
    {
      if (inverseOrder)
        strcat (scratch, "(expire < :4 AND prio == :5) OR prio < :6)");
      else
        strcat (scratch, "(expire > :4 AND prio == :5) OR prio > :6)");
    }
  else
    {
      if (inverseOrder)
        strcat (scratch, "(prio < :4 AND expire == :5) OR expire < :6)");
      else
        strcat (scratch, "(prio > :4 AND expire == :5) OR expire > :6)");
    }
  if (type != 0)
    {
      strcat (scratch, " AND type = :7");
    }
  else if (limit_ondemand == YES)
    {
      SNPRINTF (&scratch[strlen (scratch)],
                512 - strlen (scratch),
                " AND type != %d AND type != %d",
                RESERVED_BLOCK, ONDEMAND_BLOCK);
    }
  else
    {
      SNPRINTF (&scratch[strlen (scratch)], 512 - strlen (scratch), " AND type != %d", RESERVED_BLOCK); /* otherwise we iterate over
                                                                                                           the stats entry, which would
                                                                                                           be bad */
    }
  if (NO == include_expired)
    {
      if (type != 0)
        strcat (scratch, " AND expire > :8");
      else
        strcat (scratch, " AND expire > :7");
    }
  if (sortByPriority)
    {
      if (inverseOrder)
        strcat (scratch, " ORDER BY prio DESC, expire DESC, hash ASC");
      else
        strcat (scratch, " ORDER BY prio ASC, expire ASC, hash ASC");
    }
  else
    {
      if (inverseOrder)
        strcat (scratch, " ORDER BY expire DESC, prio DESC, hash ASC");
      else
        strcat (scratch, " ORDER BY expire ASC, prio ASC, hash ASC");
    }
  strcat (scratch, " LIMIT 1)");
  if (sq_prepare (dbh, scratch, &stmt) != SQLITE_OK)
    {
      LOG_SQLITE (handle,
                  GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "sqlite3_prepare");
      MUTEX_UNLOCK (lock);
      return SYSERR;
    }
  count = 0;
  if (inverseOrder)
    {
      lastPrio = 0x7FFFFFFF;
      lastExp = 0x7FFFFFFFFFFFFFFFLL;
    }
  else
    {
      lastPrio = 0;
      lastExp = 0;
    }
  memset (&key, 0, sizeof (HashCode512));
  while (1)
    {
      sqlite3_bind_blob (stmt,
                         1, &key, sizeof (HashCode512), SQLITE_TRANSIENT);
      sqlite3_bind_int64 (stmt, 2, lastExp);
      sqlite3_bind_int (stmt, 3, lastPrio);
      if (sortByPriority)
        {
          sqlite3_bind_int64 (stmt, 4, lastExp);
          sqlite3_bind_int (stmt, 5, lastPrio);
          sqlite3_bind_int (stmt, 6, lastPrio);
        }
      else
        {
          sqlite3_bind_int64 (stmt, 4, lastExp);
          sqlite3_bind_int (stmt, 5, lastPrio);
          sqlite3_bind_int64 (stmt, 6, lastExp);
        }
      if (type)
        sqlite3_bind_int (stmt, 7, type);
      if (NO == include_expired)
        {
          now = get_time ();
          if (type)
            sqlite3_bind_int64 (stmt, 8, now);
          else
            sqlite3_bind_int64 (stmt, 7, now);
        }
      if ((ret = sqlite3_step (stmt)) == SQLITE_ROW)
        {
          datum = assembleDatum (handle, stmt, &key, &rowid);
          if (SQLITE_OK != sqlite3_reset (stmt))
            LOG_SQLITE (handle,
                        GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
                        "sqlite3_reset");
          if (datum == NULL)
            continue;
#if 0
          printf ("FOUND %4u prio %4u exp %20llu old: %4u, %20llu\n",
                  (ntohl (datum->size) - sizeof (Datastore_Value)),
                  ntohl (datum->prio),
                  ntohll (datum->expirationTime), lastPrio, lastExp);
#endif
          if ((NO == limit_nonanonymous) ||
              (ntohl (datum->anonymityLevel) == 0))
            {
              count++;
              if (iter != NULL)
                {
                  MUTEX_UNLOCK (lock);
                  ret = iter (&key, datum, closure, rowid);
                  MUTEX_LOCK (lock);
                  if (ret == SYSERR)
                    {
                      FREE (datum);
                      count = SYSERR;
                      break;
                    }
                  if (ret == NO)
                    {
                      payload -= getContentDatastoreSize (datum);
                      delete_by_rowid (handle, rowid);
                    }
                }
            }
          lastPrio = ntohl (datum->prio);
          lastExp = ntohll (datum->expirationTime);
          FREE (datum);
        }
      else
        {
          if (ret != SQLITE_DONE)
            {
              LOG_SQLITE (handle,
                          GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
                          "sqlite3_step");
              sqlite3_finalize (stmt);
              MUTEX_UNLOCK (lock);
              return SYSERR;
            }
          sqlite3_reset (stmt);
          break;
        }
    }
  sqlite3_finalize (stmt);
  MUTEX_UNLOCK (lock);
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
 * @return the number of results, SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int
iterateLowPriority (unsigned int type, Datum_Iterator iter, void *closure)
{
  return sqlite_iterate (type, iter, closure, YES, NO, YES, NO, NO);
}

/**
 * Call a method on content with zero anonymity.
 *
 * @param type limit the iteration to entries of this
 *   type. 0 for all entries.
  * @param iter the callback method
 * @param closure argument to all callback calls
 * @return the number of results, SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int
iterateNonAnonymous (unsigned int type, Datum_Iterator iter, void *closure)
{
  return sqlite_iterate (0, iter, closure, NO, NO, NO, YES, YES);
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
iterateExpirationTime (unsigned int type, Datum_Iterator iter, void *closure)
{
  return sqlite_iterate (type, iter, closure, NO, NO, YES, NO, NO);
}

/**
 * Iterate over the items in the datastore in migration
 * order.
 *
 * @param iter never NULL
 * @return the number of results, SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int
iterateMigrationOrder (Datum_Iterator iter, void *closure)
{
  return sqlite_iterate (0, iter, closure, NO, YES, NO, NO, NO);
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
iterateAllNow (Datum_Iterator iter, void *closure)
{
  sqlite3_stmt *stmt;
  int count;
  Datastore_Value *datum;
  sqlite3 *dbh;
  sqliteHandle *handle;
  int ret;
  unsigned long long newpayload;
  unsigned long long rowid;
  unsigned long long last_rowid;
  HashCode512 key;

  newpayload = 0;
  MUTEX_LOCK (lock);
  handle = getDBHandle ();
  dbh = handle->dbh;
  /* For the rowid trick see
     http://permalink.gmane.org/gmane.network.gnunet.devel/1363 */
  if (sq_prepare (dbh,
                  "SELECT size, type, prio, anonLevel, expire, hash, value, _ROWID_"
                  " FROM gn070 WHERE _ROWID_ > :1 ORDER BY _ROWID_ ASC LIMIT 1",
                  &stmt) != SQLITE_OK)
    {
      LOG_SQLITE (handle,
                  GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "sqlite3_prepare");
      MUTEX_UNLOCK (lock);
      return SYSERR;
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
      last_rowid = rowid;
      sqlite3_reset (stmt);
      if (datum == NULL)
        continue;
      newpayload += getContentDatastoreSize (datum);
      if (iter != NULL)
        {
          MUTEX_UNLOCK (lock);
          ret = iter (&key, datum, closure, rowid);
          MUTEX_LOCK (lock);
        }
      else
        ret = OK;
      if (ret == SYSERR)
        {
          FREE (datum);
          count = SYSERR;
          break;
        }
      if (ret == NO)
        {
          newpayload -= getContentDatastoreSize (datum);
          delete_by_rowid (handle, rowid);
        }
      FREE (datum);
      count++;
    }
  sqlite3_reset (stmt);
  sqlite3_finalize (stmt);
  if (count != SYSERR)
    {
      /* re-computed payload! */
      GE_LOG (ectx,
              GE_INFO | GE_IMMEDIATE | GE_USER | GE_ADMIN,
              "SQLite database size recomputed.  New estimate is %llu, old estimate was %llu\n",
              newpayload, payload);
      payload = newpayload;
      syncStats (handle);
    }
  MUTEX_UNLOCK (lock);
  return count;
}




static void
sqlite_shutdown ()
{
  unsigned int idx;

  if (fn == NULL)
    return;                     /* already down */
#if DEBUG_SQLITE
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER, "SQLite: closing database\n");
#endif
  syncStats (getDBHandle ());

  for (idx = 0; idx < handle_count; idx++)
    {
      sqliteHandle *h = handles[idx];

      PTHREAD_REL_SELF (h->tid);
      sqlite3_finalize (h->countContent);
      sqlite3_finalize (h->exists);
      sqlite3_finalize (h->updPrio);
      sqlite3_finalize (h->insertContent);
      if (sqlite3_close (h->dbh) != SQLITE_OK)
        LOG_SQLITE (h,
                    GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "sqlite_close");
      FREE (h);
    }
  FREE (handles);
  handles = NULL;
  handle_count = 0;
  FREE (fn);
  fn = NULL;
}

/**
 * Delete the database.  The next operation is
 * guaranteed to be unloading of the module.
 */
static void
drop ()
{
  char *n = STRDUP (fn);
  sqlite_shutdown ();
  UNLINK (n);
  FREE (n);
}


/**
 * Iterate over all entries matching a particular key and
 * type.
 *
 * @param key maybe NULL (to match all entries)
 * @param type entries of which type are relevant?
 *     Use 0 for any type.
 * @param iter maybe NULL (to just count)
 * @return the number of results, SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int
get (const HashCode512 * key,
     unsigned int type, Datum_Iterator iter, void *closure)
{
  int ret;
  int count = 0;
  sqlite3_stmt *stmt;
  char scratch[256];
  Datastore_Value *datum;
  sqlite3 *dbh;
  sqliteHandle *handle;
  HashCode512 rkey;
  unsigned long long last_rowid;
  unsigned long long rowid;

  if (key == NULL)
    return iterateLowPriority (type, iter, closure);
  MUTEX_LOCK (lock);
  handle = getDBHandle ();
  dbh = handle->dbh;
  strcpy (scratch, "SELECT ");
  if (iter == NULL)
    strcat (scratch, "count(*)");
  else
    strcat (scratch,
            "size, type, prio, anonLevel, expire, hash, value, _ROWID_");
  strcat (scratch, " FROM gn070 WHERE hash = :1 AND _ROWID_ > :2");
  if (type)
    strcat (scratch, " AND type = :3");
  strcat (scratch, " ORDER BY _ROWID_ ASC LIMIT 1");
  if (sq_prepare (dbh, scratch, &stmt) != SQLITE_OK)
    {
      LOG_SQLITE (handle,
                  GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "sqlite_prepare");
      MUTEX_UNLOCK (lock);
      return SYSERR;
    }
  count = 0;
  last_rowid = 0;
  while (1)
    {
      ret = sqlite3_bind_blob (stmt,
                               1,
                               key, sizeof (HashCode512), SQLITE_TRANSIENT);
      if (ret == SQLITE_OK)
        ret = sqlite3_bind_int64 (stmt, 2, last_rowid);
      if (type && (ret == SQLITE_OK))
        ret = sqlite3_bind_int (stmt, 3, type);
      if (ret == SQLITE_OK)
        {
          ret = sqlite3_step (stmt);
          if (ret != SQLITE_ROW)
            break;
          if (iter == NULL)
            {
              count = sqlite3_column_int (stmt, 0);
              sqlite3_reset (stmt);
              sqlite3_finalize (stmt);
              MUTEX_UNLOCK (lock);
              return count;
            }
          datum = assembleDatum (handle, stmt, &rkey, &rowid);
          last_rowid = rowid;
          sqlite3_reset (stmt);
          if (datum == NULL)
            continue;
          if ((key != NULL) &&
              (0 != memcmp (&rkey, key, sizeof (HashCode512))))
            {
              GE_BREAK (NULL, 0);
              FREE (datum);
              continue;
            }
          MUTEX_UNLOCK (lock);
          ret = iter (&rkey, datum, closure, rowid);
          MUTEX_LOCK (lock);
          if (ret == SYSERR)
            {
              count = SYSERR;
              FREE (datum);
              ret = SQLITE_DONE;
              break;
            }
          if (ret == NO)
            {
              payload -= getContentDatastoreSize (datum);
              delete_by_rowid (handle, rowid);
            }
          FREE (datum);
          count++;
        }
    }
  sqlite3_reset (stmt);
  sqlite3_finalize (stmt);
  MUTEX_UNLOCK (lock);
  return count;
}

/**
 * Write content to the db.  Always adds a new record
 * (does NOT overwrite existing data).
 *
 * @return SYSERR on error, NO on temporary error, OK if ok.
 */
static int
put (const HashCode512 * key, const Datastore_Value * value)
{
  int n;
  sqlite3_stmt *stmt;
  unsigned int contentSize;
  unsigned int size, type, prio, anon;
  unsigned long long expir;
  sqliteHandle *dbh;
#if DEBUG_SQLITE
  EncName enc;

  IF_GELOG (ectx, GE_DEBUG | GE_BULK | GE_USER, hash2enc (key, &enc));
  GE_LOG (ectx,
          GE_DEBUG | GE_BULK | GE_USER,
          "Storing in database block with type %u/key `%s'/priority %u/expiration %llu.\n",
          ntohl (*(int *) &value[1]),
          &enc, ntohl (value->prio), ntohll (value->expirationTime));
#endif

  if ((ntohl (value->size) < sizeof (Datastore_Value)))
    {
      GE_BREAK (ectx, 0);
      return SYSERR;
    }
  MUTEX_LOCK (lock);
  dbh = getDBHandle ();
  if (lastSync > 1000)
    syncStats (dbh);
  contentSize = ntohl (value->size) - sizeof (Datastore_Value);
  stmt = dbh->insertContent;
  size = ntohl (value->size);
  type = ntohl (value->type);
  prio = ntohl (value->prio);
  anon = ntohl (value->anonymityLevel);
  expir = ntohll (value->expirationTime);
  if ((SQLITE_OK != sqlite3_bind_int (stmt, 1, size)) ||
      (SQLITE_OK != sqlite3_bind_int (stmt, 2, type)) ||
      (SQLITE_OK != sqlite3_bind_int (stmt, 3, prio)) ||
      (SQLITE_OK != sqlite3_bind_int (stmt, 4, anon)) ||
      (SQLITE_OK != sqlite3_bind_int64 (stmt, 5, expir)) ||
      (SQLITE_OK !=
       sqlite3_bind_blob (stmt, 6, key, sizeof (HashCode512),
                          SQLITE_TRANSIENT))
      || (SQLITE_OK !=
          sqlite3_bind_blob (stmt, 7, &value[1], contentSize,
                             SQLITE_TRANSIENT)))
    {
      LOG_SQLITE (dbh,
                  GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
                  "sqlite3_bind_XXXX");
      if (SQLITE_OK != sqlite3_reset (stmt))
        LOG_SQLITE (dbh,
                    GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "sqlite3_reset");
      MUTEX_UNLOCK (lock);
      return SYSERR;
    }

  n = sqlite3_step (stmt);
  if (n != SQLITE_DONE)
    {
      if (n == SQLITE_BUSY)
        {
          sqlite3_reset (stmt);
          MUTEX_UNLOCK (lock);
          return NO;
        }
      LOG_SQLITE (dbh,
                  GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "sqlite3_step");
      sqlite3_reset (stmt);
      MUTEX_UNLOCK (lock);
      return SYSERR;
    }
  if (SQLITE_OK != sqlite3_reset (stmt))
    LOG_SQLITE (dbh,
                GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "sqlite3_reset");
  lastSync++;
  payload += getContentDatastoreSize (value);
#if DEBUG_SQLITE
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER, "SQLite: done writing content\n");
#endif
  MUTEX_UNLOCK (lock);
  return OK;
}

/**
 * Update the priority for a particular key
 * in the datastore.
 */
static int
update (unsigned long long uid, int delta, cron_t expire)
{
  int n;
  sqliteHandle *dbh;

  MUTEX_LOCK (lock);
  dbh = getDBHandle ();
  sqlite3_bind_int (dbh->updPrio, 1, delta);
  sqlite3_bind_int64 (dbh->updPrio, 2, expire);
  sqlite3_bind_int64 (dbh->updPrio, 3, uid);
  n = sqlite3_step (dbh->updPrio);
  if (n != SQLITE_DONE)
    LOG_SQLITE (dbh, GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "sqlite3_step");

  sqlite3_reset (dbh->updPrio);

#if DEBUG_SQLITE
  GE_LOG (ectx, GE_DEBUG | GE_REQUEST | GE_USER, "SQLite: block updated\n");
#endif
  MUTEX_UNLOCK (lock);
  if (n == SQLITE_BUSY)
    return NO;
  return n == SQLITE_OK ? OK : SYSERR;
}

SQstore_ServiceAPI *
provide_module_sqstore_sqlite (CoreAPIForApplication * capi)
{
  static SQstore_ServiceAPI api;

  char *dir;
  char *afsdir;
  sqliteHandle *dbh;

  ectx = capi->ectx;
#if DEBUG_SQLITE
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER, "SQLite: initializing database\n");
#endif

  payload = 0;
  lastSync = 0;

  afsdir = NULL;
  GC_get_configuration_value_filename (capi->cfg,
                                       "FS",
                                       "DIR",
                                       VAR_DAEMON_DIRECTORY "/data/fs/",
                                       &afsdir);
  dir = MALLOC (strlen (afsdir) + strlen ("/content/gnunet.dat") + 2);
  strcpy (dir, afsdir);
  strcat (dir, "/content/gnunet.dat");
  FREE (afsdir);
  if (OK != disk_directory_create_for_file (ectx, dir))
    {
      GE_BREAK (ectx, 0);
      FREE (dir);
      return NULL;
    }
  fn = dir;
  dbh = getDBHandle ();
  if (dbh == NULL)
    {
      GE_BREAK (ectx, 0);
      FREE (fn);
      fn = NULL;
      return NULL;
    }

  payload = getStat (dbh, "PAYLOAD");
  if (payload == SYSERR)
    {
      GE_BREAK (ectx, 0);
      LOG_SQLITE (dbh,
                  GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "sqlite_payload");
      MUTEX_DESTROY (lock);
      FREE (fn);
      fn = NULL;
      return NULL;
    }
  lock = MUTEX_CREATE (NO);
  coreAPI = capi;
  stats = coreAPI->requestService ("stats");
  if (stats)
    stat_size = stats->create (gettext_noop ("# bytes in datastore"));

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
    coreAPI->releaseService (stats);
  sqlite_shutdown ();
#if DEBUG_SQLITE
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER, "SQLite: database shutdown\n");
#endif
  MUTEX_DESTROY (lock);
  lock = NULL;
  coreAPI = NULL;
}



/**
 * Update sqlite database module.
 *
 * Currently only makes sure that the sqlite indices are created.
 */
void
update_module_sqstore_sqlite (UpdateAPI * uapi)
{
  sqliteHandle *dbh;
  char *dir;
  char *afsdir;

  payload = 0;
  lastSync = 0;
  afsdir = NULL;
  GC_get_configuration_value_filename (uapi->cfg,
                                       "FS",
                                       "DIR",
                                       VAR_DAEMON_DIRECTORY "/data/fs/",
                                       &afsdir);
  dir = MALLOC (strlen (afsdir) + 8 + 2);       /* 8 = "content/" */
  strcpy (dir, afsdir);
  strcat (dir, "/content/");
  FREE (afsdir);
  if (OK != disk_directory_create (ectx, dir))
    {
      FREE (dir);
      return;
    }
  fn = dir;
  lock = MUTEX_CREATE (NO);
  dbh = getDBHandle ();
  if (dbh == NULL)
    {
      MUTEX_DESTROY (lock);
      FREE (fn);
      fn = NULL;
      return;
    }
  createIndices (dbh->dbh);
  sqlite_shutdown ();
  MUTEX_DESTROY (lock);
}

/* end of sqlite.c */
