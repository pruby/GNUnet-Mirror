/*
     This file is part of GNUnet.
     (C) 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/sqstore_postgres/postgres.c
 * @brief Postgres based implementation of the sqstore service
 * @author Christian Grothoff
 *
 * Database: Postgres
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_util.h"
#include "gnunet_sqstore_service.h"
#include "gnunet_protocols.h"
#include "gnunet_stats_service.h"
#include <postgresql/libpq-fe.h>

#define DEBUG_POSTGRES GNUNET_NO

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define DIE_POSTGRES(cmd) do { GNUNET_GE_LOG(ectx, GNUNET_GE_FATAL | GNUNET_GE_IMMEDIATE | GNUNET_GE_ADMIN, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, PQerrorMessage(dbh)); abort(); } while(0)

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_POSTGRES(level, cmd) do { GNUNET_GE_LOG(ectx, level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, PQerrorMessage(dbh)); } while(0)

#define SELECT_IT_LOW_PRIORITY_1 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (prio = $1 AND hash > $2) "\
  "ORDER BY hash ASC LIMIT 1"

#define SELECT_IT_LOW_PRIORITY_2 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (prio > $1) "\
  "ORDER BY prio ASC, hash ASC LIMIT 1"

#define SELECT_IT_NON_ANONYMOUS_1 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (prio = $1 AND hash < $2 AND anonLevel = 0) "\
  " ORDER BY hash DESC LIMIT 1"

#define SELECT_IT_NON_ANONYMOUS_2 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (prio < $1 AND anonLevel = 0)"\
  " ORDER BY prio DESC, hash DESC LIMIT 1"

#define SELECT_IT_EXPIRATION_TIME_1 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (expire = $1 AND hash > $2) "\
  " ORDER BY hash ASC LIMIT 1"

#define SELECT_IT_EXPIRATION_TIME_2 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (expire > $1) "\
  " ORDER BY expire ASC, hash ASC LIMIT 1"

#define SELECT_IT_MIGRATION_ORDER_1 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (expire = $1 AND hash < $2) "\
  " ORDER BY hash DESC LIMIT 1"

#define SELECT_IT_MIGRATION_ORDER_2 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (expire < $1) "\
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
 * Native Postgres database handle.
 */
static PGconn *dbh;

static GNUNET_Stats_ServiceAPI *stats;

static GNUNET_CoreAPIForPlugins *coreAPI;

static unsigned int stat_size;

#if DEBUG_POSTGRES
static unsigned int stat_mem;
#endif

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_Mutex *lock;

static char *fn;

static unsigned long long payload;

static unsigned int lastSync;

/**
 * @brief Prepare a SQL statement
 */
static int
pq_prepare (const char *zSql, int nParams,
	    const Oid * paramTypes)
{
  PGresult * ret;
  ret = PQprepare (dbh,
		   zSql,
		   zSql,
		   nParams,
		   paramTypes);
  if (ret == NULL)
    {
      GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
		    _("PQprepare failed (returning NULL)\n"));
      return GNUNET_SYSERR;
    }
  if (PQresultStatus(res) != PGRES_COMMAND_OK)
    {
      LOG_POSTGRES (GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
		    "PQprepare");
      PQclear (ret);
      return GNUNET_SYSERR;
    }
  PQclear (ret);
  return GNUNET_OK;
}

/**
 * Run simple SQL statement (without results).
 */
static int
pq_exec (const char * sql)
{
  PGresult * ret;
  ret = PQexec (dbh, sql);
  if (ret == NULL)
    {
      /* FIXME: report error! */
      return GNUNET_SYSERR;
    }
  if (PQresultStatus (res) != PGRES_COMMAND_OK)
    {
      LOG_POSTGRES (GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
		    "PQexec");
      PQclear(ret);
      return GNUNET_SYSERR;
    }
  PQclear(ret);
  return GNUNET_OK;
}

/**
 * Create indices 
 */
static int
create_indices ()
{
  if ( (GNUNET_OK != 
	pq_exec ("CREATE INDEX idx_hash ON gn080 (hash)")) ||
       (GNUNET_OK != 
	pq_exec ("CREATE INDEX idx_hash_vhash ON gn080 (hash,vhash)"))  ||
       (GNUNET_OK !=
	pq_exec ("CREATE INDEX idx_prio ON gn080 (prio)")) ||
       (GNUNET_OK !=
	pq_exec ("CREATE INDEX idx_expire ON gn080 (expire)")) ||
       (GNUNET_OK !=
	pq_exec ("CREATE INDEX idx_comb3 ON gn080 (prio,anonLevel)")) ||
       (GNUNET_OK !=
	pq_exec ("CREATE INDEX idx_comb4 ON gn080 (prio,hash,anonLevel)")) ||
       (GNUNET_OK !=
	pq_exec ("CREATE INDEX idx_comb7 ON gn080 (expire,hash)")) )
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

/**
 * @brief Get a database handle
 * @return the native Postgres database handle, NULL on error
 */
static PGconn *
init_connection ()
{
  char * conninfo;

  /* Open database and precompile statements */
  conninfo = NULL;
  GNUNET_GC_get_configuration_value_string (coreAPI->cfg,
					    "POSTGRES", "CONFIG", "connect_timeout=10",
					    &conninfo);
  dbh = PQconnectdb(conninfo);
  GNUNET_free (conninfo);
  if (dbh == NULL)
    {
      /* FIXME: warn about out-of-memory? */
      return NULL;
    }
  if (PQstatus(dbh) != CONNECTION_OK)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Unable to initialize Postgres: %s.\n"),
                     PQerrorMessage (dbh));
      PQfinish (dbh);
      dbh = NULL;
      return NULL;
    }
  
  if ( (GNUNET_OK !=
	pq_exec ("CREATE TABLE gn080 ("
		 "  size INTEGER NOT NULL DEFAULT 0,"
		 "  type INTEGER NOT NULL DEFAULT 0,"
		 "  prio INTEGER NOT NULL DEFAULT 0,"
		 "  anonLevel INTEGER NOT NULL DEFAULT 0,"
		 "  expire BIGINT NOT NULL DEFAULT 0,"
		 "  hash BYTEA NOT NULL DEFAULT '',"
		 "  vhash BYTEA NOT NULL DEFAULT '',"
		 "  value BYTEA NOT NULL DEFAULT '')")) ||
       (GNUNET_OK !=
	create_indices () ) )
    {
      PQfinish (dbh);
      dbh = NULL;
      return NULL;
    }
  /* FIXME: prepare statements! */
  
  return dbh;
}


/**
 * Get an estimate of the size of the given
 * value (and its key) in the datastore.<p>
 */
static unsigned int
getContentDatastoreSize (const GNUNET_DatastoreValue * value)
{
  return sizeof (GNUNET_HashCode) * 2 + ntohl (value->size) -
    sizeof (GNUNET_DatastoreValue) + 24;
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
#if DEBUG_POSTGRES
      stats->set (stat_mem, postgres3_memory_used ());
#endif
    }
  GNUNET_mutex_unlock (lock);
  return (unsigned long long) (ret * 1.00);
  /* benchmarking shows XX% overhead */
}

///////////////////////////////////////////////

static int
delete_by_rowid (postgresHandle * handle, unsigned long long rid)
{
  postgres3_stmt *stmt;

  if (sq_prepare (handle->dbh,
                  "DELETE FROM gn080 WHERE _ROWID_ = ?", &stmt) != POSTGRES_OK)
    {
      LOG_POSTGRES (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "sq_prepare");
      return GNUNET_SYSERR;
    }
  postgres3_bind_int64 (stmt, 1, rid);
  if (POSTGRES_DONE != postgres3_step (stmt))
    {
      LOG_POSTGRES (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "postgres3_step");
      postgres3_finalize (stmt);
      return GNUNET_SYSERR;
    }
  postgres3_finalize (stmt);
  return GNUNET_OK;
}

/**
 * Given a full row from gn080 table (size,type,priority,anonLevel,expire,GNUNET_hash,value),
 * assemble it into a GNUNET_DatastoreValue representation.
 */
static GNUNET_DatastoreValue *
assembleDatum (postgresHandle * handle, postgres3_stmt * stmt,
               GNUNET_HashCode * key, unsigned long long *rowid)
{
  GNUNET_DatastoreValue *value;
  int contentSize;
  postgres3 *dbh;
  unsigned int type;
  postgres3_stmt *stmtd;

  *rowid = postgres3_column_int64 (stmt, 7);
  type = postgres3_column_int (stmt, 1);
  contentSize = postgres3_column_int (stmt, 0) - sizeof (GNUNET_DatastoreValue);
  dbh = handle->dbh;
  if (contentSize < 0)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("Invalid data in %s.  Trying to fix (by deletion).\n"),
                     _("postgres datastore"));
      if (POSTGRES_OK != postgres3_reset (stmt))
        LOG_POSTGRES (handle,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "postgres3_reset");
      if (sq_prepare (dbh, "DELETE FROM gn080 WHERE size < ?", &stmtd) !=
          POSTGRES_OK)
        {
          LOG_POSTGRES (handle,
                      GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                      GNUNET_GE_BULK, "sq_prepare");
          return NULL;
        }
      if (POSTGRES_OK !=
          postgres3_bind_int (stmtd, 1, sizeof (GNUNET_DatastoreValue)))
        LOG_POSTGRES (handle,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "postgres3_bind_int");
      if (POSTGRES_DONE != postgres3_step (stmtd))
        LOG_POSTGRES (handle,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "postgres3_step");
      if (POSTGRES_OK != postgres3_finalize (stmtd))
        LOG_POSTGRES (handle,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "postgres3_finalize");
      return NULL;              /* error */
    }

  if (postgres3_column_bytes (stmt, 5) != sizeof (GNUNET_HashCode) ||
      postgres3_column_bytes (stmt, 6) != contentSize)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Invalid data in %s.  Trying to fix (by deletion).\n"),
                     _("postgres datastore"));
      if (POSTGRES_OK != postgres3_reset (stmt))
        LOG_POSTGRES (handle,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "postgres3_reset");
      if (sq_prepare
          (dbh,
           "DELETE FROM gn080 WHERE NOT ((LENGTH(hash) = ?) AND (size = LENGTH(value) + ?))",
           &stmtd) != POSTGRES_OK)
        {
          LOG_POSTGRES (handle,
                      GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                      GNUNET_GE_BULK, "sq_prepare");
          return NULL;
        }

      if (POSTGRES_OK != postgres3_bind_int (stmtd, 1, sizeof (GNUNET_HashCode)))
        LOG_POSTGRES (handle,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "postgres3_bind_int");
      if (POSTGRES_OK !=
          postgres3_bind_int (stmtd, 2, sizeof (GNUNET_DatastoreValue)))
        LOG_POSTGRES (handle,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "postgres3_bind_int");
      if (POSTGRES_DONE != postgres3_step (stmtd))
        LOG_POSTGRES (handle,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "postgres3_step");
      if (POSTGRES_OK != postgres3_finalize (stmtd))
        LOG_POSTGRES (handle,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "postgres3_finalize");
      return NULL;
    }

  value = GNUNET_malloc (sizeof (GNUNET_DatastoreValue) + contentSize);
  value->size = htonl (contentSize + sizeof (GNUNET_DatastoreValue));
  value->type = htonl (type);
  value->priority = htonl (postgres3_column_int (stmt, 2));
  value->anonymity_level = htonl (postgres3_column_int (stmt, 3));
  value->expiration_time = GNUNET_htonll (postgres3_column_int64 (stmt, 4));
  memcpy (key, postgres3_column_blob (stmt, 5), sizeof (GNUNET_HashCode));
  memcpy (&value[1], postgres3_column_blob (stmt, 6), contentSize);
  return value;
}


/**
 * @brief Get database statistics
 * @param key kind of stat to retrieve
 * @return GNUNET_SYSERR on error, the value otherwise
 */
static unsigned long long
getStat (const char *key)
{
  int i;
  postgres3_stmt *stmt;
  unsigned long long ret = GNUNET_SYSERR;

  i = sq_prepare (handle->dbh,
                  "SELECT value FROM gn071 WHERE key = ?", &stmt);
  if (i == POSTGRES_OK)
    {
      postgres3_bind_text (stmt, 1, key, strlen (key), POSTGRES_STATIC);
      i = postgres3_step (stmt);

      if (i == POSTGRES_DONE)
        {
          ret = 0;
          i = POSTGRES_OK;
        }
      else if (i == POSTGRES_ROW)
        {
          ret = postgres3_column_int64 (stmt, 0);
          i = POSTGRES_OK;
        }
      postgres3_finalize (stmt);
    }
  if (i == POSTGRES_BUSY)
    return GNUNET_SYSERR;
  if (i != POSTGRES_OK)
    {
      LOG_POSTGRES (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "postgres_getStat");
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
setStat (postgresHandle * handle, const char *key, unsigned long long val)
{
  postgres3_stmt *stmt;
  postgres3 *dbh;

  dbh = handle->dbh;
  if (sq_prepare (dbh, "DELETE FROM gn071 where key = ?", &stmt) == POSTGRES_OK)
    {
      postgres3_bind_text (stmt, 1, key, strlen (key), POSTGRES_STATIC);
      if (POSTGRES_DONE != postgres3_step (stmt))
        LOG_POSTGRES (handle,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "postgres3_step");

      postgres3_finalize (stmt);
    }

  if (sq_prepare (dbh,
                  "INSERT INTO gn071(key, value) VALUES (?, ?)",
                  &stmt) != POSTGRES_OK)
    return GNUNET_SYSERR;
  if ((POSTGRES_OK !=
       postgres3_bind_text (stmt, 1, key, strlen (key), POSTGRES_STATIC))
      || (POSTGRES_OK != postgres3_bind_int64 (stmt, 2, val)))
    {
      LOG_POSTGRES (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "postgres3_bind_xxx");
      postgres3_finalize (stmt);
      return GNUNET_SYSERR;
    }
  if (postgres3_step (stmt) != POSTGRES_DONE)
    {
      LOG_POSTGRES (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "postgres3_step");
      postgres3_finalize (stmt);
      return GNUNET_SYSERR;
    }
  postgres3_finalize (stmt);

  return GNUNET_OK;
}

/**
 * @brief write all statistics to the db
 */
static void
syncStats (postgresHandle * handle)
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
postgres_iterate (unsigned int type,
                int is_asc,
                int is_prio,
                int is_migr,
                int limit_nonanonymous,
                const char *stmt_str_1,
                const char *stmt_str_2,
                GNUNET_DatastoreValueIterator iter, void *closure)
{
  postgres3_stmt *stmt_1;
  postgres3_stmt *stmt_2;
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
  int ret;
  GNUNET_CronTime now;
  unsigned long long rowid;
  unsigned long long rowid_1;
  unsigned long long rowid_2;

  GNUNET_mutex_lock (lock);
  if (sq_prepare (dbh, stmt_str_1, &stmt_1) != POSTGRES_OK)
    {
      LOG_POSTGRES (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "postgres3_prepare");
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  if (sq_prepare (dbh, stmt_str_2, &stmt_2) != POSTGRES_OK)
    {
      LOG_POSTGRES (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "postgres3_prepare");
      postgres3_finalize (stmt_1);
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
          postgres3_bind_int (stmt_1, 1, lastPrio);
          postgres3_bind_int (stmt_2, 1, lastPrio);
        }
      else
        {
          postgres3_bind_int64 (stmt_1, 1, lastExp);
          postgres3_bind_int64 (stmt_2, 1, lastExp);
        }
      postgres3_bind_blob (stmt_1, 2, &key, sizeof (GNUNET_HashCode),
                         POSTGRES_TRANSIENT);
      now = GNUNET_get_time ();
      datum_1 = NULL;
      datum_2 = last_datum_2;
      last_datum_2 = NULL;
      if ((ret = postgres3_step (stmt_1)) == POSTGRES_ROW)
        {
          if (is_migr && postgres3_column_int64 (stmt_1, 4) < now)
            datum_1 = NULL;
          else
            datum_1 = assembleDatum (handle, stmt_1, &key_1, &rowid_1);
          if (POSTGRES_OK != postgres3_reset (stmt_1))
            LOG_POSTGRES (handle,
                        GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                        GNUNET_GE_BULK, "postgres3_reset");
        }
      else
        {
          if (ret != POSTGRES_DONE)
            {
              LOG_POSTGRES (handle,
                          GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                          GNUNET_GE_BULK, "postgres3_step");
              postgres3_finalize (stmt_1);
              postgres3_finalize (stmt_2);
              GNUNET_mutex_unlock (lock);
              return GNUNET_SYSERR;
            }
          postgres3_reset (stmt_1);
        }

      if (datum_2 == NULL)
        {
          if ((ret = postgres3_step (stmt_2)) == POSTGRES_ROW)
            {
              if (is_migr && postgres3_column_int64 (stmt_2, 4) < now)
                datum_2 = NULL;
              else
                datum_2 = assembleDatum (handle, stmt_2, &key_2, &rowid_2);
              if (POSTGRES_OK != postgres3_reset (stmt_2))
                LOG_POSTGRES (handle,
                            GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER
                            | GNUNET_GE_BULK, "postgres3_reset");
            }
          else
            {
              if (ret != POSTGRES_DONE)
                {
                  LOG_POSTGRES (handle,
                              GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                              GNUNET_GE_USER | GNUNET_GE_BULK,
                              "postgres3_step");
                  postgres3_finalize (stmt_1);
                  postgres3_finalize (stmt_2);
                  GNUNET_mutex_unlock (lock);
                  GNUNET_free_non_null (datum_1);
                  return GNUNET_SYSERR;
                }
              postgres3_reset (stmt_2);
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
  postgres3_finalize (stmt_1);
  postgres3_finalize (stmt_2);
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
  return postgres_iterate (type, GNUNET_YES, GNUNET_YES, GNUNET_NO, GNUNET_NO,
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
  return postgres_iterate (type, GNUNET_NO, GNUNET_YES, GNUNET_NO, GNUNET_YES,
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
  return postgres_iterate (type, GNUNET_YES, GNUNET_NO, GNUNET_NO, GNUNET_NO,
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
  return postgres_iterate (0, GNUNET_NO, GNUNET_NO, GNUNET_YES, GNUNET_NO,
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
  postgres3_stmt *stmt;
  int count;
  GNUNET_DatastoreValue *datum;
  int ret;
  unsigned long long newpayload;
  unsigned long long rowid;
  unsigned long long last_rowid;
  GNUNET_HashCode key;

  newpayload = 0;
  GNUNET_mutex_lock (lock);
  /* For the rowid trick see
     http://permalink.gmane.org/gmane.network.gnunet.devel/1363 */
  if (sq_prepare (dbh,
                  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_"
                  " FROM gn080 WHERE _ROWID_ > :1 ORDER BY _ROWID_ ASC LIMIT 1",
                  &stmt) != POSTGRES_OK)
    {
      LOG_POSTGRES (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "postgres3_prepare");
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  count = 0;
  last_rowid = 0;
  while (1)
    {
      ret = postgres3_bind_int64 (stmt, 1, last_rowid);
      if (ret != POSTGRES_OK)
        break;
      if (postgres3_step (stmt) != POSTGRES_ROW)
        break;
      datum = assembleDatum (handle, stmt, &key, &rowid);
#if 0
      printf ("IA-FOUND %4u prio %4u exp %20llu RID %llu old-RID: %llu\n",
              (ntohl (datum->size) - sizeof (GNUNET_DatastoreValue)),
              ntohl (datum->priority),
              GNUNET_ntohll (datum->expiration_time), rowid, last_rowid);
#endif
      last_rowid = rowid;
      postgres3_reset (stmt);
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
  postgres3_reset (stmt);
  postgres3_finalize (stmt);
  if (count != GNUNET_SYSERR)
    {
      /* re-computed payload! */
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_IMMEDIATE | GNUNET_GE_USER |
                     GNUNET_GE_ADMIN,
                     "Postgres database size recomputed.  New estimate is %llu, old estimate was %llu\n",
                     newpayload, payload);
      payload = newpayload;
      syncStats (handle);
    }
  GNUNET_mutex_unlock (lock);
  return count;
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
  postgres3_stmt *stmt;
  char scratch[256];
  GNUNET_DatastoreValue *datum;
  postgres3 *dbh;
  GNUNET_HashCode rkey;
  unsigned long long last_rowid;
  unsigned long long rowid;
  int sqoff;

  if (key == NULL)
    return iterateLowPriority (type, iter, closure);
  GNUNET_mutex_lock (lock);

  GNUNET_snprintf (scratch, 256,
                   "SELECT count(*) FROM gn080 WHERE hash=:1%s%s",
                   vhash == NULL ? "" : " AND vhash=:2",
                   type == 0 ? "" : (vhash ==
                                     NULL) ? " AND type=:2" : " AND type=:3");
  if (sq_prepare (dbh, scratch, &stmt) != POSTGRES_OK)
    {
      LOG_POSTGRES (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "postgres_prepare");
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  sqoff = 1;
  ret = postgres3_bind_blob (stmt,
                           sqoff++,
                           key, sizeof (GNUNET_HashCode), POSTGRES_TRANSIENT);
  if ((vhash != NULL) && (ret == POSTGRES_OK))
    ret = postgres3_bind_blob (stmt,
                             sqoff++,
                             vhash,
                             sizeof (GNUNET_HashCode), POSTGRES_TRANSIENT);
  if ((type != 0) && (ret == POSTGRES_OK))
    ret = postgres3_bind_int (stmt, sqoff++, type);
  if (ret != POSTGRES_OK)
    {
      LOG_POSTGRES (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "postgres_bind");
      postgres3_reset (stmt);
      postgres3_finalize (stmt);
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;

    }
  ret = postgres3_step (stmt);
  if (ret != POSTGRES_ROW)
    {
      LOG_POSTGRES (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "postgres_step");
      postgres3_reset (stmt);
      postgres3_finalize (stmt);
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;

    }
  total = postgres3_column_int (stmt, 0);
  postgres3_reset (stmt);
  postgres3_finalize (stmt);
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
  if (sq_prepare (dbh, scratch, &stmt) != POSTGRES_OK)
    {
      LOG_POSTGRES (handle,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "postgres_prepare");
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
      ret = postgres3_bind_blob (stmt,
                               sqoff++,
                               key, sizeof (GNUNET_HashCode),
                               POSTGRES_TRANSIENT);
      if ((vhash != NULL) && (ret == POSTGRES_OK))
        ret = postgres3_bind_blob (stmt,
                                 sqoff++,
                                 vhash,
                                 sizeof (GNUNET_HashCode), POSTGRES_TRANSIENT);
      if ((type != 0) && (ret == POSTGRES_OK))
        ret = postgres3_bind_int (stmt, sqoff++, type);
      if (ret == POSTGRES_OK)
        ret = postgres3_bind_int64 (stmt, sqoff++, last_rowid);
      if (ret == POSTGRES_OK)
        ret = postgres3_bind_int (stmt, sqoff++, limit_off);
      if (ret == POSTGRES_OK)
        {
          ret = postgres3_step (stmt);
          if (ret != POSTGRES_ROW)
            break;
          datum = assembleDatum (handle, stmt, &rkey, &rowid);
          last_rowid = rowid + 1;
          postgres3_reset (stmt);
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
              ret = POSTGRES_DONE;
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
  postgres3_reset (stmt);
  postgres3_finalize (stmt);
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
  postgres3_stmt *stmt;
  unsigned int contentSize;
  unsigned int size, type, prio, anon;
  unsigned long long expir;
  GNUNET_HashCode vhash;
  postgresHandle *dbh;
#if DEBUG_POSTGRES
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
  if (lastSync > 1000)
    syncStats (dbh);
  stmt = dbh->insertContent;
  if ((POSTGRES_OK != postgres3_bind_int (stmt, 1, size)) ||
      (POSTGRES_OK != postgres3_bind_int (stmt, 2, type)) ||
      (POSTGRES_OK != postgres3_bind_int (stmt, 3, prio)) ||
      (POSTGRES_OK != postgres3_bind_int (stmt, 4, anon)) ||
      (POSTGRES_OK != postgres3_bind_int64 (stmt, 5, expir)) ||
      (POSTGRES_OK !=
       postgres3_bind_blob (stmt, 6, key, sizeof (GNUNET_HashCode),
                          POSTGRES_TRANSIENT)) ||
      (POSTGRES_OK !=
       postgres3_bind_blob (stmt, 7, &vhash, sizeof (GNUNET_HashCode),
                          POSTGRES_TRANSIENT))
      || (POSTGRES_OK !=
          postgres3_bind_blob (stmt, 8, &value[1], contentSize,
                             POSTGRES_TRANSIENT)))
    {
      LOG_POSTGRES (dbh,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "postgres3_bind_XXXX");
      if (POSTGRES_OK != postgres3_reset (stmt))
        LOG_POSTGRES (dbh,
                    GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                    GNUNET_GE_BULK, "postgres3_reset");
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }

  n = postgres3_step (stmt);
  if (n != POSTGRES_DONE)
    {
      if (n == POSTGRES_BUSY)
        {
          postgres3_reset (stmt);
          GNUNET_mutex_unlock (lock);
          GNUNET_GE_BREAK (NULL, 0);
          return GNUNET_NO;
        }
      LOG_POSTGRES (dbh,
                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                  GNUNET_GE_BULK, "postgres3_step");
      postgres3_reset (stmt);
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  if (POSTGRES_OK != postgres3_reset (stmt))
    LOG_POSTGRES (dbh,
                GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                GNUNET_GE_BULK, "postgres3_reset");
  lastSync++;
  payload += getContentDatastoreSize (value);
#if DEBUG_POSTGRES
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Postgres: done writing content\n");
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

  GNUNET_mutex_lock (lock);
  postgres3_bind_int (dbh->updPrio, 1, delta);
  postgres3_bind_int64 (dbh->updPrio, 2, expire);
  postgres3_bind_int64 (dbh->updPrio, 3, uid);
  n = postgres3_step (dbh->updPrio);
  if (n != POSTGRES_DONE)
    LOG_POSTGRES (dbh,
                GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                GNUNET_GE_BULK, "postgres3_step");

  postgres3_reset (dbh->updPrio);

#if DEBUG_POSTGRES
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Postgres: block updated\n");
#endif
  GNUNET_mutex_unlock (lock);
  if (n == POSTGRES_BUSY)
    return GNUNET_NO;
  return n == POSTGRES_OK ? GNUNET_OK : GNUNET_SYSERR;
}

///////////////////////////////////////


static void
postgres_shutdown ()
{
  if (dbh == NULL)
    return; /* already down */
#if DEBUG_POSTGRES
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Postgres: closing database\n");
#endif
  syncStats ();
  PQfinish (dbh);
  dbh = NULL;
}

/**
 * Delete the database.  The next operation is
 * guaranteed to be unloading of the module.
 */
static void
drop ()
{
  pq_exec ("DROP TABLE gn080");
  postgres_shutdown ();
}


GNUNET_SQstore_ServiceAPI *
provide_module_sqstore_postgres (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_SQstore_ServiceAPI api;

  ectx = capi->ectx;
#if DEBUG_POSTGRES
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Postgres: initializing database\n");
#endif

  payload = 0;
  lastSync = 0;
  dbh = init_connection ();
  if (dbh == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return NULL;
    }
  payload = getStat ("PAYLOAD");
  if (payload == GNUNET_SYSERR)
    {
      GNUNET_GE_BREAK (ectx, 0);
      LOG_POSTGRES (GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
		    GNUNET_GE_BULK, "postgres_payload");
      GNUNET_mutex_destroy (lock);
      return NULL;
    }
  lock = GNUNET_mutex_create (GNUNET_NO);
  coreAPI = capi;
  stats = coreAPI->service_request ("stats");
  if (stats)
    {
      stat_size = stats->create (gettext_noop ("# bytes in datastore"));
#if DEBUG_POSTGRES
      stat_mem = stats->create (gettext_noop ("# bytes allocated by Postgres"));
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
release_module_sqstore_postgres ()
{
  if (stats != NULL)
    coreAPI->service_release (stats);
  postgres_shutdown ();
#if DEBUG_POSTGRES
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Postgres: database shutdown\n");
#endif
  GNUNET_mutex_destroy (lock);
  lock = NULL;
  coreAPI = NULL;
}



/**
 * Update postgres database module.
 *
 * Currently only makes sure that the postgres indices are created.
 */
void
update_module_sqstore_postgres (GNUNET_UpdateAPI * uapi)
{
  payload = 0;
  lastSync = 0;
  lock = GNUNET_mutex_create (GNUNET_NO);
  dbh = init_connection ();
  if (dbh == NULL)
    {
      GNUNET_mutex_destroy (lock);
      GNUNET_free (fn);
      fn = NULL;
      return;
    }
  create_indices ();
  postgres_shutdown ();
  GNUNET_mutex_destroy (lock);
}

/* end of postgres.c */
