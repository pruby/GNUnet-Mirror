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

#define SELECT_IT_LOW_PRIORITY "(SELECT size, type, prio, anonLevel, expire, hash, value, oid FROM gn080 "\
                               "WHERE (prio = $1 AND oid > $2) "			\
                               "ORDER BY prio ASC,oid ASC LIMIT 1) "\
                               "UNION "\
                               "(SELECT  size, type, prio, anonLevel, expire, hash, value, oid FROM gn080 "\
                               "WHERE (prio > $1 AND oid != $2)"\
                               "ORDER BY prio ASC,oid ASC LIMIT 1)"\
                               "ORDER BY prio ASC,oid ASC LIMIT 1"

#define SELECT_IT_NON_ANONYMOUS "(SELECT  size, type, prio, anonLevel, expire, hash, value, oid FROM gn080 "\
                                "WHERE (prio = $1 AND oid < $2)"\
                                " AND anonLevel=0 ORDER BY prio DESC,oid DESC LIMIT 1) "\
                                "UNION "\
                                "(SELECT size, type, prio, anonLevel, expire, hash, value, oid FROM gn080 "\
                                "WHERE (prio < $1 AND oid != $2)"\
                                " AND anonLevel=0 ORDER BY prio DESC,oid DESC LIMIT 1) "\
                                "ORDER BY prio DESC,oid DESC LIMIT 1"

#define SELECT_IT_EXPIRATION_TIME "(SELECT size, type, prio, anonLevel, expire, hash, value, oid FROM gn080 "\
                                  "WHERE (expire = $1 AND oid > $2) "\
                                  "ORDER BY expire ASC,oid ASC LIMIT 1) "\
                                  "UNION "\
                                  "(SELECT size, type, prio, anonLevel, expire, hash, value, oid FROM gn080 "\
                                  "WHERE (expire > $1 AND oid != $2) "		\
                                  "ORDER BY expire ASC,oid ASC LIMIT 1)"\
                                  "ORDER BY expire ASC,oid ASC LIMIT 1"


#define SELECT_IT_MIGRATION_ORDER "(SELECT size, type, prio, anonLevel, expire, hash, value, oid FROM gn080 "\
                                  "WHERE (expire = $1 AND oid < $2)"\
                                  " AND expire > $3 AND type!=3"\
                                  " ORDER BY expire DESC,oid DESC LIMIT 1) "\
                                  "UNION "\
                                  "(SELECT size, type, prio, anonLevel, expire, hash, value, oid FROM gn080 "\
                                  "WHERE (expire < $1 AND oid != $2)"		\
                                  " AND expire > $3 AND type!=3"\
                                  " ORDER BY expire DESC,oid DESC LIMIT 1)"\
                                  "ORDER BY expire DESC,oid DESC LIMIT 1"

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

static struct GNUNET_Mutex *lock;

static unsigned long long payload;

static unsigned int lastSync;

/**
 * Check if the result obtained from Postgres has
 * the desired status code.  If not, log an error, clear the
 * result and return GNUNET_SYSERR.
 * 
 * @return GNUNET_OK if the result is acceptable
 */
static int
check_result (PGresult * ret,
              int expected_status,
              const char *command, const char *args, int line)
{
  if (ret == NULL)
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                     "Postgres failed to allocate result for `%s:%s' at %d\n",
                     command, args, line);
      return GNUNET_SYSERR;
    }
  if (PQresultStatus (ret) != expected_status)
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                     _("`%s:%s' failed at %s:%d with error: %s"),
                     command, args, __FILE__, line, PQerrorMessage (dbh));
      PQclear (ret);
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

/**
 * Run simple SQL statement (without results).
 */
static int
pq_exec (const char *sql, int line)
{
  PGresult *ret;
  ret = PQexec (dbh, sql);
  if (GNUNET_OK != check_result (ret, PGRES_COMMAND_OK, "PQexec", sql, line))
    return GNUNET_SYSERR;
  PQclear (ret);
  return GNUNET_OK;
}

/**
 * Prepare SQL statement.
 */
static int
pq_prepare (const char *name, const char *sql, int nparms, int line)
{
  PGresult *ret;
  ret = PQprepare (dbh, name, sql, nparms, NULL);
  if (GNUNET_OK !=
      check_result (ret, PGRES_COMMAND_OK, "PQprepare", sql, line))
    return GNUNET_SYSERR;
  PQclear (ret);
  return GNUNET_OK;
}

/**
 * @brief Get a database handle
 * @return the native Postgres database handle, NULL on error
 */
static int
init_connection ()
{
  char *conninfo;
  PGresult *ret;

  /* Open database and precompile statements */
  conninfo = NULL;
  GNUNET_GC_get_configuration_value_string (coreAPI->cfg,
                                            "POSTGRES", "CONFIG",
                                            "connect_timeout=10", &conninfo);
  dbh = PQconnectdb (conninfo);
  GNUNET_free (conninfo);
  if (dbh == NULL)
    {
      /* FIXME: warn about out-of-memory? */
      return GNUNET_SYSERR;
    }
  if (PQstatus (dbh) != CONNECTION_OK)
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Unable to initialize Postgres: %s"),
                     PQerrorMessage (dbh));
      PQfinish (dbh);
      dbh = NULL;
      return GNUNET_SYSERR;
    }

  ret = PQexec (dbh,
                "CREATE TABLE gn080 ("
                "  size INTEGER NOT NULL DEFAULT 0,"
                "  type INTEGER NOT NULL DEFAULT 0,"
                "  prio INTEGER NOT NULL DEFAULT 0,"
                "  anonLevel INTEGER NOT NULL DEFAULT 0,"
                "  expire BIGINT NOT NULL DEFAULT 0,"
                "  hash BYTEA NOT NULL DEFAULT '',"
                "  vhash BYTEA NOT NULL DEFAULT '',"
                "  value BYTEA NOT NULL DEFAULT '')" "WITH OIDS");
  if ((ret == NULL) || ((PQresultStatus (ret) != PGRES_COMMAND_OK) && (0 != strcmp ("42P07",    /* duplicate table */
                                                                                    PQresultErrorField
                                                                                    (ret,
                                                                                     PG_DIAG_SQLSTATE)))))
    {
      check_result (ret, PGRES_COMMAND_OK, "CREATE TABLE", "gn080", __LINE__);
      PQfinish (dbh);
      dbh = NULL;
      return GNUNET_SYSERR;
    }
  if (PQresultStatus (ret) == PGRES_COMMAND_OK)
    {
      if ((GNUNET_OK !=
           pq_exec ("CREATE INDEX idx_hash ON gn080 (hash)", __LINE__)) ||
          (GNUNET_OK !=
           pq_exec ("CREATE INDEX idx_hash_vhash ON gn080 (hash,vhash)",
                    __LINE__))
          || (GNUNET_OK !=
              pq_exec ("CREATE INDEX idx_prio ON gn080 (prio)", __LINE__))
          || (GNUNET_OK !=
              pq_exec ("CREATE INDEX idx_expire ON gn080 (expire)", __LINE__))
          || (GNUNET_OK !=
              pq_exec ("CREATE INDEX idx_comb3 ON gn080 (prio,anonLevel)",
                       __LINE__))
          || (GNUNET_OK !=
              pq_exec
              ("CREATE INDEX idx_comb4 ON gn080 (prio,hash,anonLevel)",
               __LINE__))
          || (GNUNET_OK !=
              pq_exec ("CREATE INDEX idx_comb7 ON gn080 (expire,hash)",
                       __LINE__)))
        {
          PQclear (ret);
          PQfinish (dbh);
          dbh = NULL;
          return GNUNET_SYSERR;
        }
    }
  PQclear (ret);
  if ((GNUNET_OK !=
       pq_prepare ("getvt",
                   "SELECT size, type, prio, anonLevel, expire, hash, value, oid FROM gn080 "
                   "WHERE hash=$1 AND vhash=$2 AND type=$3 "
                   "AND oid >= $4 ORDER BY oid ASC LIMIT 1 OFFSET $5",
                   5,
                   __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare ("gett",
                   "SELECT size, type, prio, anonLevel, expire, hash, value, oid FROM gn080 "
                   "WHERE hash=$1 AND type=$2"
                   "AND oid >= $3 ORDER BY oid ASC LIMIT 1 OFFSET $4",
                   4,
                   __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare ("getv",
                   "SELECT size, type, prio, anonLevel, expire, hash, value, oid FROM gn080 "
                   "WHERE hash=$1 AND vhash=$2"
                   "AND oid >= $3 ORDER BY oid ASC LIMIT 1 OFFSET $4",
                   4,
                   __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare ("get",
                   "SELECT size, type, prio, anonLevel, expire, hash, value, oid FROM gn080 "
                   "WHERE hash=$1"
                   "AND oid >= $2 ORDER BY oid ASC LIMIT 1 OFFSET $3",
                   3,
                   __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare ("put",
                   "INSERT INTO gn080 (size, type, prio, anonLevel, expire, hash, vhash, value) "
                   "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                   8,
                   __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare ("update",
                   "UPDATE gn080 SET prio = prio + $1, expire = CASE WHEN expire < $2 THEN $2 ELSE expire END "
                   "WHERE oid = $3",
                   3,
                   __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare ("select_low_priority",
                   SELECT_IT_LOW_PRIORITY,
                   2,
                   __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare ("select_non_anonymous",
                   SELECT_IT_NON_ANONYMOUS,
                   2,
                   __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare ("select_expiration_time",
                   SELECT_IT_EXPIRATION_TIME,
                   2,
                   __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare ("select_migration_order",
                   SELECT_IT_MIGRATION_ORDER,
                   3,
                   __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare ("delrow",
                   "DELETE FROM gn080 " "WHERE oid=$1", 1, __LINE__)))
    {
      PQfinish (dbh);
      dbh = NULL;
      return GNUNET_SYSERR;
    }

  return GNUNET_OK;
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
    stats->set (stat_size, ret);
  GNUNET_mutex_unlock (lock);
  return (unsigned long long) (ret * 1.00);
  /* benchmarking shows XX% overhead */
}

/**
 * @brief write all statistics to the db
 */
static void
syncStats ()
{
  // setStat (handle, "PAYLOAD", payload);
  lastSync = 0;
}

/**
 * @brief Get database statistics
 * @param key kind of stat to retrieve
 * @return GNUNET_SYSERR on error, the value otherwise
 */
static unsigned long long
getStat (const char *key)
{
  return 0;
}

/**
 * Delete the row identified by the given rowid (qid
 * in postgres).
 *
 * @return GNUNET_OK on success
 */
static int
delete_by_rowid (unsigned int rowid)
{
  const char *paramValues[] = { (const char *) &rowid };
  int paramLengths[] = { sizeof (rowid) };
  const int paramFormats[] = { 1 };
  PGresult *ret;

  ret = PQexecPrepared (dbh,
                        "delrow",
                        1, paramValues, paramLengths, paramFormats, 1);
  if (GNUNET_OK !=
      check_result (ret, PGRES_COMMAND_OK, "PQexecPrepared", "delrow",
                    __LINE__))
    {
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  PQclear (ret);
  return GNUNET_OK;
}

/**
 * Given a full row from gn080 table (size,type,priority,anonLevel,expire,hash,value,rowid),
 * assemble it into a GNUNET_DatastoreValue representation.
 */
static GNUNET_DatastoreValue *
assembleDatum (PGresult * res, GNUNET_HashCode * key, unsigned int *rowid)
{
  GNUNET_DatastoreValue *value;
  unsigned int size;

  if (0 == PQntuples (res))
    return NULL;                /* no result */
  if ((1 != PQntuples (res)) ||
      (8 != PQnfields (res)) ||
      (sizeof (unsigned int) != PQfsize (res, 0)) ||
      (sizeof (unsigned int) != PQfsize (res, 7)))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return NULL;
    }
  *rowid = *(unsigned int *) PQgetvalue (res, 0, 7);
  size = ntohl (*(unsigned int *) PQgetvalue (res, 0, 0));
  if ((size < sizeof (GNUNET_DatastoreValue)) ||
      (sizeof (unsigned int) != PQfsize (res, 1)) ||
      (sizeof (unsigned int) != PQfsize (res, 2)) ||
      (sizeof (unsigned int) != PQfsize (res, 3)) ||
      (sizeof (unsigned long long) != PQfsize (res, 4)) ||
      (sizeof (GNUNET_HashCode) != PQgetlength (res, 0, 5)) ||
      (size - sizeof (GNUNET_DatastoreValue) != PQgetlength (res, 0, 6)))
    {
      GNUNET_GE_BREAK (NULL, 0);
      delete_by_rowid (*rowid);
      return NULL;
    }
  value = GNUNET_malloc (size);
  value->size = htonl (size);
  value->type = *(unsigned int *) PQgetvalue (res, 0, 1);
  value->priority = *(unsigned int *) PQgetvalue (res, 0, 2);
  value->anonymity_level = *(unsigned int *) PQgetvalue (res, 0, 3);
  value->expiration_time = *(unsigned long long *) PQgetvalue (res, 0, 4);
  memcpy (key, PQgetvalue (res, 0, 5), sizeof (GNUNET_HashCode));
  memcpy (&value[1], PQgetvalue (res, 0, 6),
          size - sizeof (GNUNET_DatastoreValue));
  return value;
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
                  unsigned int iter_select,
                  GNUNET_DatastoreValueIterator dviter, void *closure)
{
  GNUNET_DatastoreValue *datum;
  int count;
  const char *pname;
  int pcount;
  int iret;
  PGresult *ret;
  unsigned int last_prio;
  unsigned long long last_expire;
  unsigned int last_oid;
  GNUNET_CronTime now;
  GNUNET_HashCode key;
  const char *paramValues[3];
  int paramLengths[3];
  const int paramFormats[] = { 1, 1, 1 };

  if (is_asc)
    {
      last_prio = 0;
      last_oid = 0;
      last_expire = 0;
    }
  else
    {
      last_prio = 0x7FFFFFFFL;
      last_oid = 0xFFFFFFFF;
      last_expire = 0x7FFFFFFFFFFFFFFFLL;
    }
  switch (iter_select)
    {
    case 0:
      pname = "select_low_priority";
      pcount = 2;
      paramValues[0] = (const char *) &last_prio;
      paramValues[1] = (const char *) &last_oid;
      paramLengths[0] = sizeof (last_prio);
      paramLengths[1] = sizeof (last_oid);
      break;
    case 1:
      pname = "select_non_anonymous";
      pcount = 2;
      paramValues[0] = (const char *) &last_prio;
      paramValues[1] = (const char *) &last_oid;
      paramLengths[0] = sizeof (last_prio);
      paramLengths[1] = sizeof (last_oid);
      break;
    case 2:
      pname = "select_expiration_time";
      pcount = 2;
      paramValues[0] = (const char *) &last_expire;
      paramValues[1] = (const char *) &last_oid;
      paramLengths[0] = sizeof (last_expire);
      paramLengths[1] = sizeof (last_oid);
      break;
    case 3:
      pname = "select_migration_order";
      pcount = 3;
      paramValues[0] = (const char *) &last_expire;
      paramValues[1] = (const char *) &last_oid;
      paramValues[2] = (const char *) &now;
      paramLengths[0] = sizeof (last_expire);
      paramLengths[1] = sizeof (last_oid);
      paramLengths[2] = sizeof (now);
      break;
    default:
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  now = GNUNET_htonll (GNUNET_get_time ());
  count = 0;
  GNUNET_mutex_lock (lock);
  while (1)
    {
      ret = PQexecPrepared (dbh,
                            pname,
                            pcount,
                            paramValues, paramLengths, paramFormats, 1);
      if (GNUNET_OK != check_result (ret,
                                     PGRES_TUPLES_OK,
                                     "PQexecPrepared", pname, __LINE__))
        {
          GNUNET_mutex_unlock (lock);
          return GNUNET_SYSERR;
        }
      datum = assembleDatum (ret, &key, &last_oid);
      if (datum == NULL)
        break;                  /* iteration complete */
      last_prio = datum->priority;
      last_expire = datum->expiration_time;
      count++;
      if (dviter != NULL)
        {
          GNUNET_mutex_unlock (lock);
          iret = dviter (&key, datum, closure, last_oid);
          GNUNET_mutex_lock (lock);
          if (iret == GNUNET_SYSERR)
            {
              GNUNET_free (datum);
              break;
            }
          if (iret == GNUNET_NO)
            {
              payload -= getContentDatastoreSize (datum);
              lastSync++;
              delete_by_rowid (last_oid);
            }
        }
      GNUNET_free (datum);
    }
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
  return postgres_iterate (type, GNUNET_YES, 0, iter, closure);
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
  return postgres_iterate (type, GNUNET_NO, 1, iter, closure);
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
  return postgres_iterate (type, GNUNET_YES, 2, iter, closure);
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
  return postgres_iterate (0, GNUNET_NO, 3, iter, closure);
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
  return postgres_iterate (0, GNUNET_YES, 0, iter, closure);
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
  unsigned long long total;
  const char *paramValues[5];
  int paramLengths[5];
  const int paramFormats[] = { 1, 1, 1, 1, 1 };
  unsigned int last_rowid;
  unsigned int rowid;
  int nparams;
  int iret;
  unsigned int n_type;
  const char *pname;
  long long count;
  long long off;
  long long limit_off;
  PGresult *ret;
  GNUNET_DatastoreValue *datum;
  GNUNET_HashCode rkey;

  if (key == NULL)
    return iterateLowPriority (type, iter, closure);
  GNUNET_mutex_lock (lock);
  paramValues[0] = (const char *) key;
  paramLengths[0] = sizeof (GNUNET_HashCode);
  if (type != 0)
    {
      n_type = htonl (type);
      if (vhash != NULL)
        {
          paramValues[1] = (const char *) vhash;
          paramLengths[1] = sizeof (GNUNET_HashCode);
          paramValues[2] = (const char *) &n_type;
          paramLengths[2] = sizeof (unsigned int);
          paramValues[3] = (const char *) &last_rowid;
          paramLengths[3] = sizeof (last_rowid);
          paramValues[4] = (const char *) &limit_off;
          paramLengths[4] = sizeof (limit_off);
          nparams = 5;
          pname = "getvt";
          ret = PQexecParams (dbh,
                              "SELECT count(*) FROM gn080 WHERE hash=$1 AND vhash=$2 AND type=$3",
                              3,
                              NULL,
                              paramValues, paramLengths, paramFormats, 1);
        }
      else
        {
          paramValues[1] = (const char *) &n_type;
          paramLengths[1] = sizeof (unsigned int);
          paramValues[2] = (const char *) &last_rowid;
          paramLengths[2] = sizeof (last_rowid);
          paramValues[3] = (const char *) &limit_off;
          paramLengths[3] = sizeof (limit_off);
          nparams = 4;
          pname = "gett";
          ret = PQexecParams (dbh,
                              "SELECT count(*) FROM gn080 WHERE hash=$1 AND type=$2",
                              2,
                              NULL,
                              paramValues, paramLengths, paramFormats, 1);
        }
    }
  else
    {
      if (vhash != NULL)
        {
          paramValues[1] = (const char *) vhash;
          paramLengths[1] = sizeof (GNUNET_HashCode);
          paramValues[2] = (const char *) &last_rowid;
          paramLengths[2] = sizeof (last_rowid);
          paramValues[3] = (const char *) &limit_off;
          paramLengths[3] = sizeof (limit_off);
          nparams = 4;
          pname = "getv";
          ret = PQexecParams (dbh,
                              "SELECT count(*) FROM gn080 WHERE hash=$1 AND vhash=$2",
                              2,
                              NULL,
                              paramValues, paramLengths, paramFormats, 1);
        }
      else
        {
          paramValues[1] = (const char *) &last_rowid;
          paramLengths[1] = sizeof (last_rowid);
          paramValues[2] = (const char *) &limit_off;
          paramLengths[2] = sizeof (limit_off);
          nparams = 3;
          pname = "get";
          ret = PQexecParams (dbh,
                              "SELECT count(*) FROM gn080 WHERE hash=$1",
                              1,
                              NULL,
                              paramValues, paramLengths, paramFormats, 1);
        }
    }
  if (GNUNET_OK != check_result (ret,
                                 PGRES_TUPLES_OK,
                                 "PQexecParams", pname, __LINE__))
    {
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  if ((PQntuples (ret) != 1) ||
      (PQnfields (ret) != 1) ||
      (PQgetlength (ret, 0, 0) != sizeof (unsigned long long)))
    {
      GNUNET_GE_BREAK (NULL, 0);
      PQclear (ret);
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  total =
    GNUNET_ntohll (*(const unsigned long long *) PQgetvalue (ret, 0, 0));
  PQclear (ret);
  if ((iter == NULL) || (total == 0))
    {
      GNUNET_mutex_unlock (lock);
      fprintf (stderr, "Total is %llu\n", total);
      return total;
    }

  count = 0;
  last_rowid = 0;
  off = GNUNET_random_u64 (GNUNET_RANDOM_QUALITY_WEAK, total);
  while (1)
    {
      if (count == 0)
        limit_off = off;
      else
        limit_off = 0;

      ret = PQexecPrepared (dbh,
                            pname,
                            nparams,
                            paramValues, paramLengths, paramFormats, 1);
      if (GNUNET_OK != check_result (ret,
                                     PGRES_TUPLES_OK,
                                     "PQexecPrepared", pname, __LINE__))
        {
          GNUNET_mutex_unlock (lock);
          return GNUNET_SYSERR;
        }
      datum = assembleDatum (ret, &rkey, &rowid);
      last_rowid = rowid + 1;
      PQclear (ret);
      if (datum == NULL)
        {
          total--;
          if (count == total)
            break;
          continue;
        }
      if ((key != NULL) &&
          (0 != memcmp (&rkey, key, sizeof (GNUNET_HashCode))))
        {
          GNUNET_GE_BREAK (NULL, 0);
          GNUNET_free (datum);
          continue;
        }
      GNUNET_mutex_unlock (lock);
      count++;
      iret = iter (&rkey, datum, closure, rowid);
      GNUNET_mutex_lock (lock);
      if (iret == GNUNET_SYSERR)
        {
          GNUNET_free (datum);
          break;
        }
      if (iret == GNUNET_NO)
        {
          payload -= getContentDatastoreSize (datum);
          lastSync++;
          delete_by_rowid (rowid);
        }
      GNUNET_free (datum);
      if (count + off == total)
        last_rowid = 0;         /* back to start */
      if (count == total)
        break;
    }
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
  unsigned int size = ntohl (value->size);
  GNUNET_HashCode vhash;
  PGresult *ret;
  const char *paramValues[] = {
    (const char *) &value->size,
    (const char *) &value->type,
    (const char *) &value->priority,
    (const char *) &value->anonymity_level,
    (const char *) &value->expiration_time,
    (const char *) key,
    (const char *) &vhash,
    (const char *) &value[1]
  };
  int paramLengths[] = {
    sizeof (value->size),
    sizeof (value->type),
    sizeof (value->priority),
    sizeof (value->anonymity_level),
    sizeof (value->expiration_time),
    sizeof (GNUNET_HashCode),
    sizeof (GNUNET_HashCode),
    size - sizeof (GNUNET_DatastoreValue)
  };
  const int paramFormats[] = { 1, 1, 1, 1, 1, 1, 1, 1 };

  if (size < sizeof (GNUNET_DatastoreValue))
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
      return GNUNET_SYSERR;
    }
  GNUNET_hash (&value[1], size - sizeof (GNUNET_DatastoreValue), &vhash);
  GNUNET_mutex_lock (lock);
  if (lastSync > 1000)
    syncStats ();
  ret = PQexecPrepared (dbh,
                        "put", 8, paramValues, paramLengths, paramFormats, 1);
  if (GNUNET_OK != check_result (ret,
                                 PGRES_COMMAND_OK,
                                 "PQexecPrepared", "put", __LINE__))
    {
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  PQclear (ret);
  lastSync++;
  payload += getContentDatastoreSize (value);
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
  unsigned int oid = (unsigned int) uid;        /* only 32 bit for postgres */
  int n_delta = htonl (delta);
  GNUNET_CronTime n_expire = GNUNET_htonll (expire);
  PGresult *ret;
  const char *paramValues[] = {
    (const char *) &n_delta,
    (const char *) &n_expire,
    (const char *) &oid,
  };
  int paramLengths[] = {
    sizeof (n_delta),
    sizeof (n_expire),
    sizeof (oid),
  };
  const int paramFormats[] = { 1, 1, 1 };

  GNUNET_mutex_lock (lock);
  ret = PQexecPrepared (dbh,
                        "update",
                        3, paramValues, paramLengths, paramFormats, 1);
  if (GNUNET_OK != check_result (ret,
                                 PGRES_COMMAND_OK,
                                 "PQexecPrepared", "update", __LINE__))
    {
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  PQclear (ret);
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}



static void
postgres_shutdown ()
{
  if (dbh == NULL)
    return;                     /* already down */
#if DEBUG_POSTGRES
  GNUNET_GE_LOG (coreAPI->ectx,
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
  pq_exec ("DROP TABLE gn080", __LINE__);
  postgres_shutdown ();
}


GNUNET_SQstore_ServiceAPI *
provide_module_sqstore_postgres (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_SQstore_ServiceAPI api;

  coreAPI = capi;
#if DEBUG_POSTGRES
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Postgres: initializing database\n");
#endif

  payload = 0;
  lastSync = 0;
  lock = GNUNET_mutex_create (GNUNET_NO);
  if (GNUNET_OK != init_connection ())
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
      GNUNET_mutex_destroy (lock);
      return NULL;
    }
  payload = getStat ("PAYLOAD");
  if (payload == GNUNET_SYSERR)
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
      GNUNET_mutex_destroy (lock);
      return NULL;
    }
  coreAPI = capi;
  stats = coreAPI->service_request ("stats");
  if (stats)
    {
      stat_size = stats->create (gettext_noop ("# bytes in datastore"));
#if DEBUG_POSTGRES
      stat_mem =
        stats->create (gettext_noop ("# bytes allocated by Postgres"));
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
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Postgres: database shutdown\n");
#endif
  GNUNET_mutex_destroy (lock);
  lock = NULL;
  coreAPI = NULL;
  payload = 0;
  lastSync = 0;
}

/**
 * Update postgres database module.  Does nothing right now.
 */
void
update_module_sqstore_postgres (GNUNET_UpdateAPI * uapi)
{
  lock = GNUNET_mutex_create (GNUNET_NO);
  if (GNUNET_OK != init_connection ())
    {
      GNUNET_mutex_destroy (lock);
      return;
    }
  postgres_shutdown ();
  GNUNET_mutex_destroy (lock);
}

/* end of postgres.c */
