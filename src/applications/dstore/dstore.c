/*
     This file is part of GNUnet.
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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file applications/dstore/dstore.c
 * @brief SQLite based implementation of the dstore service
 * @author Christian Grothoff
 * @todo Indexes, statistics
 *
 * Database: SQLite
 *
 * TODO:
 * - add bloomfilter to reduce disk IO
 * - finish delete for quota maintenance
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_dstore_service.h"
#include <sqlite3.h>

/**
 * Bytes used
 */
static unsigned long long payload;

/**
 * Maximum bytes available
 */ 
static unsigned long long quota;

/**
 * Filename of this database
 */
static char * fn;

static CoreAPIForApplication * coreAPI;

static struct MUTEX * lock;

/**
 * @brief Prepare a SQL statement
 */
static int sq_prepare(sqlite3 * dbh,
		      const char *zSql,       /* SQL statement, UTF-8 encoded */
		      sqlite3_stmt **ppStmt) {  /* OUT: Statement handle */
  char * dummy;
  return sqlite3_prepare(dbh,
		  zSql,
		  strlen(zSql),
		  ppStmt,
		  (const char**) &dummy);
}

static void db_reset() {
  int fd;

  UNLINK(fn);
  FREE(fn);
  fn = STRDUP("/tmp/dstoreXXXXXX");
  fd = mkstemp(fn);
  if (fd != -1) 
    CLOSE(fd);
}

static void db_init(sqlite3 * dbh) {
  sqlite3_exec(dbh,
	       "PRAGMA temp_store=MEMORY", 
	       NULL,
	       NULL,
	       NULL);
  sqlite3_exec(dbh,
	       "PRAGMA synchronous=OFF", 
	       NULL,
	       NULL, 
	       NULL);
  sqlite3_exec(dbh,
	       "PRAGMA count_changes=OFF", 
	       NULL, 
	       NULL, 
	       NULL);
  sqlite3_exec(dbh,
	       "PRAGMA page_size=4092", 
	       NULL,
	       NULL, 
	       NULL);
  sqlite3_exec(dbh,
	       "CREATE TABLE ds071 ("
	       "  size INTEGER NOT NULL DEFAULT 0,"
	       "  type INTEGER NOT NULL DEFAULT 0,"
	       "  puttime INTEGER NOT NULL DEFAULT 0,"
	       "  expire INTEGER NOT NULL DEFAULT 0,"
	       "  key TEXT NOT NULL DEFAULT '',"
	       "  value BLOB NOT NULL DEFAULT '')",
	       NULL,
	       NULL,
	       NULL);
  sqlite3_exec(dbh,
	       "CREATE INDEX idx_key ON ds071 (key)",
	       NULL, 
	       NULL, 
	       NULL);
  sqlite3_exec(dbh,
	       "CREATE INDEX idx_puttime ON ds071 (puttime)",
	       NULL, 
	       NULL, 
	       NULL);
}

/**
 * Store an item in the datastore.
 *
 * @return OK on success, SYSERR on error
 */
static int d_put(const HashCode512 * key,
		 unsigned int type,
		 cron_t discard_time,
		 unsigned int size,
		 const char * data) {
  sqlite3 * dbh;
  sqlite3_stmt * stmt;
  sqlite3_stmt * dstmt;

  MUTEX_LOCK(lock);
  if (SQLITE_OK != sqlite3_open(fn,
				&dbh)) {
    db_reset(dbh);
    MUTEX_UNLOCK(lock);    
    return SYSERR;
  }
  db_init(dbh);
  if (sq_prepare(dbh,
		 "INSERT INTO ds071 "
		 "(size, type, puttime, expire, key, value) "
		 "VALUES (?, ?, ?, ?, ?, ?)",
		 &stmt) != SQLITE_OK) {
    sqlite3_close(dbh);
    MUTEX_UNLOCK(lock);
    return SYSERR;
  }
  sqlite3_bind_int(stmt,
		   1,
		   size);
  sqlite3_bind_int(stmt,
		   2,
		   type);
  sqlite3_bind_int64(stmt,
		     3,
		     get_time());
  sqlite3_bind_int64(stmt,
		     4,
		     discard_time);
  sqlite3_bind_blob(stmt,
		    5,
		    key,
		    sizeof(HashCode512),
		    SQLITE_TRANSIENT);
  sqlite3_bind_blob(stmt,
		    6,
		    data,
		    size,
		    SQLITE_TRANSIENT);
  sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  stmt = NULL;
  dstmt = NULL;
  payload += size;
  if (payload > quota) {
    if ( (sq_prepare(dbh,
		     "SELECT size, type, puttime, expire, key, value FROM ds071 ORDER BY puttime ASC",
		     &stmt) == SQLITE_OK) &&
	 (sq_prepare(dbh,
		     "DELETE FROM ds071 "
		     "WHERE size = ? AND type = ? AND puttime = ? AND expire = ? AND key = ? AND value = ?",
		     &dstmt) == SQLITE_OK) ) {
      while (payload > quota) {
	/* FIMXE: delete until quota is satisfied again */
	break; /* for now */
      }
      sqlite3_finalize(dstmt);
      sqlite3_finalize(stmt);
    } else {
      GE_BREAK(NULL, 0);
      if (dstmt != NULL)
	sqlite3_finalize(dstmt);
      if (stmt != NULL)
	sqlite3_finalize(stmt);
    }
  }
  sqlite3_close(dbh);
  MUTEX_UNLOCK(lock);
  return OK;
}

/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param key 
 * @param type entries of which type are relevant?
 * @param iter maybe NULL (to just count)
 * @return the number of results, SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int d_get(const HashCode512 * key,
		 unsigned int type,
		 ResultHandler handler,
		 void * closure) {
  sqlite3 * dbh;
  sqlite3_stmt * stmt;
  cron_t expire;
  unsigned int size;
  const char * dat;
  unsigned int cnt;

  MUTEX_LOCK(lock);
  if (SQLITE_OK != sqlite3_open(fn,
				&dbh)) {
    db_reset(dbh);
    MUTEX_UNLOCK(lock);    
    return SYSERR;
  }
  db_init(dbh);
  if (sq_prepare(dbh,
		 "SELECT size, type, puttime, expire, key, value FROM ds071 WHERE key=? AND type=?",
		 &stmt) != SQLITE_OK) {
    sqlite3_close(dbh);
    MUTEX_UNLOCK(lock);
    return SYSERR;
  }
  sqlite3_bind_blob(stmt,
		    1,
		    key,
		    sizeof(HashCode512),
		    SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt,
		   2,
		   type);
  cnt = 0;
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    size = sqlite3_column_int(stmt, 0);
    if (size != sqlite3_column_bytes(stmt, 5)) {
      GE_BREAK(NULL, 0);
      continue;
    }
    expire = sqlite3_column_int64(stmt, 3);
    if (expire < get_time()) 
      continue;
    dat = sqlite3_column_blob(stmt, 5);
    handler(key,
	    type,
	    size,
	    dat,
	    closure);
    cnt++;
  }
  sqlite3_finalize(stmt);
  sqlite3_close(dbh);
  MUTEX_UNLOCK(lock);
  return cnt;
}

Dstore_ServiceAPI *
provide_module_dstore(CoreAPIForApplication * capi) {
  static Dstore_ServiceAPI api;
  int fd;

#if DEBUG_SQLITE
  GE_LOG(capi->ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "SQLite Dstore: initializing database\n");
#endif
  fn = STRDUP("/tmp/dstoreXXXXXX");
  fd = mkstemp(fn);
  if (fd == -1) {
    FREE(fn);
    return NULL;
  }
  CLOSE(fd);
  lock = MUTEX_CREATE(NO);
  coreAPI = capi;
  api.get = &d_get;
  api.put = &d_put;
  return &api;
}

/**
 * Shutdown the module.
 */
void release_module_dstore() {
  UNLINK(fn);
  FREE(fn);
  fn = NULL;
#if DEBUG_SQLITE
  GE_LOG(coreAPI->ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "SQLite Dstore: database shutdown\n");
#endif
  MUTEX_DESTROY(lock);
  coreAPI = NULL;
}

/* end of dstore.c */
