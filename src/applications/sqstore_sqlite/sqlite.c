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
 * @file applications/sqstore_sqlite/sqlite.c
 * @brief SQLite based implementation of the sqstore service
 * @author Nils Durner
 * @todo Estimation of DB size
 * @todo Apply fixes from MySQL module
 *
 * Database: SQLite
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_sqstore_service.h"
#include "gnunet_protocols.h"
#include <sqlite3.h>

#define DEBUG_SQLITE NO

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define DIE_SQLITE(cmd) do { errexit(_("'%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(dbh->dbf)); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_SQLITE(level, cmd) do { LOG(level, _("'%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(dbh->dbf)); } while(0);


/**
 * @brief SQLite wrapper
 */
typedef struct {
  sqlite3 *dbf;
  Mutex DATABASE_Lock_;
  /** filename of this bucket */
  char *fn;
  /** bytes used */
  double payload;
  unsigned int lastSync;

  /** Precompiled SQL */
  sqlite3_stmt *exists, *countContent, *updPrio, *insertContent;
} sqliteHandle;

static sqliteHandle *dbh;

static int sq_prepare(const char *zSql,       /* SQL statement, UTF-8 encoded */
		      sqlite3_stmt **ppStmt) {  /* OUT: Statement handle */
  char * dummy;
  return sqlite3_prepare(dbh->dbf,
			 zSql,
			 strlen(zSql),
			 ppStmt,
			 (const char**) &dummy);
}


/**
 * Get the current on-disk size of the SQ store.  Estimates are fine,
 * if that's the only thing available.
 *
 * @return number of bytes used on disk
 */
static unsigned long long getSize() {
  double ret;

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  ret = dbh->payload * 1.0; /* FIXME 0.7: Find magic factor */
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
#if DEBUG_SQLITE
  LOG(LOG_DEBUG,
      "SQLite: database size: %.0f\n",
      ret);
#endif
  return ret;
}

/**
 * @brief Encode a binary buffer "in" of size n bytes so that it contains
 *        no instances of characters '\'' or '\000'.  The output is
 *        null-terminated and can be used as a string value in an INSERT
 *        or UPDATE statement.
 * @param in input
 * @param n size of in
 * @param out output
 */
static int sqlite_encode_binary(const unsigned char *in,
				int n,
				unsigned char *out){
  char c;
  unsigned char *start = out;

  n--;
  for (; n > -1; n--) {
    c = *in;
    in++;

    if (c == 0 || c == 1) {
      *out = 1;
      out++;
      *out = c + 1;
    } else {
      *out = c;
    }
    out++;
  }
  *out = 0;

  return (int) (out - start);
}

/**
 * @brief Decode the string "in" into binary data and write it into "out".
 * @param in input
 * @param out output
 * @param num size of the output buffer
 * @return number of output bytes, -1 on error
 */
static int sqlite_decode_binary_n(const unsigned char *in,
				  unsigned char *out,
				  unsigned int num){
  char c;
  unsigned char *start = out;

  while((c = *in) && (out - start < num)) {
    if (c == 1) {
      in++;
      *out = *in - 1;
    } else
      *out = c;
    in++;
    out++;
  }
  return (int) (out - start);
}

/**
 * Given a full row from gn070 table (size,type,prio,anonLevel,expire,hash,value),
 * assemble it into a Datastore_Datum representation.
 */
static Datastore_Datum * assembleDatum(sqlite3_stmt *stmt) {
  Datastore_Datum * datum;
  Datastore_Value * value;
  int contentSize;

  contentSize = sqlite3_column_int(stmt, 0) - sizeof(Datastore_Value);

  if (contentSize < 0) {
    return NULL; /* error */
  }

  if (sqlite3_column_bytes(stmt, 5) > sizeof(HashCode512) * 2 + 1 ||
      sqlite3_column_bytes(stmt, 6) > contentSize * 2 + 1) {

    LOG(LOG_WARNING,
	_("SQL Database corrupt, ignoring result.\n"));
    return NULL;
  }

  datum = MALLOC(sizeof(Datastore_Datum) + contentSize);
  value = &datum->value;
  value->size = htonl(contentSize + sizeof(Datastore_Value));
  value->type = htonl(sqlite3_column_int(stmt, 1));
  value->prio = htonl(sqlite3_column_int(stmt, 2));
  value->anonymityLevel = htonl(sqlite3_column_int(stmt, 3));
  value->expirationTime = htonll(sqlite3_column_int64(stmt, 4));

  if (sqlite_decode_binary_n(sqlite3_column_blob(stmt, 5),
			     (char *) &datum->key,
			     sizeof(HashCode512)) != sizeof(HashCode512) ||
      sqlite_decode_binary_n(sqlite3_column_blob(stmt, 6),
			     (char *) &value[1],
			     contentSize) != contentSize) {

    LOG(LOG_WARNING,
	_("SQL Database corrupt, ignoring result.\n"));
    return NULL;
  }
  return datum;
}


/**
 * @brief Get database statistics
 * @param key kind of stat to retrieve
 * @return SYSERR on error, the value otherwise
 */
static double getStat(const char * key) {
  int i;
  sqlite3_stmt *stmt;
  double ret = SYSERR;

  i = sq_prepare("SELECT anonLevel FROM gn070 WHERE hash = ?",
		 &stmt);
  if (i == SQLITE_OK) {
    sqlite3_bind_text(stmt,
		      1,
		      key,
		      strlen(key),
		      SQLITE_STATIC);
    i = sqlite3_step(stmt);

    if (i == SQLITE_DONE) {
      ret = 0;
      i = SQLITE_OK;
    }
    else if (i == SQLITE_ROW) {
      ret = sqlite3_column_double(stmt, 0);
      i = SQLITE_OK;
    }
  }
  sqlite3_finalize(stmt);

  if (i != SQLITE_OK) {
    LOG_SQLITE(LOG_ERROR,
	       "sqlite_getStat");
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
static int setStat(const char *key,
		   double val) {
  sqlite3_stmt *stmt;

  if (sq_prepare("REPLACE INTO gn070(hash, anonLevel, type) VALUES (?, ?, ?)",
		 &stmt) == SQLITE_OK) {
    sqlite3_bind_text(stmt,
		      1,
		      key,
		      strlen(key),
		      SQLITE_STATIC);
    sqlite3_bind_double(stmt,
			2,
			val);
    sqlite3_bind_int(stmt,
		     3,
		     RESERVED_BLOCK);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
      LOG_SQLITE(LOG_ERROR,
		 "sqlite_setStat");
      return SYSERR;
    }
    sqlite3_finalize(stmt);

    return OK;
  } else
    return SYSERR;
}

/**
 * @brief write all statistics to the db
 */
static void syncStats() {
  setStat("PAYLOAD",
	  dbh->payload);
  dbh->lastSync = 0;
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
static int sqlite_iterate(unsigned int type,
			  Datum_Iterator iter,
			  void * closure,
			  int sortByPriority) {	
  sqlite3_stmt * stmt;
  int count;
  char scratch[512];
  Datastore_Datum * datum;
  unsigned int lastPrio;
  unsigned long long lastExp;
  unsigned long hashLen;
  char * lastHash;
  HashCode512 key;

#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: iterating through the database\n");
#endif

  MUTEX_LOCK(&dbh->DATABASE_Lock_);

  strcpy(scratch,
	 "SELECT size, type, prio, anonLevel, expire, hash, value FROM gn070"
	 " WHERE ((hash > :1 AND expire == :2 AND prio == :3) OR ");
  if (sortByPriority)
    strcat(scratch,
	   "(expire > :4 AND prio == :5) OR prio > :6)");
  else
    strcat(scratch,
	   "(prio > :4 AND expire == :5) OR expire > :6)");
  if (type)
    strcat(scratch, " AND type = :7");
  else
    SNPRINTF(&scratch[strlen(scratch)],
	     512 - strlen(scratch),
	     " AND type != %d",
	     RESERVED_BLOCK); /* otherwise we iterate over
				 the stats entry, which would
				 be bad */
  if (sortByPriority)
    strcat(scratch, " ORDER BY prio ASC, expire ASC, hash ASC");
  else
    strcat(scratch, " ORDER BY expire ASC, prio ASC, hash ASC");
  strcat(scratch, " LIMIT 1");
  if (sq_prepare(scratch,
		 &stmt) != SQLITE_OK) {
    LOG_SQLITE(LOG_ERROR, "sqlite3_prepare");
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }

  count    = 0;
  lastPrio = 0;
  lastExp  = 0x8000000000000000LL; /* MIN long long; sqlite does not know about unsigned... */
  memset(&key, 0, sizeof(HashCode512));
  lastHash = MALLOC(sizeof(HashCode512)*2 + 2);
  while (1) {
    hashLen = sqlite_encode_binary((const char *) &key,
				   sizeof(HashCode512),
				   lastHash);

    sqlite3_bind_blob(stmt,
		      1,
		      lastHash,
		      hashLen,
		      SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt,
		       2,
		       lastExp);
    sqlite3_bind_int(stmt,
		     3,
		     lastPrio);
    if (sortByPriority) {
      sqlite3_bind_int(stmt,
		       4,
		       lastPrio);
      sqlite3_bind_int64(stmt,
			 5,
			 lastExp);
      sqlite3_bind_int(stmt,
		       6,
		       lastPrio);
    } else {
      sqlite3_bind_int64(stmt,
			 4,
			 lastExp);
      sqlite3_bind_int(stmt,
		       5,
		       lastPrio);
      sqlite3_bind_int64(stmt,
			 6,
			 lastExp);
    }
    if (type)
      sqlite3_bind_int(stmt,
		       7,
		       type);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
      datum = assembleDatum(stmt);

      if (datum == NULL) {
	LOG(LOG_WARNING,
	    _("Invalid data in database.  Please verify integrity!\n"));
	continue;
      }

      /*      printf("FOUND %4u prio %4u exp %20llu old: %4u, %20llu\n",
	     (ntohl(datum->value.size) - sizeof(Datastore_Value))/8,
	     ntohl(datum->value.prio),
	     ntohll(datum->value.expirationTime),
	     lastPrio,
	     lastExp);
      */

      if (iter != NULL) {
	MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
	if (SYSERR == iter(&datum->key,
			   &datum->value,
			   closure) ) {
	  count = SYSERR;
	  FREE(datum);
	  MUTEX_LOCK(&dbh->DATABASE_Lock_);
	  break;
	}
	MUTEX_LOCK(&dbh->DATABASE_Lock_);
      }
      key = datum->key;
      lastPrio = ntohl(datum->value.prio);
      lastExp  = ntohll(datum->value.expirationTime);
      FREE(datum);
      count++;
    } else
      break;
    sqlite3_reset(stmt);
  }
  FREE(lastHash);
  sqlite3_finalize(stmt);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);

#if DEBUG_SQLITE
  LOG(LOG_DEBUG,
      "SQLite: reached end of database\n");
#endif
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
static int iterateLowPriority(unsigned int type,
			      Datum_Iterator iter,
			      void * closure) {
  return sqlite_iterate(type, iter, closure, 1);
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
static int iterateExpirationTime(unsigned int type,
				 Datum_Iterator iter,
				 void * closure) {
  return sqlite_iterate(type, iter, closure, 0);
}

static void sqlite_shutdown() {
#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: closing database\n");
#endif
  if (! dbh)
    return;

  MUTEX_DESTROY(&dbh->DATABASE_Lock_);

  sqlite3_finalize(dbh->countContent);
  sqlite3_finalize(dbh->exists);
  sqlite3_finalize(dbh->updPrio);
  sqlite3_finalize(dbh->insertContent);
  syncStats();
  if (sqlite3_close(dbh->dbf) != SQLITE_OK)
    LOG_SQLITE(LOG_ERROR, "sqlite_close");

  FREE(dbh->fn);
  FREE(dbh);
  dbh = NULL;
}

/**
 * Delete the database.  The next operation is
 * guaranteed to be unloading of the module.
 */
static void drop() {
  char *fn = STRDUP(dbh->fn);
  sqlite_shutdown();
  UNLINK(fn);
  FREE(fn);
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
static int get(const HashCode512 * key,
	       unsigned int type,
	       Datum_Iterator iter,
	       void * closure) {
  char *escapedHash = NULL;
  int len, ret, count = 0;
  sqlite3_stmt *stmt;
  char scratch[97];
  int bind = 1;
  Datastore_Datum *datum;

#if DEBUG_SQLITE
  {
    char block[33];
    hash2enc(block, (EncName *) key);
    LOG(LOG_DEBUG, "SQLite: read content %s\n", key);
  }
#endif

  MUTEX_LOCK(&dbh->DATABASE_Lock_);

  strcpy(scratch, "SELECT ");
  if (iter == NULL)
    strcat(scratch, "count(*)");
  else
    strcat(scratch, "size, type, prio, anonLevel, expire, hash, value");
  strcat(scratch, " FROM gn070");

  if (type || key) {
    strcat(scratch, " WHERE ");
    if (type) {
      strcat(scratch, "type = :1");
      if (key)
	strcat(scratch, " and ");
    }
    if (key)
      strcat(scratch, "hash = :2");
  }

  if (sq_prepare(scratch,
		 &stmt) != SQLITE_OK) {
    LOG_SQLITE(LOG_ERROR, "sqlite_query");
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }

  if (type)
    ret = sqlite3_bind_int(stmt,
			   bind++,
			   type);
  else
    ret = SQLITE_OK;
  	
  if (key && (ret == SQLITE_OK)) {
    escapedHash = MALLOC(sizeof(HashCode512)*2 + 2);
    len = sqlite_encode_binary((const char *) key,
			       sizeof(HashCode512),
			       escapedHash);
    ret = sqlite3_bind_blob(stmt,
			    bind,
			    escapedHash,
			    len,
			    SQLITE_TRANSIENT);
  }

  if (ret == SQLITE_OK) {
    while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
      if (iter != NULL) {
	datum = assembleDatum(stmt);
	
	if (datum == NULL) {
	  LOG(LOG_WARNING,
	      _("Invalid data in database.  Please verify integrity!\n"));
	  continue;
	}

#if DEBUG_SQLITE
	LOG(LOG_DEBUG,
	    "Found in database block with type %u.\n",
	    ntohl(*(int*)&((&datum->value)[1])));
#endif
	if (SYSERR == iter(&datum->key,
			   &datum->value,
			   closure) ) {
	
	  count = SYSERR;
	  FREE(datum);
	  ret = SQLITE_DONE;
	  break;
	}
	FREE(datum);
	count++;
      } else
	count += sqlite3_column_int(stmt, 0);
    }
    if (ret != SQLITE_DONE) {
      LOG_SQLITE(LOG_ERROR, "sqlite_query");
      sqlite3_finalize(stmt);
      FREENONNULL(escapedHash);
      MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
      return SYSERR;
    }

    sqlite3_finalize(stmt);
  } else
    LOG_SQLITE(LOG_ERROR, "sqlite_query");

  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);

#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: done reading content\n");
#endif
  FREENONNULL(escapedHash);

  return count;
}

/**
 * Write content to the db.  Always adds a new record
 * (does NOT overwrite existing data).
 *
 * @return SYSERR on error, OK if ok.
 */
static int put(const HashCode512 * key,
	       const Datastore_Value * value) {
  char *escapedBlock;
  char *escapedHash;
  int n, hashLen, blockLen;
  sqlite3_stmt *stmt;
  unsigned long rowLen;
  unsigned int contentSize;

  if ( (ntohl(value->size) < sizeof(Datastore_Value)) ) {
    BREAK();
    return SYSERR;
  }

#if DEBUG_SQLITE
  LOG(LOG_DEBUG,
      "Storing in database block with type %u.\n",
      ntohl(*(int*)&value[1]));
#endif

  MUTEX_LOCK(&dbh->DATABASE_Lock_);

  if (dbh->lastSync > 1000)
    syncStats(dbh);

  rowLen = 0;
  contentSize = ntohl(value->size)-sizeof(Datastore_Value);

  escapedHash = MALLOC(2*sizeof(HashCode512)+1);
  hashLen = sqlite_encode_binary((const char *) key,
				 sizeof(HashCode512),
				 escapedHash);

  escapedBlock = MALLOC(2 * contentSize + 1);
  blockLen = sqlite_encode_binary((const char *) &value[1],
				  contentSize,
				  escapedBlock);

  stmt = dbh->insertContent;
  sqlite3_bind_int(stmt, 1, ntohl(value->size));
  sqlite3_bind_int(stmt, 2, ntohl(value->type));
  sqlite3_bind_int(stmt, 3, ntohl(value->prio));
  sqlite3_bind_int(stmt, 4, ntohl(value->anonymityLevel));
  sqlite3_bind_int64(stmt, 5, ntohll(value->expirationTime));
  sqlite3_bind_blob(stmt, 6, escapedHash, hashLen, SQLITE_TRANSIENT);
  sqlite3_bind_blob(stmt, 7, escapedBlock, blockLen, SQLITE_TRANSIENT);

  n = sqlite3_step(stmt);
  FREE(escapedBlock);
  FREE(escapedHash);
  sqlite3_reset(stmt);
  if(n != SQLITE_DONE) {
    LOG_SQLITE(LOG_ERROR,
	       "sqlite_query");
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }
  dbh->lastSync++;
  dbh->payload += (hashLen + blockLen + sizeof(long long) * 5);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);

#if DEBUG_SQLITE
  LOG(LOG_DEBUG,
      "SQLite: done writing content\n");
#endif

  return OK;
}

/**
 * Delete an item from the datastore.
 *
 * @param value maybe NULL, then all items under the
 *        given key are deleted
 * @return the number of items deleted, 0 if
 *        none were found, SYSERR on errors
 */
static int del(const HashCode512 * key,
	       const Datastore_Value * value) {
  char *escapedHash;
  size_t n;
  sqlite3_stmt *stmt;
  unsigned long rowLen;
  int deleted, hashLen;
  char * escapedBlock;
  int blockLen;
  unsigned long contentSize;

#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: delete block\n");
#endif

  MUTEX_LOCK(&dbh->DATABASE_Lock_);

  if (dbh->lastSync > 1000)
    syncStats(dbh);

  escapedHash = MALLOC(2 * sizeof(HashCode512) + 1);
  hashLen = sqlite_encode_binary((const char *)key,
				 sizeof(HashCode512),
				 escapedHash);
  if (!value) {
    sqlite3_bind_blob(dbh->exists,
		      1,
		      escapedHash,
		      hashLen,
		      SQLITE_TRANSIENT);
    while(sqlite3_step(dbh->exists) == SQLITE_ROW) {	
      rowLen = sqlite3_column_int(dbh->exists, 0) +
	sqlite3_column_int(dbh->exists, 1) + 5 * sizeof(int);

      if (dbh->payload > rowLen)
	dbh->payload -= rowLen;
      else
	dbh->payload = 0;

      dbh->lastSync++;
    }
    sqlite3_reset(dbh->exists);

    n = sq_prepare("DELETE FROM gn070 WHERE hash = ?", /*  ORDER BY prio ASC LIMIT 1" -- not available */
		   &stmt);
    if (n == SQLITE_OK) {
      sqlite3_bind_blob(stmt,
			1,
			escapedHash,
			hashLen,
			SQLITE_TRANSIENT);
      n = sqlite3_step(stmt);
    }
  } else {
    n = sq_prepare("DELETE FROM gn070 WHERE hash = ? and "
		   "value = ? AND size = ? AND type = ? AND prio = ? AND anonLevel = ? "
		   "AND expire = ?", /* ORDER BY prio ASC LIMIT 1" -- not available in sqlite */
		   &stmt);
    if (n == SQLITE_OK) {
      escapedBlock = MALLOC(2 * (ntohl(value->size)-sizeof(Datastore_Value)) + 1);

      contentSize = ntohl(value->size)-sizeof(Datastore_Value);
      blockLen = sqlite_encode_binary((const char *) &value[1],
				      contentSize,
				      escapedBlock);
      sqlite3_bind_blob(stmt, 1, escapedHash, hashLen, SQLITE_TRANSIENT);
      sqlite3_bind_blob(stmt, 2, escapedBlock, blockLen, SQLITE_TRANSIENT);
      sqlite3_bind_int(stmt, 3, ntohl(value->size));
      sqlite3_bind_int(stmt, 4, ntohl(value->type));
      sqlite3_bind_int(stmt, 5, ntohl(value->prio));
      sqlite3_bind_int(stmt, 6, ntohl(value->anonymityLevel));
      sqlite3_bind_int64(stmt, 7, ntohll(value->expirationTime));
      n = sqlite3_step(stmt);
      FREE(escapedBlock);
      if ( (n == SQLITE_DONE) || (n == SQLITE_ROW) )
	dbh->payload -= (hashLen + blockLen + 5 * sizeof(long long));
    } else {
      LOG_SQLITE(LOG_ERROR, "sqlite3_prepare");
    }
  }
  deleted = ( (n == SQLITE_DONE) || (n == SQLITE_ROW) ) ? sqlite3_changes(dbh->dbf) : SYSERR;

  FREE(escapedHash);
  sqlite3_finalize(stmt);

  if(n != SQLITE_DONE) {
    LOG_SQLITE(LOG_ERROR, "sqlite_query");
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }

  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);

#if DEBUG_SQLITE
  LOG(LOG_DEBUG,
      "SQLite: %d block(s) deleted\n",
      deleted);
#endif

  return deleted;
}

/**
 * Update the priority for a particular key
 * in the datastore.
 */
static int update(const HashCode512 * key,
		  const Datastore_Value * value,
		  int delta) {
  char *escapedHash, *escapedBlock;
  int hashLen, blockLen, n;
  unsigned long contentSize;

#if DEBUG_SQLITE
  LOG(LOG_DEBUG,
      "SQLite: update block\n");
#endif

  MUTEX_LOCK(&dbh->DATABASE_Lock_);

  contentSize = ntohl(value->size)-sizeof(Datastore_Value);

  escapedHash = MALLOC(2*sizeof(HashCode512)+1);
  hashLen = sqlite_encode_binary((const char *) key,
				 sizeof(HashCode512),
				 escapedHash);
  escapedBlock = MALLOC(2*contentSize+1);
  blockLen = sqlite_encode_binary((const char *) &value[1],
				  contentSize,
				  escapedBlock);
  sqlite3_bind_int(dbh->updPrio,
		   1,
		   delta);
  sqlite3_bind_blob(dbh->updPrio,
		    2,
		    escapedHash,
		    hashLen,
		    SQLITE_TRANSIENT);
  sqlite3_bind_blob(dbh->updPrio,
		    3,
		    escapedBlock,
		    blockLen,
		    SQLITE_TRANSIENT);
  sqlite3_bind_int(dbh->updPrio,
		   4,
		   delta);
  sqlite3_bind_int(dbh->updPrio,
		   5,
		   MAX_PRIO);

  n = sqlite3_step(dbh->updPrio);
  sqlite3_reset(dbh->updPrio);

  FREE(escapedHash);
  FREE(escapedBlock);

  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);

#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: block updated\n");
#endif

  return n == SQLITE_OK ? OK : SYSERR;
}


SQstore_ServiceAPI *
provide_module_sqstore_sqlite(CoreAPIForApplication * capi) {
  static SQstore_ServiceAPI api;

  char *dir, *afsdir;
  size_t nX;
  sqlite3_stmt *stmt;

#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: initializing database\n");
#endif

  dbh = MALLOC(sizeof(sqliteHandle));

  dbh->payload = 0;
  dbh->lastSync = 0;

  afsdir = getFileName("FS", "DIR",
		       _("Configuration file must specify directory for "
			 "storing FS data in section '%s' under '%s'.\n"));
  dir = MALLOC(strlen(afsdir) + 8 + 2); /* 8 = "content/" */
  strcpy(dir, afsdir);
  strcat(dir, "/content/");
  FREE(afsdir);
  mkdirp(dir);
  nX = strlen(dir) + 6 + 4 + 256;  /* 6 = "gnunet", 4 = ".dat" */
  dbh->fn = MALLOC(strlen(dir) + 6 + 4 + 256);
  SNPRINTF(dbh->fn, nX, "%s/gnunet.dat", dir);
  FREE(dir);

  if (sqlite3_open(dbh->fn, &dbh->dbf) != SQLITE_OK) {
    LOG(LOG_ERROR,
        _("Unable to initialize SQLite.\n"));
    FREE(dbh->fn);
    FREE(dbh);
    return NULL;
  }

  sqlite3_exec(dbh->dbf, "PRAGMA temp_store=MEMORY", NULL, NULL, NULL);
  sqlite3_exec(dbh->dbf, "PRAGMA synchronous=OFF", NULL, NULL, NULL);
  sqlite3_exec(dbh->dbf, "PRAGMA count_changes=OFF", NULL, NULL, NULL);

  sq_prepare("Select 1 from sqlite_master where tbl_name = 'gn070'",
	     &stmt);
  if (sqlite3_step(stmt) == SQLITE_DONE) {
    if (sqlite3_exec(dbh->dbf,
		     "CREATE TABLE gn070 ("
		     "  size INTEGER NOT NULL DEFAULT 0,"
		     "  type INTEGER NOT NULL DEFAULT 0,"
		     "  prio INTEGER NOT NULL DEFAULT 0,"
		     "  anonLevel INTEGER NOT NULL DEFAULT 0,"
		     "  expire INTEGER NOT NULL DEFAULT 0,"
		     "  hash TEXT NOT NULL DEFAULT '',"
		     "  value BLOB NOT NULL DEFAULT '')", NULL, NULL,
		     NULL) != SQLITE_OK) {
      LOG_SQLITE(LOG_ERROR, "sqlite_query");
      FREE(dbh->fn);
      FREE(dbh);
      return NULL;
    }
  }
  sqlite3_finalize(stmt);

  sqlite3_exec(dbh->dbf, "CREATE INDEX idx_hash ON gn070 (hash)",
	       NULL, NULL, NULL);
  sqlite3_exec(dbh->dbf, "CREATE INDEX idx_prio ON gn070 (prio)",
	       NULL, NULL, NULL);
  sqlite3_exec(dbh->dbf, "CREATE INDEX idx_expire ON gn070 (expire)",
	       NULL, NULL, NULL);

  if ( (sq_prepare("SELECT COUNT(*) FROM gn070 WHERE hash=?",
		   &dbh->countContent) != SQLITE_OK) ||
       (sq_prepare("SELECT LENGTH(hash), LENGTH(value) "
		   "FROM gn070 WHERE hash=?",
		   &dbh->exists) != SQLITE_OK) ||					
       (sq_prepare("UPDATE gn070 SET prio = prio + ? WHERE "
		   "hash = ? AND value = ? AND prio + ? < ?",
		   &dbh->updPrio) != SQLITE_OK) ||
       (sq_prepare("INSERT INTO gn070 (size, type, prio, "
		   "anonLevel, expire, hash, value) VALUES "
		   "(?, ?, ?, ?, ?, ?, ?)",
		   &dbh->insertContent) != SQLITE_OK) ) {
    LOG_SQLITE(LOG_ERROR,
	       "precompiling");
    FREE(dbh->fn);
    FREE(dbh);
    return NULL;
  }

  dbh->payload = getStat("PAYLOAD");

  if (dbh->payload == SYSERR) {
    FREE(dbh->fn);
    FREE(dbh);
    return NULL;
  }

  MUTEX_CREATE(&dbh->DATABASE_Lock_);

  api.getSize = &getSize;
  api.put = &put;
  api.get = &get;
  api.iterateLowPriority = &iterateLowPriority;
  api.iterateExpirationTime = &iterateExpirationTime;
  api.del = &del;
  api.drop = &drop;
  api.update = &update;
  return &api;
}

/**
 * Shutdown the module.
 */
void release_module_sqstore_sqlite() {
  sqlite_shutdown();
}

/* end of sqlite.c */
