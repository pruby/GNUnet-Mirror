/*
     This file is part of GNUnet.
     (C) 2001 - 2005 Christian Grothoff (and other contributing authors)

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
  char *fn;                /* filename of this bucket */
  double payload;          /* bytes used */
  unsigned int lastSync;
  
  /* Precompiled SQL */
  sqlite3_stmt *exists, *countContent, *updPrio, *insertContent;
} sqliteHandle;

static sqliteHandle *dbh;


static Datastore_Datum * assembleDatum(sqlite3_stmt *stmt);
static double getStat(char *key);
static int setStat(char *key, double val);
static int sqlite_iterate(unsigned int type, Datum_Iterator iter,
	void *closure, int sort);
static int iterateLowPriority(unsigned int type, Datum_Iterator iter,
	void * closure);
static int iterateExpirationTime(unsigned int type, Datum_Iterator iter,
	void * closure);
static int get(const HashCode160 * key, unsigned int type, Datum_Iterator iter,
	void * closure);
static int put(const HashCode160 * key, const Datastore_Value * value);
static int del(const HashCode160 * key, const Datastore_Value * value);
static int update(const HashCode160 * key, const Datastore_Value * value,
	int delta);
static unsigned long long getSize();
static void drop();

/**
 * @brief Encode a binary buffer "in" of size n bytes so that it contains
 *        no instances of characters '\'' or '\000'.  The output is
 *        null-terminated and can be used as a string value in an INSERT
 *        or UPDATE statement.
 * @param in input
 * @param n size of in
 * @param out output
 */
static int sqlite_encode_binary(const unsigned char *in, int n, unsigned char *out){
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

#if 0
/**
 * @brief Decode the string "in" into binary data and write it into "out".
 * @param in input
 * @param out output
 * @return number of output bytes, -1 on error
 */
static int sqlite_decode_binary(const unsigned char *in,
				unsigned char *out){
  char c;
  unsigned char *start = out;
  
  while((c = *in)) {
    if (c == 1) {
      in++;
      *out = *in - 1;
    }
    else
      *out = c;
    
    in++;
    out++;
  }
  
  return (int) (out - start);
}
#endif

/**
 * @brief Decode the string "in" into binary data and write it into "out".
 * @param in input
 * @param out output
 * @param num size of the output buffer
 * @return number of output bytes, -1 on error
 */
static int sqlite_decode_binary_n(const unsigned char *in, unsigned char *out,
	unsigned int num){
  char c;
  unsigned char *start = out;
  
  while((c = *in) && (out - start < num)) {
    if (c == 1) {
      in++;
      *out = *in - 1;
    }
    else
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
  int contentSize;
    
  contentSize = sqlite3_column_int(stmt, 0) - sizeof(Datastore_Value);
  
  if (contentSize < 0)
  	return NULL; /* error */
  	
  if (sqlite3_column_bytes(stmt, 5) > sizeof(HashCode160) * 2 + 1 ||
  		sqlite3_column_bytes(stmt, 6) > contentSize * 2 + 1) {
  			
		LOG(LOG_WARNING,
			_("SQL Database corrupt, ignoring result.\n"));
		return NULL;
  }

  datum = MALLOC(sizeof(Datastore_Datum) + contentSize);
  datum->value.size = htonl(contentSize + sizeof(Datastore_Value));
  datum->value.type = htonl(sqlite3_column_int(stmt, 1));
  datum->value.prio = htonl(sqlite3_column_int(stmt, 2));
  datum->value.anonymityLevel = htonl(sqlite3_column_int(stmt, 3));
  datum->value.expirationTime = htonll(sqlite3_column_int64(stmt, 4));
	
	if (sqlite_decode_binary_n(sqlite3_column_blob(stmt, 5), (char *) &datum->key,
				sizeof(HashCode160)) != sizeof(HashCode160) ||
			sqlite_decode_binary_n(sqlite3_column_blob(stmt, 6), (char *) &datum[1], 
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
static double getStat(char *key) {
  int i;
  sqlite3_stmt *stmt;
  double ret = SYSERR;
  char *dummy;

  i = sqlite3_prepare(dbh->dbf, 
    "Select anonLevel from gn070 where hash = ?", 42, &stmt,
    (const char **) &dummy);
  if (i == SQLITE_OK) {
    sqlite3_bind_text(stmt, 1, key, strlen(key), SQLITE_STATIC);
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
static int setStat(char *key, double val) {
  sqlite3_stmt *stmt;
  char *dummy;

  if (sqlite3_prepare(dbh->dbf,
        "REPLACE into gn070(hash, anonLevel, type) values (?, ?, ?)", 58,
        &stmt, (const char **) &dummy) == SQLITE_OK) {
    sqlite3_bind_text(stmt, 1, key, strlen(key), SQLITE_STATIC);
    sqlite3_bind_double(stmt, 2, val);
    sqlite3_bind_int(stmt, 3, RESERVED_BLOCK);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
      LOG_SQLITE(LOG_ERROR, "sqlite_setStat");

      return SYSERR;
    }
    sqlite3_finalize(stmt);

    return OK;    
  }
  else
    return SYSERR;
}

/**
 * @brief write all statistics to the db
 */
static void syncStats() {
  setStat("PAYLOAD", dbh->payload);
  
  dbh->lastSync = 0;
}

SQstore_ServiceAPI *
provide_module_sqstore_sqlite(CoreAPIForApplication * capi) {
  static SQstore_ServiceAPI api;

  char *dummy, *dir, *afsdir;
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
  
  sqlite3_prepare(dbh->dbf, "Select 1 from sqlite_master where tbl_name"
    " = 'gn070'", 52, &stmt, (const char**) &dummy);
  if (sqlite3_step(stmt) == SQLITE_DONE) {
    if (sqlite3_exec(dbh->dbf, "CREATE TABLE gn070 ("
           "  size integer NOT NULL default 0,"
           "  type integer NOT NULL default 0,"
           "  prio integer NOT NULL default 0,"
           "  anonLevel integer NOT NULL default 0,"
           "  expire integer NOT NULL default 0,"
           "  hash text NOT NULL default '',"
           "  value blob NOT NULL default '')", NULL, NULL,
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

  if (sqlite3_prepare(dbh->dbf, "SELECT count(*) FROM gn070 where hash=?", 39,
         &dbh->countContent, (const char **) &dummy) != SQLITE_OK ||
     
      sqlite3_prepare(dbh->dbf, "SELECT length(hash), length(value), "
         "from gn070 WHERE hash=?", 59,
         &dbh->exists, (const char **) &dummy) != SQLITE_OK ||

      sqlite3_prepare(dbh->dbf, "UPDATE gn070 SET prio = prio + ? where "
              "hash = ? and value = ? and prio + ? < ?", 78, &dbh->updPrio,
              (const char **) &dummy) != SQLITE_OK ||

      sqlite3_prepare(dbh->dbf, "insert into gn070 (size, type, prio, "
              "anonLevel, expire, hash, value) values "
              "(?, ?, ?, ?, ?, ?, ?)", 97, &dbh->insertContent,
              (const char **) &dummy) != SQLITE_OK) {
        
      LOG_SQLITE(LOG_ERROR, "precompiling");
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
    
  MUTEX_CREATE_RECURSIVE(&dbh->DATABASE_Lock_);  

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
 * Shutdown the module.
 */
void release_module_sqstore_sqlite() {
  sqlite_shutdown();  
}

/**
 * Call a method for each key in the database and
 * call the callback method on it. 
 *
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param callback the callback method
 * @param data second argument to all callback calls
 * @param sort 0 to order by expiration, 1 to order by prio
 * @return the number of items stored in the content database
 */
static int sqlite_iterate(unsigned int type, Datum_Iterator iter,
	void *closure, int sort) {
	
  sqlite3_stmt *stmt;
  int count = 0;
  char *dummy;
  char scratch[107];
  Datastore_Datum * datum;

#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: iterating through the database\n");
#endif 

  MUTEX_LOCK(&dbh->DATABASE_Lock_);

	sprintf(scratch, "SELECT size, type, prio, anonLevel, expire, hash, value "
					 "FROM gn070 %s order by %s ASC",
					 type ? "where type = :1" : "", sort ? "prio" : "expire");

  if (sqlite3_prepare(dbh->dbf, scratch, -1, &stmt,
           (const char **) &dummy) != SQLITE_OK) {
    LOG_SQLITE(LOG_ERROR, "sqlite_query");
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return(SYSERR);
  }

	if (type)
		sqlite3_bind_int(stmt, 1, type);

  while (sqlite3_step(stmt) == SQLITE_ROW) {
		datum = assembleDatum(stmt);
		
    if (datum == NULL) {
      LOG(LOG_WARNING,
	  		_("Invalid data in database.  Please verify integrity!\n"));
      continue; 
    }

    if( SYSERR == iter(&datum->key, &datum->value, closure) ) {
      count = SYSERR;
      FREE(datum);
      break;
    }
    FREE(datum);

    count++;
  }
    
  sqlite3_finalize(stmt);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  
#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: reached end of database\n");
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
static int get(const HashCode160 * key, 
	       unsigned int type,
	       Datum_Iterator iter,
	       void * closure) {
  char *escapedHash = NULL;
  int len, ret, count = 0;
  sqlite3_stmt *stmt;
  char scratch[97], *dummy;
  int bind = 1;
  Datastore_Datum *datum;

#if DEBUG_SQLITE
  {
    char block[33];
    hash2enc(query, (EncName *) key);
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
  
  if (sqlite3_prepare(dbh->dbf, scratch, -1, &stmt,
           (const char **) &dummy) != SQLITE_OK) {
    LOG_SQLITE(LOG_ERROR, "sqlite_query");
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return(SYSERR);
  }  
  
  if (type)
  	ret = sqlite3_bind_int(stmt, bind++, type);
  else
  	ret = SQLITE_OK;
  	
  if (key && ret == SQLITE_OK) {
	  escapedHash = MALLOC(sizeof(HashCode160)*2 + 2);
	  len = sqlite_encode_binary((char *) key, sizeof(HashCode160), escapedHash);
	
	  ret = sqlite3_bind_blob(stmt, bind, escapedHash, len,
	    SQLITE_TRANSIENT);
  }

  if (ret == SQLITE_OK) {
    
    while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
			if (iter == NULL) {
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
				if( SYSERR == iter(&datum->key,
							&datum->value, 
							closure) ) {

					count = SYSERR;
		      FREE(datum);
		      break;
		    }
		    FREE(datum);								
			  
			  count++;
			}
			else
				count += sqlite3_column_int(stmt, 0);
    }

    FREENONNULL(escapedHash);
    sqlite3_finalize(stmt);

	  if (ret != SQLITE_OK) {
	    LOG_SQLITE(LOG_ERROR, "sqlite_query");
	    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
	    return SYSERR;
	  }
  }
  else
  	LOG_SQLITE(LOG_ERROR, "sqlite_query");
  
	MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  
#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: done reading content\n");
#endif 
  
  return count;
}

/**
 * Write content to the db.  Always adds a new record
 * (does NOT overwrite existing data).
 *
 * @return SYSERR on error, OK if ok.
 */
static int put(const HashCode160 * key, 
	       const Datastore_Value * value) {
  char *escapedBlock;
  char *escapedHash;
  int n, hashLen, blockLen;
  sqlite3_stmt *stmt;
  unsigned long rowLen;
	unsigned int contentSize;
	
  if ( (ntohl(value->size) <= sizeof(Datastore_Value)) ) {
    BREAK();
    return SYSERR;
  }

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  
  if (dbh->lastSync > 1000)
    syncStats(dbh);
  
  rowLen = 0;
  contentSize = ntohl(value->size)-sizeof(Datastore_Value);
 
  escapedHash = MALLOC(2*sizeof(HashCode160)+1);
  hashLen = sqlite_encode_binary((char *) key, sizeof(HashCode160), escapedHash);
    
  escapedBlock = MALLOC(2 * contentSize + 1);
  blockLen = sqlite_encode_binary((char *) &value[1], contentSize, escapedBlock);

#if DEBUG_SQLITE
  LOG(LOG_DEBUG,
      "Storing in database block with type %u.\n",
      ntohl(*(int*)&value[1]));
#endif

	stmt = dbh->insertContent;
	sqlite3_bind_double(stmt, 1, ntohl(value->size));
	sqlite3_bind_double(stmt, 2, ntohl(value->type));
	sqlite3_bind_double(stmt, 3, ntohl(value->prio));
	sqlite3_bind_double(stmt, 4, ntohl(value->anonymityLevel));
	sqlite3_bind_double(stmt, 5, ntohll(value->expirationTime));
	sqlite3_bind_blob(stmt, 6, escapedHash, hashLen, SQLITE_TRANSIENT);
	sqlite3_bind_blob(stmt, 7, escapedBlock, blockLen, SQLITE_TRANSIENT);
	
  n = sqlite3_step(stmt);
  FREE(escapedBlock);
  FREE(escapedHash);
  sqlite3_reset(stmt);
  if(n != SQLITE_DONE) {
    LOG_SQLITE(LOG_ERROR, "sqlite_query");
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }
  dbh->lastSync++;
  dbh->payload += (hashLen + blockLen + sizeof(long long) * 5);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
 
#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: done writing content\n");
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
static int del(const HashCode160 * key, 
	       const Datastore_Value * value) {
  char *escapedHash, *dummy;
  size_t n;
  sqlite3_stmt *stmt;
  unsigned long rowLen;
  int deleted, hashLen;

#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: delete block\n");
#endif 

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  
  if (dbh->lastSync > 1000)
    syncStats(dbh);
  
  escapedHash = MALLOC(2 * sizeof(HashCode160) + 1);
  hashLen = sqlite_encode_binary((char *)key, sizeof(HashCode160), escapedHash);

	if (!value) {
	  sqlite3_bind_blob(dbh->exists, 1, escapedHash, hashLen,
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

	  n = sqlite3_prepare(dbh->dbf, "DELETE FROM gn070 WHERE hash = ?", 32, 
	  	&stmt, (const char **) &dummy);
	  if (n == SQLITE_OK) {
	    sqlite3_bind_blob(stmt, 1, escapedHash, hashLen, SQLITE_TRANSIENT);
	    n = sqlite3_step(stmt);
	  }
	}
	else {
		sqlite3_stmt *stmt;

	  n = sqlite3_prepare(dbh->dbf, "DELETE FROM gn070 WHERE hash = ? and "
	  			"value = ? and size = ? and type = ? and prio = ? and anonLevel = ? "
	  			"expire = ?", 114, &stmt, (const char **) &dummy);
	  if (n == SQLITE_OK) {
	  	char *escapedBlock;
	  	int hashLen, blockLen;
	  	
	  	escapedBlock = MALLOC(2 * (ntohl(value->size)-sizeof(Datastore_Value)) + 1);
	  	
	  	hashLen = strlen(escapedHash);
	  	blockLen = strlen(escapedBlock);
	  	
	    sqlite3_bind_blob(stmt, 1, escapedHash, hashLen, SQLITE_TRANSIENT);
	    sqlite3_bind_blob(stmt, 2, escapedBlock, blockLen, SQLITE_TRANSIENT);
			sqlite3_bind_double(stmt, 3, ntohl(value->size));
			sqlite3_bind_double(stmt, 4, ntohl(value->type));
			sqlite3_bind_double(stmt, 5, ntohl(value->prio));
			sqlite3_bind_double(stmt, 6, ntohl(value->anonymityLevel));
			sqlite3_bind_double(stmt, 7, ntohll(value->expirationTime));

	    n = sqlite3_step(stmt);
	    
	    FREE(escapedBlock);
	    
	    if (n == SQLITE_OK)
	    	dbh->payload -= (hashLen + blockLen + 5 * sizeof(long long));
	  }
	}
	
  deleted = (n == SQLITE_OK) ? sqlite3_changes(dbh->dbf) : SYSERR;
	  
  FREE(escapedHash);
  sqlite3_finalize(stmt);

  if(n != SQLITE_DONE) {
    LOG_SQLITE(LOG_ERROR, "sqlite_query");
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }

  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  
#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite: %i block(s) deleted\n", deleted);
#endif 
  
  return deleted;
}

/**
 * Update the priority for a particular key
 * in the datastore.
 */
static int update(const HashCode160 * key,
		  const Datastore_Value * value,
		  int delta) {
  char *escapedHash, *escapedBlock;
  int hashLen, blockLen, n;
  unsigned long contentSize;
	
  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  contentSize = ntohl(value->size)-sizeof(Datastore_Value);
  
  escapedHash = MALLOC(2*sizeof(HashCode160)+1);
  hashLen = sqlite_encode_binary((const char *) key,
				 sizeof(HashCode160),
				 escapedHash);  
  escapedBlock = MALLOC(2*contentSize+1);
  blockLen = sqlite_encode_binary((const char *) value, 
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
  sqlite3_bind_int64(dbh->updPrio, 
		     5, 
		     MAX_PRIORITY);
  
  n = sqlite3_step(dbh->updPrio);
  sqlite3_reset(dbh->updPrio);
  
  FREE(escapedHash);
  FREE(escapedBlock);

  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);

  return n == SQLITE_OK ? OK : SYSERR;
}

/**
 * Get the current on-disk size of the SQ store.
 * Estimates are fine, if that's the only thing
 * available.
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
 * Delete the database.  The next operation is
 * guaranteed to be unloading of the module.
 */
static void drop() {
  char *fn = STRDUP(dbh->fn);  
  sqlite_shutdown();  
  UNLINK(fn);
}
 
/* end of sqlite.c */
