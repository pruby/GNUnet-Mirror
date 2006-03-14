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
 * @file applications/kvstore_sqlite/kv_sqlite.c
 * @brief SQLite based implementation of the kvstore service
 * @author Nils Durner
 *
 * @todo Indexes, statistics
 * 
 * Database: SQLite
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_kvstore_service.h"
#include <sqlite3.h>

#define DEBUG_SQLITE NO

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define DIE_SQLITE(cmd) do { errexit(_("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(dbh->dbh)); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_SQLITE(level, cmd) do { fprintf(stderr, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(dbh->dbh)); } while(0);

static CoreAPIForApplication * coreAPI;

/**
 * @brief Wrapper for SQLite
 */
typedef struct {
  /* Native SQLite database handle - may not be shared between threads! */
  sqlite3 *dbh;
  /* Thread ID owning this handle */
  pthread_t tid;
  /* Synchronized access to sqlite */
  Mutex *DATABASE_Lock_;
} sqliteHandle;

/**
 * @brief Information about the database
 */
typedef struct {
  Mutex DATABASE_Lock_;
  /** name of the database */
  char *name;  
  /** filename of this database */
  char *fn;
  /** bytes used */
  double payload;
  unsigned int lastSync;
  
  /* Open handles */
  unsigned int handle_count;
  
  /* List of open handles */
  sqliteHandle *handles;  

 /* Is database closed? */
 int closed;
} sqliteDatabase;


static unsigned int databases = 0;
static sqliteDatabase *dbs;

static sqliteHandle *getDBHandle(const char *name);

static Mutex databasesLock;

/**
 * @brief Encode a binary buffer "in" of size n bytes so that it contains
 *        no instances of character '\000'.
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
  unsigned char *start = out;
  unsigned char *stop = (unsigned char *) (in + num);

  while(in != stop) {
    if (*in == 1) {
      in++;
      *out = *in - 1;
    } else
      *out = *in;
    in++;
    out++;
  }
  return (int) (out - start);
}

/**
 * @brief Prepare a SQL statement
 */
static int sq_prepare(sqliteHandle *dbh,
          const char *zSql,       /* SQL statement, UTF-8 encoded */
          sqlite3_stmt **ppStmt) {  /* OUT: Statement handle */
  char * dummy;
  return sqlite3_prepare(dbh->dbh,
       zSql,
       strlen(zSql),
       ppStmt,
       (const char**) &dummy);
}

/**
 * @brief Create new database structure
 */
static void new_db(sqliteDatabase *db, const char *name)
{
  char *dir;
  unsigned int mem;
  
  memset(db, sizeof(sqliteDatabase), 0);
  
  MUTEX_CREATE(&db->DATABASE_Lock_);
  
  /* Get path to database file */
  dir = getFileName("KEYVALUE_DATABASE", "DIR",
           _("Configuration file must specify directory for "
           "storing data in section `%s' under `%s'.\n"));
           
  if (dir != NULL)
    mem = strlen(dir);
  else
    mem = 0;
    
  mkdirp(dir);
    
  mem += strlen(name) + 6; /* 6 = "/" + ".dat" */
   
  db->fn = (char *) MALLOC(mem);
  sprintf(db->fn, "%s/%s.dat", dir, name);
  FREE(dir);
  
  db->name = STRDUP(name);
}

/**
 * @brief Get information about an open database
 * @param name the name of the database
 */
static sqliteDatabase *getDB(const char *name)
{
  unsigned int idx;
  
  for(idx = 0; idx < databases; idx++)
    if (!dbs[idx].closed && strcmp(dbs[idx].name, name) == 0)
      return dbs + idx;

  return NULL;
}

/**
 * @brief Get a database handle for this thread.
 * @note SQLite handles may no be shared between threads - see
 *        http://permalink.gmane.org/gmane.network.gnunet.devel/1377
 *       We therefore (re)open the database in each thread.
 * @return the native SQLite database handle
 */
static sqliteHandle *getDBHandle(const char *name) {
  unsigned int idx;
  pthread_t this_tid;
  sqliteHandle *dbh = NULL;
  sqliteDatabase *db = NULL;
  
  MUTEX_LOCK(&databasesLock);
  
  /* Is database already open? */
  db = getDB(name);  
  if (db == NULL)
  {
    GROW(dbs, databases, databases + 1);
    db = dbs + databases - 1;
    
    new_db(db, name);
  }

  MUTEX_UNLOCK(&databasesLock);

  MUTEX_LOCK(&db->DATABASE_Lock_);
  
  /* Was it opened by this thread? */
  this_tid = pthread_self();
  for (idx = 0; idx < db->handle_count; idx++)
    if (pthread_equal(db->handles[idx].tid, this_tid)) {
      dbh = db->handles + idx;
      break;
    }
  
  if (idx == db->handle_count) {
    /* we haven't opened the DB for this thread yet */
    GROW(db->handles,
  	 db->handle_count,
  	 db->handle_count + 1);
    dbh = db->handles + db->handle_count - 1;
    dbh->tid = this_tid;
    dbh->DATABASE_Lock_ = &db->DATABASE_Lock_;

    /* Open database */
    if (sqlite3_open(db->fn, &dbh->dbh) != SQLITE_OK) {
      LOG(LOG_ERROR,
          _("Unable to initialize SQLite KVStore.\n"));
      
      FREE(db->fn);
      FREE(db);
      return NULL;
    }

    sqlite3_exec(dbh->dbh, "PRAGMA temp_store=MEMORY", NULL, NULL, NULL);
    sqlite3_exec(dbh->dbh, "PRAGMA synchronous=OFF", NULL, NULL, NULL);
    sqlite3_exec(dbh->dbh, "PRAGMA count_changes=OFF", NULL, NULL, NULL);
    sqlite3_exec(dbh->dbh, "PRAGMA page_size=4096", NULL, NULL, NULL);
  }

  MUTEX_UNLOCK(&db->DATABASE_Lock_);

  return dbh;
}

static void close_database(sqliteDatabase *db)
{
  unsigned int idx;

  for (idx = 0; idx < db->handle_count; idx++) {
    sqliteHandle *dbh = db->handles + idx;

    if (sqlite3_close(dbh->dbh) != SQLITE_OK)
      LOG_SQLITE(LOG_ERROR, "sqlite_close");
  }
  FREE(db->handles);
  db->handle_count = 0;

  MUTEX_DESTROY(&db->DATABASE_Lock_);
  FREE(db->fn);
  FREE(db->name);

  db->closed = 1;
}

static void shutdown_database(sqliteDatabase *db)
{
  FREE(db);
}

static void sqlite_shutdown() {
  unsigned int idx;
  
#if DEBUG_SQLITE
  LOG(LOG_DEBUG, "SQLite KVStore: closing database\n");
#endif

  for (idx = 0; idx < databases; idx++)
    if (!dbs[idx].closed)
    {
      close_database(dbs + idx);
      shutdown_database(dbs + idx);
    }
  
  GROW(dbs, databases, 0);
}

/**
 * @brief Delete the database.
 */
static void dropDatabase(const char *name) {
  sqliteDatabase *db = getDB(name);

  char *fn = STRDUP(db->fn);
  close_database(db);
  UNLINK(fn);
  FREE(fn);
  db->closed = 1;
}

/**
 * @brief Open a Key/Value-Table
 * @param table the name of the Key/Value-Table
 * @return a handle
 */
static KVHandle *getTable(const char *database, const char *table)
{
  sqlite3_stmt *stmt;
  unsigned int len;
  KVHandle *ret;
  sqliteHandle *dbh;
  char *idx;
  
  dbh = getDBHandle(database);
  MUTEX_LOCK(dbh->DATABASE_Lock_);
  
  sq_prepare(dbh, "Select 1 from sqlite_master where tbl_name = ?",
       &stmt);
  len = strlen(table);
  sqlite3_bind_text(stmt, 1, table, len, SQLITE_STATIC);
  if (sqlite3_step(stmt) == SQLITE_DONE)
  {
    char *create = malloc(len + 58);
    
    sprintf(create, "CREATE TABLE %s (gn_key BLOB, gn_val BLOB, gn_age BIGINT)", table);
    
    if (sqlite3_exec(dbh->dbh, create, NULL, NULL, NULL) != SQLITE_OK)
    {
      LOG_SQLITE(LOG_ERROR, "sqlite_create");
      sqlite3_finalize(stmt);
      free(create);
      MUTEX_UNLOCK(dbh->DATABASE_Lock_);
      return NULL;
    }
    
    free(create);
  }
  sqlite3_finalize(stmt);  

  /* FIXME: more indexes */
  idx = (char *) malloc(len + 34);
  sprintf(idx, "CREATE INDEX idx_key ON %s (gn_key)", table);
  sqlite3_exec(dbh->dbh, idx, NULL, NULL, NULL);
  
  MUTEX_UNLOCK(dbh->DATABASE_Lock_);

  ret = MALLOC(sizeof(KVHandle));
  ret->table = STRDUP(table);
  ret->db = STRDUP(database);
  
  return ret;
}

/**
 * @brief Get data from a Key/Value-Table
 * @param kv handle to the table
 * @param key the key to retrieve
 * @param keylen length of the key
 * @param sort 0 = dont, sort, 1 = random, 2 = sort by age
 * @param limit limit result set to n rows
 * @param handler callback function to be called for every result (may be NULL)
 * @param closure optional parameter for handler
 */
static void *get(KVHandle *kv, void *key, int keylen, unsigned int sort,
  unsigned int limit, KVCallback handler, void *closure)
{
  unsigned int len, enclen, retlen;
  char *sel, *order, *where, limit_spec[30];
  sqlite3_stmt *stmt;
  void *ret;
  sqliteHandle *dbh;
  unsigned char *key_enc;
  void *ret_dec;
  
  ret = NULL;
  ret_dec = NULL;
 
  len = strlen(kv->table); 
  sel = MALLOC(len + 45);
  
  if (key)
  {
    where = "WHERE gn_key = ?";
    key_enc = MALLOC(keylen * 2 + 1);
    enclen = sqlite_encode_binary(key, keylen, key_enc);
  }
  else
  {
    where = "";
    key_enc = NULL;
  }
  
  switch(sort)
  {
    case 1:
      order = "BY RANDOM()";
      break;
    case 2:
      order = "BY gn_age desc";
      break;
    default:
      order = "";
      break;
  }
  
  if (limit != 0)
    sprintf(limit_spec, "LIMIT %u", limit);
  else
    *limit_spec = 0;
  
  sprintf(sel, "SELECT gn_val FROM %s %s %s %s", kv->table, where, order, limit_spec);
  
  dbh = getDBHandle(kv->db);
  MUTEX_LOCK(dbh->DATABASE_Lock_);

  sq_prepare(dbh, sel, &stmt);
  if (key)
    sqlite3_bind_blob(stmt, 1, key_enc, enclen, SQLITE_STATIC);
  while(sqlite3_step(stmt) == SQLITE_ROW)
  {
    retlen = sqlite3_column_bytes(stmt, 0);
    ret = (void *) sqlite3_column_blob(stmt, 0);

    /* free previous result, only the last in the result set
       is returned to the caller */
    FREENONNULL(ret_dec);

    ret_dec = MALLOC(retlen);
    retlen = sqlite_decode_binary_n(ret, ret_dec, retlen);

    if (handler)
      if (handler(closure, ret, retlen) != OK)
      {
        FREE(sel);
	FREENONNULL(key_enc);
        FREE(ret_dec);
        MUTEX_UNLOCK(dbh->DATABASE_Lock_);
        sqlite3_finalize(stmt);
        
        return ret;      
      }
  }
  
  sqlite3_finalize(stmt);

  MUTEX_UNLOCK(dbh->DATABASE_Lock_);
  
  FREE(sel);
  FREENONNULL(key_enc);
  
  return ret_dec;
}

/**
 * @brief Store Key/Value-Pair in a table
 * @param kv handle to the table
 * @param key key of the pair
 * @param keylen length of the key (int because of SQLite!)
 * @param val value of the pair
 * @param vallen length of the value (int because of SQLite!)
 * @param optional creation time
 * @return OK on success, SYSERR otherwise
 */
static int put(KVHandle *kv, void *key, int keylen, void *val, int vallen,
  unsigned long long age)
{
  unsigned int len;
  char *ins;
  sqlite3_stmt *stmt;
  sqliteHandle *dbh;
  unsigned char *key_enc, *val_enc;
  unsigned int keyenc_len, valenc_len;
 
  len = strlen(kv->table); 
  ins = MALLOC(len + 68);
  
  sprintf(ins, "INSERT INTO %s(gn_key, gn_val, gn_age) values (?, ?, ?)", kv->table);
  
  key_enc = MALLOC(keylen * 2);
  keyenc_len = sqlite_encode_binary(key, keylen, key_enc);

  val_enc = MALLOC(vallen * 2);
  valenc_len = sqlite_encode_binary(val, vallen, val_enc);

  dbh = getDBHandle(kv->db);
  MUTEX_LOCK(dbh->DATABASE_Lock_);

  sq_prepare(dbh, ins, &stmt);
  sqlite3_bind_blob(stmt, 1, key_enc, keyenc_len, SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 2, val_enc, valenc_len, SQLITE_STATIC);
  sqlite3_bind_int64(stmt, 3, age);
  if (sqlite3_step(stmt) != SQLITE_DONE)
  {
    FREE(ins);
    FREE(key_enc);
    FREE(val_enc);
    LOG_SQLITE(LOG_ERROR, "put");
    MUTEX_UNLOCK(dbh->DATABASE_Lock_);
    sqlite3_finalize(stmt);
    
    return SYSERR;
  }
  
  sqlite3_finalize(stmt);

  MUTEX_UNLOCK(dbh->DATABASE_Lock_);
  
  FREE(ins);
  FREE(key_enc);
  FREE(val_enc);
  
  return OK;
}

/**
 * @brief Delete values from a Key/Value-Table
 * @param key key to delete (may be NULL)
 * @param keylen length of the key
 * @param age age of the items to delete (may be 0)
 * @return OK on success, SYSERR otherwise
 */
static int del(KVHandle *kv, void *key, int keylen, unsigned long long age)
{
  unsigned int len;
  char *del, *key_where, *age_where;
  sqlite3_stmt *stmt;
  int bind;
  sqliteHandle *dbh;
  unsigned char *keyenc;
  unsigned int keyenc_len;
 
  len = strlen(kv->table); 
  del = MALLOC(len + 52);
  bind = 1;
  
  if (key)
    key_where = "gn_key = ?";
  else
    key_where = "";
  
  if (age)
    age_where = "gn_age = ?";
  else
    age_where = "";
  
  sprintf(del, "DELETE from %s where %s %s %s", kv->table, key_where, age ? "or" : "", age_where);
  
  keyenc = MALLOC(keylen * 2);
  keyenc_len = sqlite_encode_binary(key, keylen, keyenc);

  dbh = getDBHandle(kv->db);
  MUTEX_LOCK(dbh->DATABASE_Lock_);

  sq_prepare(dbh, del, &stmt);
  if (key)
  {
    sqlite3_bind_blob(stmt, 1, keyenc, keyenc_len, SQLITE_STATIC);
    bind++;
  }
  
  if (age)
    sqlite3_bind_int64(stmt, bind, age);

  if (sqlite3_step(stmt) != SQLITE_DONE)
  {
    FREE(del);
    FREE(keyenc);
    LOG_SQLITE(LOG_ERROR, "delete");
    MUTEX_UNLOCK(dbh->DATABASE_Lock_);
    sqlite3_finalize(stmt);
    
    return SYSERR;      
  }
  
  sqlite3_finalize(stmt);

  MUTEX_UNLOCK(dbh->DATABASE_Lock_);
  
  FREE(del);
  FREE(keyenc);
  
  return OK;  
}

/**
 * @brief Close a handle to a Key/Value-Table
 * @param kv the handle to close
 */
static void closeTable(KVHandle *kv)
{
  FREE(kv->table);
  FREE(kv->db);
}

/**
 * @brief Drop a Key/Value-Table
 * @param the handle to the table
 * @return OK on success, SYSERR otherwise
 */
static int dropTable(KVHandle *kv)
{
  sqlite3_stmt *stmt;
  sqliteHandle *dbh;

  char *drop = (void *) MALLOC(12 + strlen(kv->table));
  
  sprintf(drop, "DROP TABLE %s", kv->table);
  dbh = getDBHandle(kv->db);
  MUTEX_LOCK(dbh->DATABASE_Lock_);

  sq_prepare(dbh, drop, &stmt);

  if (sqlite3_step(stmt) != SQLITE_DONE)
  {
    FREE(drop);
    LOG_SQLITE(LOG_ERROR, "drop");
    MUTEX_UNLOCK(dbh->DATABASE_Lock_);
    sqlite3_finalize(stmt);
    
    return SYSERR;
  }
  
  sqlite3_finalize(stmt);

  MUTEX_UNLOCK(dbh->DATABASE_Lock_);

  FREE(drop);
  
  closeTable(kv);

  return OK;
}

KVstore_ServiceAPI *
provide_module_kvstore_sqlite(CoreAPIForApplication * capi) {
  static KVstore_ServiceAPI api;

#if DEBUG_SQLITE
  LOG(LOG_DEBUG,
      "SQLite: initializing database\n");
#endif

  MUTEX_CREATE(&databasesLock);

  coreAPI = capi;

  api.closeTable = &closeTable;
  api.del = &del;
  api.get = &get;
  api.getTable = &getTable;
  api.put = &put;
  api.dropTable = dropTable;
  api.dropDatabase = dropDatabase;
  return &api;
}

/**
 * Shutdown the module.
 */
void release_module_kvstore_sqlite() {
  sqlite_shutdown();
#if DEBUG_SQLITE
  LOG(LOG_DEBUG,
      "SQLite KVStore: database shutdown\n");
#endif

  MUTEX_DESTROY(&databasesLock);

  coreAPI = NULL;
}

/* end of kv_sqlite.c */
