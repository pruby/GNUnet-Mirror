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
 * @author Christian Grothoff
 * @todo Indexes, statistics
 *
 * Database: SQLite
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_directories.h"
#include "gnunet_kvstore_service.h"
#include <sqlite3.h>

#define DEBUG_SQLITE GNUNET_NO

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define DIE_SQLITE(dbh, cmd) do { GNUNET_GE_LOG(ectx, GNUNET_GE_FATAL | GNUNET_GE_ADMIN | GNUNET_GE_BULK, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(dbh)); abort(); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_SQLITE(dbh, level, cmd) do { GNUNET_GE_LOG(ectx, GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_BULK, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(dbh)); } while(0);

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

} sqliteHandle;

/**
 * @brief Information about the database
 */
typedef struct
{

  /**
   * bytes used
   */
  double payload;

  /**
   * name of the database
   */
  char *name;

  /**
   * filename of this database
   */
  char *fn;

  /**
   * List of open handles
   */
  sqliteHandle **handles;

  /**
   * Open handles (one per thread)
   */
  unsigned int handle_count;

  unsigned int lastSync;

} sqliteDatabase;

static GNUNET_CoreAPIForPlugins *coreAPI;

static struct GNUNET_GE_Context *ectx;

static unsigned int databases;

static sqliteDatabase **dbs;

static struct GNUNET_Mutex *lock;

/**
 * @brief Encode a binary buffer "in" of size n bytes so that it contains
 *        no instances of character '\000'.
 * @param in input
 * @param n size of in
 * @param out output
 */
static int
sqlite_encode_binary (const unsigned char *in, int n, unsigned char *out)
{
  char c;
  unsigned char *start = out;

  n--;
  for (; n > -1; n--)
    {
      c = *in;
      in++;

      if (c == 0 || c == 1)
        {
          *out = 1;
          out++;
          *out = c + 1;
        }
      else
        {
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
static int
sqlite_decode_binary_n (const unsigned char *in,
                        unsigned char *out, unsigned int num)
{
  unsigned char *start = out;
  unsigned char *stop = (unsigned char *) (in + num);

  while (in != stop)
    {
      if (*in == 1)
        {
          in++;
          *out = *in - 1;
        }
      else
        *out = *in;
      in++;
      out++;
    }
  return (int) (out - start);
}

/**
 * @brief Prepare a SQL statement
 */
static int
sq_prepare (sqliteHandle * dbh, const char *zSql,       /* SQL statement, UTF-8 encoded */
            sqlite3_stmt ** ppStmt)
{                               /* OUT: Statement handle */
  char *dummy;

  return sqlite3_prepare (dbh->dbh,
                          zSql,
                          strlen (zSql), ppStmt, (const char **) &dummy);
}

/**
 * Get path to database file
 */
static char *
getDBFileName (const char *name)
{
  char *dir;
  char *fn;
  size_t mem;

  GNUNET_GC_get_configuration_value_filename (coreAPI->cfg,
                                              "KEYVALUE_DATABASE",
                                              "DIR",
                                              GNUNET_DEFAULT_DAEMON_VAR_DIRECTORY
                                              "/kvstore/", &dir);
  GNUNET_disk_directory_create (ectx, dir);
  mem = strlen (dir) + strlen (name) + 6;
  fn = GNUNET_malloc (mem);
  GNUNET_snprintf (fn, mem, "%s/%s.dat", dir, name);
  GNUNET_free (dir);
  return fn;
}

/**
 * @brief Get information about an open database
 * @param name the name of the database
 */
static sqliteDatabase *
getDB (const char *name)
{
  unsigned int idx;
  sqliteDatabase *db;

  for (idx = 0; idx < databases; idx++)
    if (0 == strcmp (dbs[idx]->name, name))
      return dbs[idx];
  db = GNUNET_malloc (sizeof (sqliteDatabase));
  memset (db, 0, sizeof (sqliteDatabase));
  db->fn = getDBFileName (name);
  db->name = GNUNET_strdup (name);
  GNUNET_array_append (dbs, databases, db);
  return db;
}

/**
 * @brief Get a database handle for this thread.
 * @note SQLite handles may no be shared between threads - see
 *        http://permalink.gmane.org/gmane.network.gnunet.devel/1377
 *       We therefore (re)open the database in each thread.
 * @return the native SQLite database handle
 */
static sqliteHandle *
getDBHandle (const char *name)
{
  unsigned int idx;
  sqliteHandle *dbh;
  sqliteDatabase *db;
  char *utf8;

  GNUNET_mutex_lock (lock);
  db = getDB (name);
  for (idx = 0; idx < db->handle_count; idx++)
    if (GNUNET_thread_test_self (db->handles[idx]->tid))
      {
        sqliteHandle *ret = db->handles[idx];
        GNUNET_mutex_unlock (lock);
        return ret;
      }
  /* we haven't opened the DB for this thread yet */
  dbh = GNUNET_malloc (sizeof (sqliteHandle));
  dbh->tid = GNUNET_thread_get_self ();
  utf8 = GNUNET_convert_string_to_utf8 (ectx, db->fn, strlen (db->fn),
#ifdef ENABLE_NLS
                                        nl_langinfo (CODESET)
#else
                                        "UTF-8" /* good luck */
#endif
    );
  if (sqlite3_open (utf8, &dbh->dbh) != SQLITE_OK)
    {
      LOG_SQLITE (dbh->dbh, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                  "sqlite3_open");
      sqlite3_close (dbh->dbh);
      GNUNET_mutex_unlock (lock);
      GNUNET_thread_release_self (dbh->tid);
      GNUNET_free (dbh);
      GNUNET_free (utf8);
      return NULL;
    }
  GNUNET_free (utf8);
  GNUNET_array_append (db->handles, db->handle_count, dbh);
  sqlite3_exec (dbh->dbh, "PRAGMA temp_store=MEMORY", NULL, NULL, NULL);
  sqlite3_exec (dbh->dbh, "PRAGMA synchronous=OFF", NULL, NULL, NULL);
  sqlite3_exec (dbh->dbh, "PRAGMA count_changes=OFF", NULL, NULL, NULL);
  sqlite3_exec (dbh->dbh, "PRAGMA page_size=4096", NULL, NULL, NULL);
  GNUNET_mutex_unlock (lock);
  return dbh;
}

static void
close_database (sqliteDatabase * db)
{
  unsigned int idx;

  for (idx = 0; idx < db->handle_count; idx++)
    {
      sqliteHandle *dbh = db->handles[idx];
      GNUNET_thread_release_self (dbh->tid);
      if (sqlite3_close (dbh->dbh) != SQLITE_OK)
        LOG_SQLITE (dbh->dbh, LOG_ERROR, "sqlite_close");
      GNUNET_free (dbh);
    }
  GNUNET_array_grow (db->handles, db->handle_count, 0);
  GNUNET_free (db->fn);
  GNUNET_free (db->name);
  GNUNET_free (db);
}

/**
 * @brief Delete the database.
 */
static void
dropDatabase (const char *name)
{
  sqliteDatabase *db;
  unsigned int idx;
  char *fn;

  GNUNET_mutex_lock (lock);
  for (idx = 0; idx < databases; idx++)
    {
      if (0 == strcmp (dbs[idx]->name, name))
        {
          db = dbs[idx];
          close_database (db);
          dbs[idx] = dbs[databases - 1];
          GNUNET_array_grow (dbs, databases, databases - 1);
          break;
        }
    }
  fn = getDBFileName (name);
  UNLINK (fn);
  GNUNET_free (fn);
  GNUNET_mutex_unlock (lock);
}

/**
 * @brief Open a Key/Value-Table
 * @param table the name of the Key/Value-Table
 * @return a handle
 */
static GNUNET_KeyValueRecord *
getTable (const char *database, const char *table)
{
  sqlite3_stmt *stmt;
  unsigned int len;
  GNUNET_KeyValueRecord *ret;
  sqliteHandle *dbh;
  char *idx;

  dbh = getDBHandle (database);
  if (dbh == NULL)
    return NULL;
  sq_prepare (dbh, "Select 1 from sqlite_master where tbl_name = ?", &stmt);
  len = strlen (table);
  sqlite3_bind_text (stmt, 1, table, len, SQLITE_STATIC);
  if (sqlite3_step (stmt) == SQLITE_DONE)
    {
      char *create = GNUNET_malloc (len + 58);

      sprintf (create,
               "CREATE TABLE %s (gn_key BLOB, gn_val BLOB, gn_age BIGINT)",
               table);

      if (sqlite3_exec (dbh->dbh, create, NULL, NULL, NULL) != SQLITE_OK)
        {
          LOG_SQLITE (dbh->dbh, LOG_ERROR, "sqlite_create");
          sqlite3_finalize (stmt);
          GNUNET_free (create);
          return NULL;
        }

      GNUNET_free (create);
    }
  sqlite3_finalize (stmt);

  /* FIXME: more indexes */
  idx = GNUNET_malloc (len + 34);
  sprintf (idx, "CREATE INDEX idx_key ON %s (gn_key)", table);
  sqlite3_exec (dbh->dbh, idx, NULL, NULL, NULL);
  GNUNET_free (idx);
  ret = GNUNET_malloc (sizeof (GNUNET_KeyValueRecord));
  ret->table = GNUNET_strdup (table);
  ret->db = GNUNET_strdup (database);

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
static void *
get (GNUNET_KeyValueRecord * kv,
     void *key,
     int keylen,
     unsigned int sort, unsigned int limit, GNUNET_KeyValueProcessor handler,
     void *closure)
{
  unsigned int len, enclen, retlen;
  char *sel, *order, *where, limit_spec[30];
  sqlite3_stmt *stmt;
  void *ret;
  sqliteHandle *dbh;
  unsigned char *key_enc;
  void *ret_dec;

  dbh = getDBHandle (kv->db);
  if (dbh == NULL)
    return NULL;
  ret = NULL;
  ret_dec = NULL;

  len = strlen (kv->table);
  sel = GNUNET_malloc (len + 45);

  if (key)
    {
      where = "WHERE gn_key = ?";
      key_enc = GNUNET_malloc (keylen * 2 + 1);
      enclen = sqlite_encode_binary (key, keylen, key_enc);
    }
  else
    {
      where = "";
      key_enc = NULL;
      enclen = 0;               /* make gcc happy */
    }

  switch (sort)
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
    sprintf (limit_spec, "LIMIT %u", limit);
  else
    *limit_spec = 0;

  sprintf (sel,
           "SELECT gn_val FROM %s %s %s %s",
           kv->table, where, order, limit_spec);

  sq_prepare (dbh, sel, &stmt);
  if (key)
    sqlite3_bind_blob (stmt, 1, key_enc, enclen, SQLITE_STATIC);
  while (sqlite3_step (stmt) == SQLITE_ROW)
    {
      retlen = sqlite3_column_bytes (stmt, 0);
      ret = (void *) sqlite3_column_blob (stmt, 0);

      /* free previous result, only the last in the result set
         is returned to the caller */
      GNUNET_free_non_null (ret_dec);

      ret_dec = GNUNET_malloc (retlen);
      retlen = sqlite_decode_binary_n (ret, ret_dec, retlen);

      if (handler)
        if (handler (closure, ret, retlen) != GNUNET_OK)
          {
            GNUNET_free (sel);
            GNUNET_free_non_null (key_enc);
            GNUNET_free (ret_dec);
            sqlite3_finalize (stmt);

            return ret;
          }
    }
  sqlite3_finalize (stmt);
  GNUNET_free (sel);
  GNUNET_free_non_null (key_enc);
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
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
static int
put (GNUNET_KeyValueRecord * kv, void *key, int keylen, void *val, int vallen,
     unsigned long long age)
{
  unsigned int len;
  char *ins;
  sqlite3_stmt *stmt;
  sqliteHandle *dbh;
  unsigned char *key_enc, *val_enc;
  unsigned int keyenc_len, valenc_len;

  dbh = getDBHandle (kv->db);
  if (dbh == NULL)
    return GNUNET_SYSERR;
  len = strlen (kv->table);
  ins = GNUNET_malloc (len + 68);

  sprintf (ins,
           "INSERT INTO %s(gn_key, gn_val, gn_age) values (?, ?, ?)",
           kv->table);

  key_enc = GNUNET_malloc (keylen * 2);
  keyenc_len = sqlite_encode_binary (key, keylen, key_enc);

  val_enc = GNUNET_malloc (vallen * 2);
  valenc_len = sqlite_encode_binary (val, vallen, val_enc);

  sq_prepare (dbh, ins, &stmt);
  sqlite3_bind_blob (stmt, 1, key_enc, keyenc_len, SQLITE_STATIC);
  sqlite3_bind_blob (stmt, 2, val_enc, valenc_len, SQLITE_STATIC);
  sqlite3_bind_int64 (stmt, 3, age);
  if (sqlite3_step (stmt) != SQLITE_DONE)
    {
      GNUNET_free (ins);
      GNUNET_free (key_enc);
      GNUNET_free (val_enc);
      LOG_SQLITE (dbh->dbh, LOG_ERROR, "put");
      sqlite3_finalize (stmt);
      return GNUNET_SYSERR;
    }
  sqlite3_finalize (stmt);
  GNUNET_free (ins);
  GNUNET_free (key_enc);
  GNUNET_free (val_enc);

  return GNUNET_OK;
}

/**
 * @brief Delete values from a Key/Value-Table
 * @param key key to delete (may be NULL)
 * @param keylen length of the key
 * @param age age of the items to delete (may be 0)
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
static int
del (GNUNET_KeyValueRecord * kv, void *key, int keylen,
     unsigned long long age)
{
  unsigned int len;
  char *del, *key_where, *age_where;
  sqlite3_stmt *stmt;
  int bind;
  sqliteHandle *dbh;
  unsigned char *keyenc;
  unsigned int keyenc_len;

  dbh = getDBHandle (kv->db);
  if (dbh == NULL)
    return GNUNET_SYSERR;

  len = strlen (kv->table);
  del = GNUNET_malloc (len + 52);
  bind = 1;

  if (key)
    key_where = "gn_key = ?";
  else
    key_where = "";

  if (age)
    age_where = "gn_age = ?";
  else
    age_where = "";

  sprintf (del, "DELETE from %s where %s %s %s", kv->table, key_where,
           age ? "or" : "", age_where);


  sq_prepare (dbh, del, &stmt);
  if (key)
    {
      keyenc = GNUNET_malloc (keylen * 2);
      keyenc_len = sqlite_encode_binary (key, keylen, keyenc);
      sqlite3_bind_blob (stmt, 1, keyenc, keyenc_len, SQLITE_STATIC);
      bind++;
    }
  else
    {
      keyenc = NULL;
    }

  if (age)
    sqlite3_bind_int64 (stmt, bind, age);

  if (sqlite3_step (stmt) != SQLITE_DONE)
    {
      GNUNET_free (del);
      GNUNET_free_non_null (keyenc);
      LOG_SQLITE (dbh->dbh, LOG_ERROR, "delete");
      sqlite3_finalize (stmt);

      return GNUNET_SYSERR;
    }
  sqlite3_finalize (stmt);
  GNUNET_free (del);
  GNUNET_free_non_null (keyenc);

  return GNUNET_OK;
}

/**
 * @brief Close a handle to a Key/Value-Table
 * @param kv the handle to close
 */
static void
closeTable (GNUNET_KeyValueRecord * kv)
{
  GNUNET_free (kv->table);
  GNUNET_free (kv->db);
}

/**
 * @brief Drop a Key/Value-Table
 * @param the handle to the table
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
static int
dropTable (GNUNET_KeyValueRecord * kv)
{
  sqlite3_stmt *stmt;
  sqliteHandle *dbh;
  char *drop;

  dbh = getDBHandle (kv->db);
  if (dbh == NULL)
    return GNUNET_SYSERR;
  drop = GNUNET_malloc (12 + strlen (kv->table));
  sprintf (drop, "DROP TABLE %s", kv->table);
  sq_prepare (dbh, drop, &stmt);
  if (sqlite3_step (stmt) != SQLITE_DONE)
    {
      GNUNET_free (drop);
      LOG_SQLITE (dbh->dbh, LOG_ERROR, "drop");
      sqlite3_finalize (stmt);
      return GNUNET_SYSERR;
    }
  sqlite3_finalize (stmt);
  GNUNET_free (drop);
  closeTable (kv);
  return GNUNET_OK;
}

GNUNET_KVstore_ServiceAPI *
provide_module_kvstore_sqlite (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_KVstore_ServiceAPI api;

  ectx = capi->ectx;
#if DEBUG_SQLITE
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "KV-SQLite: initializing database\n");
#endif

  lock = GNUNET_mutex_create (GNUNET_NO);
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
void
release_module_kvstore_sqlite ()
{
  unsigned int idx;

  for (idx = 0; idx < databases; idx++)
    close_database (dbs[idx]);
  GNUNET_array_grow (dbs, databases, 0);

#if DEBUG_SQLITE
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "SQLite KVStore: database shutdown\n");
#endif

  GNUNET_mutex_destroy (lock);
  coreAPI = NULL;
}

/* end of kv_sqlite.c */
