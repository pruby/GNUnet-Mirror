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
 * @file applications/sqstore_mysql/mysql.c
 * @author Igor Wronsky and Christian Grothoff
 *
 * Database: MySQL
 *
 * NOTE: This db module does NOT work with mysql prior to 4.1 since
 * it uses prepared statements.  MySQL 5.0.46 promises to fix a bug
 * in MyISAM that is causing us grief.  At the time of this writing,
 * that version is yet to be released.  In anticipation, the code
 * will use MyISAM with 5.0.46 (and higher).  If you run such a
 * version, please run "make check" to verify that the MySQL bug
 * was actually fixed in your version (and if not, change the
 * code below to use MyISAM for gn071).
 *
 * HIGHLIGHTS
 *
 * Pros
 * + On up-to-date hardware where mysql can be used comfortably, this
 *   module will have better performance than the other db choices
 *   (according to our tests).
 * + Its often possible to recover the mysql database from internal
 *   inconsistencies. The other db choices do not support repair!
 * Cons
 * - Memory usage (Comment: "I have 1G and it never caused me trouble")
 * - Manual setup
 *
 * MANUAL SETUP INSTRUCTIONS
 *
 * 1) in /etc/gnunet.conf, set
 *    <pre>
 *
 *     sqstore = "sqstore_mysql"
 *
 *    </pre>
 * 2) Then access mysql as root,
 *    <pre>
 *
 *    $ mysql -u root -p
 *
 *    </pre>
 *    and do the following. [You should replace $USER with the username
 *    that will be running the gnunetd process].
 *    <pre>
 *
      CREATE DATABASE gnunet;
      GRANT select,insert,update,delete,create,alter,drop,create temporary tables
         ON gnunet.* TO $USER@localhost;
      SET PASSWORD FOR $USER@localhost=PASSWORD('$the_password_you_like');
      FLUSH PRIVILEGES;
 *
 *    </pre>
 * 3) In the $HOME directory of $USER, create a ".my.cnf" file
 *    with the following lines
 *    <pre>

      [client]
      user=$USER
      password=$the_password_you_like

 *    </pre>
 *
 * Thats it. Note that .my.cnf file is a security risk unless its on
 * a safe partition etc. The $HOME/.my.cnf can of course be a symbolic
 * link. Even greater security risk can be achieved by setting no
 * password for $USER.  Luckily $USER has only priviledges to mess
 * up GNUnet's tables, nothing else (unless you give him more,
 * of course).<p>
 *
 * 4) Still, perhaps you should briefly try if the DB connection
 *    works. First, login as $USER. Then use,
 *
 *    <pre>
 *    $ mysql -u $USER -p $the_password_you_like
 *    mysql> use gnunet;
 *    </pre>
 *
 *    If you get the message &quot;Database changed&quot; it probably works.
 *
 *    [If you get &quot;ERROR 2002: Can't connect to local MySQL server
 *     through socket '/tmp/mysql.sock' (2)&quot; it may be resolvable by
 *     &quot;ln -s /var/run/mysqld/mysqld.sock /tmp/mysql.sock&quot;
 *     so there may be some additional trouble depending on your mysql setup.]
 *
 * REPAIRING TABLES
 *
 * - Its probably healthy to check your tables for inconsistencies
 *   every now and then.
 * - If you get odd SEGVs on gnunetd startup, it might be that the mysql
 *   databases have been corrupted.
 * - The tables can be verified/fixed in two ways;
 *   1) by running mysqlcheck -A, or
 *   2) by executing (inside of mysql using the GNUnet database):
 *   mysql> REPAIR TABLE gn080;
 *   mysql> REPAIR TABLE gn072;
 *
 * PROBLEMS?
 *
 * If you have problems related to the mysql module, your best
 * friend is probably the mysql manual. The first thing to check
 * is that mysql is basically operational, that you can connect
 * to it, create tables, issue queries etc.
 *
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_mysql.h"
#include "gnunet_protocols.h"
#include "gnunet_sqstore_service.h"
#include "gnunet_stats_service.h"
#include "gnunet_state_service.h"

#define DEBUG_MYSQL GNUNET_NO

#define MAX_DATUM_SIZE 65536

static GNUNET_Stats_ServiceAPI *stats;

static GNUNET_CoreAPIForPlugins *coreAPI;

static unsigned int stat_size;

/**
 * Size of the mysql database on disk.
 */
static unsigned long long content_size;

/**
 * Lock for updating content_size
 */
static struct GNUNET_Mutex *lock;

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_MysqlDatabaseHandle *db;

/* stuff dealing with gn072 table */
#define SELECT_VALUE "SELECT value FROM gn072 WHERE vkey=?"
static struct GNUNET_MysqlStatementHandle *select_value;

#define DELETE_VALUE "DELETE FROM gn072 WHERE vkey=?"
static struct GNUNET_MysqlStatementHandle *delete_value;

#define INSERT_VALUE "INSERT INTO gn072 (value) VALUES (?)"
static struct GNUNET_MysqlStatementHandle *insert_value;

/* stuff dealing with gn080 table */
#define INSERT_ENTRY "INSERT INTO gn080 (size,type,prio,anonLevel,expire,hash,vhash,vkey) VALUES (?,?,?,?,?,?,?,?)"
static struct GNUNET_MysqlStatementHandle *insert_entry;

#define DELETE_ENTRY_BY_VKEY "DELETE FROM gn080 WHERE vkey=?"
static struct GNUNET_MysqlStatementHandle *delete_entry_by_vkey;

#define SELECT_ENTRY_BY_HASH "SELECT size,type,prio,anonLevel,expire,hash,vkey FROM gn080 FORCE INDEX (hash_vkey) WHERE hash=? AND vkey > ? ORDER BY vkey ASC LIMIT 1 OFFSET ?"
static struct GNUNET_MysqlStatementHandle *select_entry_by_hash;

#define SELECT_ENTRY_BY_HASH_AND_VHASH "SELECT size,type,prio,anonLevel,expire,hash,vkey FROM gn080 FORCE INDEX (hash_vhash_vkey) WHERE hash=? AND vhash=? AND vkey > ? ORDER BY vkey ASC LIMIT 1 OFFSET ?"
static struct GNUNET_MysqlStatementHandle *select_entry_by_hash_and_vhash;

#define SELECT_ENTRY_BY_HASH_AND_TYPE "SELECT size,type,prio,anonLevel,expire,hash,vkey FROM gn080 FORCE INDEX (hash_vkey) WHERE hash=? AND vkey > ? AND type=? ORDER BY vkey ASC LIMIT 1 OFFSET ?"
static struct GNUNET_MysqlStatementHandle *select_entry_by_hash_and_type;

#define SELECT_ENTRY_BY_HASH_VHASH_AND_TYPE "SELECT size,type,prio,anonLevel,expire,hash,vkey FROM gn080 FORCE INDEX (hash_vhash_vkey) WHERE hash=? AND vhash=? AND vkey > ? AND type=? ORDER BY vkey ASC LIMIT 1 OFFSET ?"
static struct GNUNET_MysqlStatementHandle
  *select_entry_by_hash_vhash_and_type;

#define COUNT_ENTRY_BY_HASH "SELECT count(*) FROM gn080 FORCE INDEX (hash) WHERE hash=?"
static struct GNUNET_MysqlStatementHandle *count_entry_by_hash;

#define COUNT_ENTRY_BY_HASH_AND_VHASH "SELECT count(*) FROM gn080 FORCE INDEX (hash_vhash_vkey) WHERE hash=? AND vhash=?"
static struct GNUNET_MysqlStatementHandle *count_entry_by_hash_and_vhash;

#define COUNT_ENTRY_BY_HASH_AND_TYPE "SELECT count(*) FROM gn080 FORCE INDEX (hash) WHERE hash=? AND type=?"
static struct GNUNET_MysqlStatementHandle *count_entry_by_hash_and_type;

#define COUNT_ENTRY_BY_HASH_VHASH_AND_TYPE "SELECT count(*) FROM gn080 FORCE INDEX (hash_vhash) WHERE hash=? AND vhash=? AND type=?"
static struct GNUNET_MysqlStatementHandle *count_entry_by_hash_vhash_and_type;

#define UPDATE_ENTRY "UPDATE gn080 SET prio=prio+?,expire=IF(expire>=?,expire,?) WHERE vkey=?"
static struct GNUNET_MysqlStatementHandle *update_entry;

/* warning, slighly crazy mysql statements ahead.  Essentially, MySQL does not handle
   "OR" very well, so we need to use UNION instead.  And UNION does not
   automatically apply a LIMIT on the outermost clause, so we need to
   repeat ourselves quite a bit.  All hail the performance gods (and thanks
   to #mysql on freenode) */
#define SELECT_IT_LOW_PRIORITY "(SELECT size,type,prio,anonLevel,expire,hash,vkey FROM gn080 FORCE INDEX(prio) WHERE (prio = ? AND vkey > ?) "\
                               "ORDER BY prio ASC,vkey ASC LIMIT 1) "\
                               "UNION "\
                               "(SELECT size,type,prio,anonLevel,expire,hash,vkey FROM gn080 FORCE INDEX(prio) WHERE (prio > ? AND vkey != ?)"\
                               "ORDER BY prio ASC,vkey ASC LIMIT 1)"\
                               "ORDER BY prio ASC,vkey ASC LIMIT 1"

#define SELECT_IT_NON_ANONYMOUS "(SELECT size,type,prio,anonLevel,expire,hash,vkey FROM gn080 FORCE INDEX(prio) WHERE (prio = ? AND vkey < ?)"\
                                " AND anonLevel=0 ORDER BY prio DESC,vkey DESC LIMIT 1) "\
                                "UNION "\
                                "(SELECT size,type,prio,anonLevel,expire,hash,vkey FROM gn080 FORCE INDEX(prio) WHERE (prio < ? AND vkey != ?)"\
                                " AND anonLevel=0 ORDER BY prio DESC,vkey DESC LIMIT 1) "\
                                "ORDER BY prio DESC,vkey DESC LIMIT 1"

#define SELECT_IT_EXPIRATION_TIME "(SELECT size,type,prio,anonLevel,expire,hash,vkey FROM gn080 FORCE INDEX(expire) WHERE (expire = ? AND vkey > ?) "\
                                  "ORDER BY expire ASC,vkey ASC LIMIT 1) "\
                                  "UNION "\
                                  "(SELECT size,type,prio,anonLevel,expire,hash,vkey FROM gn080 FORCE INDEX(expire) WHERE (expire > ? AND vkey != ?) "\
                                  "ORDER BY expire ASC,vkey ASC LIMIT 1)"\
                                  "ORDER BY expire ASC,vkey ASC LIMIT 1"


#define SELECT_IT_MIGRATION_ORDER "(SELECT size,type,prio,anonLevel,expire,hash,vkey FROM gn080 FORCE INDEX(expire) WHERE (expire = ? AND vkey < ?)"\
                                  " AND expire > ? AND type!=3"\
                                  " ORDER BY expire DESC,vkey DESC LIMIT 1) "\
                                  "UNION "\
                                  "(SELECT size,type,prio,anonLevel,expire,hash,vkey FROM gn080 FORCE INDEX(expire) WHERE (expire < ? AND vkey != ?)"\
                                  " AND expire > ? AND type!=3"\
                                  " ORDER BY expire DESC,vkey DESC LIMIT 1)"\
                                  "ORDER BY expire DESC,vkey DESC LIMIT 1"
static struct GNUNET_MysqlStatementHandle *iter[4];

#define SELECT_SIZE "SELECT sum(size) FROM gn080"

/**
 * Initiate the database connection.
 *
 * @return GNUNET_OK on success
 */
static int
iopen ()
{
  if (db != NULL)
    return GNUNET_OK;
  db = GNUNET_MYSQL_database_open (ectx, coreAPI->cfg);
  if (db == NULL)
    return GNUNET_SYSERR;
#define MRUNS(a) (GNUNET_OK != GNUNET_MYSQL_run_statement (db, a) )
#define PINIT(a,b) (NULL == (a = GNUNET_MYSQL_prepared_statement_create(db, b)))
  if (MRUNS ("CREATE TABLE IF NOT EXISTS gn080 ("
             " size INT(11) UNSIGNED NOT NULL DEFAULT 0,"
             " type INT(11) UNSIGNED NOT NULL DEFAULT 0,"
             " prio INT(11) UNSIGNED NOT NULL DEFAULT 0,"
             " anonLevel INT(11) UNSIGNED NOT NULL DEFAULT 0,"
             " expire BIGINT UNSIGNED NOT NULL DEFAULT 0,"
             " hash BINARY(64) NOT NULL DEFAULT '',"
             " vhash BINARY(64) NOT NULL DEFAULT '',"
             " vkey BIGINT UNSIGNED NOT NULL DEFAULT 0,"
             " INDEX hash (hash(64)),"
             " INDEX hash_vhash_vkey (hash(64),vhash(64),vkey),"
             " INDEX hash_vkey (hash(64),vkey),"
             " INDEX vkey (vkey),"
             " INDEX prio (prio,vkey),"
             " INDEX expire (expire,vkey,type),"
             " INDEX anonLevel (anonLevel,prio,vkey,type)"
             ") ENGINE=InnoDB") ||
      MRUNS ("CREATE TABLE IF NOT EXISTS gn072 ("
             " vkey BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,"
             " value BLOB NOT NULL DEFAULT '') ENGINE=MyISAM") ||
      MRUNS ("SET AUTOCOMMIT = 1") ||
      PINIT (select_value, SELECT_VALUE) ||
      PINIT (delete_value, DELETE_VALUE) ||
      PINIT (insert_value, INSERT_VALUE) ||
      PINIT (insert_entry, INSERT_ENTRY) ||
      PINIT (delete_entry_by_vkey, DELETE_ENTRY_BY_VKEY) ||
      PINIT (select_entry_by_hash, SELECT_ENTRY_BY_HASH) ||
      PINIT (select_entry_by_hash_and_vhash, SELECT_ENTRY_BY_HASH_AND_VHASH)
      || PINIT (select_entry_by_hash_and_type, SELECT_ENTRY_BY_HASH_AND_TYPE)
      || PINIT (select_entry_by_hash_vhash_and_type,
                SELECT_ENTRY_BY_HASH_VHASH_AND_TYPE)
      || PINIT (count_entry_by_hash, COUNT_ENTRY_BY_HASH)
      || PINIT (count_entry_by_hash_and_vhash, COUNT_ENTRY_BY_HASH_AND_VHASH)
      || PINIT (count_entry_by_hash_and_type, COUNT_ENTRY_BY_HASH_AND_TYPE)
      || PINIT (count_entry_by_hash_vhash_and_type,
                COUNT_ENTRY_BY_HASH_VHASH_AND_TYPE)
      || PINIT (update_entry, UPDATE_ENTRY)
      || PINIT (iter[0], SELECT_IT_LOW_PRIORITY)
      || PINIT (iter[1], SELECT_IT_NON_ANONYMOUS)
      || PINIT (iter[2], SELECT_IT_EXPIRATION_TIME)
      || PINIT (iter[3], SELECT_IT_MIGRATION_ORDER))
    {
      GNUNET_MYSQL_database_close (db);
      db = NULL;
      return GNUNET_SYSERR;
    }
#undef PINIT
#undef MRUNS
  return GNUNET_OK;
}

/**
 * Delete an value from the gn072 table.
 *
 * @param vkey vkey identifying the value to delete
 * @return GNUNET_OK on success, GNUNET_NO if no such value exists, GNUNET_SYSERR on error
 */
static int
do_delete_value (unsigned long long vkey)
{
  int ret;

  ret = GNUNET_MYSQL_prepared_statement_run (delete_value,
                                             NULL,
                                             MYSQL_TYPE_LONGLONG,
                                             &vkey, GNUNET_YES, -1);
  if (ret > 0)
    ret = GNUNET_OK;
  return ret;
}

/**
 * Insert a value into the gn072 table.
 *
 * @param value the value to insert
 * @param size size of the value
 * @param vkey vkey identifying the value henceforth (set)
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
do_insert_value (const void *value, unsigned int size,
                 unsigned long long *vkey)
{
  unsigned long length = size;

  return GNUNET_MYSQL_prepared_statement_run (insert_value,
                                              vkey,
                                              MYSQL_TYPE_BLOB,
                                              value, length, &length, -1);
}

/**
 * Delete an entry from the gn080 table.
 *
 * @param vkey vkey identifying the entry to delete
 * @return GNUNET_OK on success, GNUNET_NO if no such value exists, GNUNET_SYSERR on error
 */
static int
do_delete_entry_by_vkey (unsigned long long vkey)
{
  int ret;

  ret = GNUNET_MYSQL_prepared_statement_run (delete_entry_by_vkey,
                                             NULL,
                                             MYSQL_TYPE_LONGLONG,
                                             &vkey, GNUNET_YES, -1);
  if (ret > 0)
    ret = GNUNET_OK;
  return ret;
}

static int
return_ok (void *cls, unsigned int num_values, MYSQL_BIND * values)
{
  return GNUNET_OK;
}

/**
 * Given a full (SELECT *) result set from gn080 table,
 * assemble it into a GNUNET_DatastoreValue representation.
 *
 * Call *without* holding the lock, but while within
 * mysql_thread_start/end.
 *
 * @param result location where mysql_stmt_fetch stored the results
 * @return NULL on error
 */
static GNUNET_DatastoreValue *
assembleDatum (MYSQL_BIND * result)
{
  GNUNET_DatastoreValue *datum;
  unsigned int contentSize;
  unsigned int type;
  unsigned int prio;
  unsigned int level;
  unsigned long long exp;
  unsigned long long vkey;
  unsigned long length;
  MYSQL_BIND rbind[1];
  int ret;

  if ((result[0].buffer_type != MYSQL_TYPE_LONG) ||
      (!result[0].is_unsigned) ||
      (result[1].buffer_type != MYSQL_TYPE_LONG) ||
      (!result[1].is_unsigned) ||
      (result[2].buffer_type != MYSQL_TYPE_LONG) ||
      (!result[2].is_unsigned) ||
      (result[3].buffer_type != MYSQL_TYPE_LONG) ||
      (!result[3].is_unsigned) ||
      (result[4].buffer_type != MYSQL_TYPE_LONGLONG) ||
      (!result[4].is_unsigned) ||
      (result[5].buffer_type != MYSQL_TYPE_BLOB) ||
      (result[5].buffer_length != sizeof (GNUNET_HashCode)) ||
      (*result[5].length != sizeof (GNUNET_HashCode)) ||
      (result[6].buffer_type != MYSQL_TYPE_LONGLONG) ||
      (!result[6].is_unsigned))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return NULL;              /* error */
    }

  contentSize = *(unsigned int *) result[0].buffer;
  if (contentSize < sizeof (GNUNET_DatastoreValue))
    return NULL;                /* error */
  contentSize -= sizeof (GNUNET_DatastoreValue);
  type = *(unsigned int *) result[1].buffer;
  prio = *(unsigned int *) result[2].buffer;
  level = *(unsigned int *) result[3].buffer;
  exp = *(unsigned long long *) result[4].buffer;
  vkey = *(unsigned long long *) result[6].buffer;
  datum = GNUNET_malloc (sizeof (GNUNET_DatastoreValue) + contentSize);
  datum->size = htonl (contentSize + sizeof (GNUNET_DatastoreValue));
  datum->type = htonl (type);
  datum->priority = htonl (prio);
  datum->anonymity_level = htonl (level);
  datum->expiration_time = GNUNET_htonll (exp);

  /* now do query on gn072 */
  length = contentSize;
  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_BLOB;
  rbind[0].buffer_length = contentSize;
  rbind[0].length = &length;
  rbind[0].buffer = &datum[1];
  ret = GNUNET_MYSQL_prepared_statement_run_select (select_value,
                                                    1,
                                                    rbind,
                                                    &return_ok,
                                                    NULL,
                                                    MYSQL_TYPE_LONGLONG,
                                                    &vkey, GNUNET_YES, -1);
  GNUNET_GE_BREAK (NULL, ret <= 1);     /* should only have one result! */
  if (ret > 0)
    ret = GNUNET_OK;
  if ( (ret != GNUNET_OK) ||
       (rbind[0].buffer_length != contentSize) || 
       (length != contentSize))
    {
      GNUNET_GE_BREAK (NULL, ret != 0);     /* should have one result! */
      GNUNET_GE_BREAK (NULL, length == contentSize);     /* length should match! */
      GNUNET_GE_BREAK (NULL, rbind[0].buffer_length == contentSize);     /* length should be internally consistent! */
      do_delete_value (vkey);
      if (ret != 0)
	do_delete_entry_by_vkey (vkey);
      content_size -= ntohl (datum->size);
      GNUNET_free (datum);
      return NULL;
    }
  return datum;
}

/**
 * Store an item in the datastore.
 *
 * @param key key for the item
 * @param value information to store
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
put (const GNUNET_HashCode * key, const GNUNET_DatastoreValue * value)
{
  unsigned long contentSize;
  unsigned long hashSize;
  unsigned long hashSize2;
  unsigned int size;
  unsigned int type;
  unsigned int prio;
  unsigned int level;
  unsigned long long expiration;
  unsigned long long vkey;
  GNUNET_HashCode vhash;

  if (((ntohl (value->size) < sizeof (GNUNET_DatastoreValue))) ||
      ((ntohl (value->size) - sizeof (GNUNET_DatastoreValue)) >
       MAX_DATUM_SIZE))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  hashSize = sizeof (GNUNET_HashCode);
  hashSize2 = sizeof (GNUNET_HashCode);
  size = ntohl (value->size);
  type = ntohl (value->type);
  prio = ntohl (value->priority);
  level = ntohl (value->anonymity_level);
  expiration = GNUNET_ntohll (value->expiration_time);
  contentSize = ntohl (value->size) - sizeof (GNUNET_DatastoreValue);
  GNUNET_hash (&value[1], contentSize, &vhash);

  if (GNUNET_OK != do_insert_value (&value[1], contentSize, &vkey))
    return GNUNET_SYSERR;
  if (GNUNET_OK !=
      GNUNET_MYSQL_prepared_statement_run (insert_entry,
                                           NULL,
                                           MYSQL_TYPE_LONG,
                                           &size,
                                           GNUNET_YES,
                                           MYSQL_TYPE_LONG,
                                           &type,
                                           GNUNET_YES,
                                           MYSQL_TYPE_LONG,
                                           &prio,
                                           GNUNET_YES,
                                           MYSQL_TYPE_LONG,
                                           &level,
                                           GNUNET_YES,
                                           MYSQL_TYPE_LONGLONG,
                                           &expiration,
                                           GNUNET_YES,
                                           MYSQL_TYPE_BLOB,
                                           key,
                                           hashSize,
                                           &hashSize,
                                           MYSQL_TYPE_BLOB,
                                           &vhash,
                                           hashSize2,
                                           &hashSize2,
                                           MYSQL_TYPE_LONGLONG,
                                           &vkey, GNUNET_YES, -1))
    {
      do_delete_value (vkey);
      return GNUNET_SYSERR;
    }
  GNUNET_mutex_lock (lock);
  content_size += ntohl (value->size);
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

/**
 * Iterate over the items in the datastore
 * using the given query to select and order
 * the items.
 *
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter never NULL
 * @param is_asc are we using ascending order?
 * @return the number of results, GNUNET_SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int
iterateHelper (unsigned int type,
               int is_asc,
               unsigned int iter_select, GNUNET_DatastoreValueIterator dviter,
               void *closure)
{
  GNUNET_DatastoreValue *datum;
  int count;
  int ret;
  unsigned int last_prio;
  unsigned long long last_expire;
  unsigned long long last_vkey;
  unsigned int size;
  unsigned int rtype;
  unsigned int prio;
  unsigned int level;
  unsigned long long expiration;
  unsigned long long vkey;
  unsigned long hashSize;
  GNUNET_HashCode key;
  GNUNET_CronTime now;
  MYSQL_BIND rbind[7];

  if (is_asc)
    {
      last_prio = 0;
      last_vkey = 0;
      last_expire = 0;
    }
  else
    {
      last_prio = 0x7FFFFFFFL;
      last_vkey = 0x7FFFFFFFFFFFFFFFLL; /* MySQL only supports 63 bits */
      last_expire = 0x7FFFFFFFFFFFFFFFLL;       /* MySQL only supports 63 bits */
    }
  hashSize = sizeof (GNUNET_HashCode);
  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_LONG;
  rbind[0].buffer = &size;
  rbind[0].is_unsigned = 1;
  rbind[1].buffer_type = MYSQL_TYPE_LONG;
  rbind[1].buffer = &rtype;
  rbind[1].is_unsigned = 1;
  rbind[2].buffer_type = MYSQL_TYPE_LONG;
  rbind[2].buffer = &prio;
  rbind[2].is_unsigned = 1;
  rbind[3].buffer_type = MYSQL_TYPE_LONG;
  rbind[3].buffer = &level;
  rbind[3].is_unsigned = 1;
  rbind[4].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[4].buffer = &expiration;
  rbind[4].is_unsigned = 1;
  rbind[5].buffer_type = MYSQL_TYPE_BLOB;
  rbind[5].buffer = &key;
  rbind[5].buffer_length = hashSize;
  rbind[5].length = &hashSize;
  rbind[6].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[6].buffer = &vkey;
  rbind[6].is_unsigned = GNUNET_YES;

  now = GNUNET_get_time ();
  count = 0;
  while (1)
    {
      switch (iter_select)
        {
        case 0:
        case 1:
          ret = GNUNET_MYSQL_prepared_statement_run_select (iter[iter_select],
                                                            7,
                                                            rbind,
                                                            &return_ok,
                                                            NULL,
                                                            MYSQL_TYPE_LONG,
                                                            &last_prio,
                                                            GNUNET_YES,
                                                            MYSQL_TYPE_LONGLONG,
                                                            &last_vkey,
                                                            GNUNET_YES,
                                                            MYSQL_TYPE_LONG,
                                                            &last_prio,
                                                            GNUNET_YES,
                                                            MYSQL_TYPE_LONGLONG,
                                                            &last_vkey,
                                                            GNUNET_YES, -1);
          break;
        case 2:
          ret = GNUNET_MYSQL_prepared_statement_run_select (iter[iter_select],
                                                            7,
                                                            rbind,
                                                            &return_ok,
                                                            NULL,
                                                            MYSQL_TYPE_LONGLONG,
                                                            &last_expire,
                                                            GNUNET_YES,
                                                            MYSQL_TYPE_LONGLONG,
                                                            &last_vkey,
                                                            GNUNET_YES,
                                                            MYSQL_TYPE_LONGLONG,
                                                            &last_expire,
                                                            GNUNET_YES,
                                                            MYSQL_TYPE_LONGLONG,
                                                            &last_vkey,
                                                            GNUNET_YES, -1);
          break;
        case 3:
          ret = GNUNET_MYSQL_prepared_statement_run_select (iter[iter_select],
                                                            7,
                                                            rbind,
                                                            &return_ok,
                                                            NULL,
                                                            MYSQL_TYPE_LONGLONG,
                                                            &last_expire,
                                                            GNUNET_YES,
                                                            MYSQL_TYPE_LONGLONG,
                                                            &last_vkey,
                                                            GNUNET_YES,
                                                            MYSQL_TYPE_LONGLONG,
                                                            &now,
                                                            GNUNET_YES,
                                                            MYSQL_TYPE_LONGLONG,
                                                            &last_expire,
                                                            GNUNET_YES,
                                                            MYSQL_TYPE_LONGLONG,
                                                            &last_vkey,
                                                            GNUNET_YES,
                                                            MYSQL_TYPE_LONGLONG,
                                                            &now,
                                                            GNUNET_YES, -1);
          break;
        default:
          GNUNET_GE_BREAK (NULL, 0);
          return GNUNET_SYSERR;
        }
      if (ret != GNUNET_OK)
        break;
      last_vkey = vkey;
      last_prio = prio;
      last_expire = expiration;
      count++;
      if (dviter != NULL)
        {
          datum = assembleDatum (rbind);
          if (datum == NULL)
            continue;
          ret = dviter (&key, datum, closure, vkey);
          if (ret == GNUNET_SYSERR)
            {
              GNUNET_free (datum);
              break;
            }
          if (ret == GNUNET_NO)
            {
              do_delete_value (vkey);
              do_delete_entry_by_vkey (vkey);
              GNUNET_mutex_lock (lock);
              content_size -= ntohl (datum->size);
              GNUNET_mutex_unlock (lock);
            }
          GNUNET_free (datum);
        }
    }
  return count;
}

/**
 * Iterate over the items in the datastore in ascending
 * order of priority.
 *
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter never NULL
 * @return the number of results, GNUNET_SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int
iterateLowPriority (unsigned int type, GNUNET_DatastoreValueIterator iter,
                    void *closure)
{
  return iterateHelper (type, GNUNET_YES, 0, iter, closure);
}

/**
 * Iterate over the items in the datastore that
 * have anonymity level 0.
 *
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter never NULL
 * @return the number of results, GNUNET_SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int
iterateNonAnonymous (unsigned int type, GNUNET_DatastoreValueIterator iter,
                     void *closure)
{
  return iterateHelper (type, GNUNET_NO, 1, iter, closure);
}

/**
 * Iterate over the items in the datastore in ascending
 * order of expiration time.
 *
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter never NULL
 * @return the number of results, GNUNET_SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int
iterateExpirationTime (unsigned int type, GNUNET_DatastoreValueIterator iter,
                       void *closure)
{
  return iterateHelper (type, GNUNET_YES, 2, iter, closure);
}

/**
 * Iterate over the items in the datastore in migration
 * order.
 *
 * @param iter never NULL
 * @return the number of results, GNUNET_SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int
iterateMigrationOrder (GNUNET_DatastoreValueIterator iter, void *closure)
{
  return iterateHelper (0, GNUNET_NO, 3, iter, closure);
}

/**
 * Iterate over the items in the datastore as
 * quickly as possible (in any order).
 *
 * @param iter never NULL
 * @return the number of results, GNUNET_SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int
iterateAllNow (GNUNET_DatastoreValueIterator iter, void *closure)
{
  return iterateHelper (0, GNUNET_YES, 0, iter, closure);
}

/**
 * Iterate over the results for a particular key
 * in the datastore.  If there are n results, the
 * code will start the iteration at result offset
 * "off=rand()%n" in order to ensure diversity of
 * the responses if iterators process only a subset.
 *
 * @param key maybe NULL (to match all entries)
 * @param vhash hash of the value; maybe NULL
 * @param type entries of which type are relevant?
 *     Use 0 for any type.
 * @param iter maybe NULL (to just count); iter
 *     should return GNUNET_SYSERR to abort the
 *     iteration, GNUNET_NO to delete the entry and
 *     continue and GNUNET_OK to continue iterating
 * @return the number of results, GNUNET_SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int
get (const GNUNET_HashCode * query,
     const GNUNET_HashCode * vhash,
     unsigned int type, GNUNET_DatastoreValueIterator iter, void *closure)
{
  int count;
  unsigned long long total;
  int off;
  int ret;
  unsigned int size;
  unsigned int rtype;
  unsigned int prio;
  unsigned int level;
  unsigned int limit_off;
  unsigned long long expiration;
  unsigned long long vkey;
  unsigned long long last_vkey;
  GNUNET_DatastoreValue *datum;
  GNUNET_HashCode key;
  unsigned long hashSize;
  unsigned long hashSize2;
  MYSQL_BIND rbind[7];

  if (query == NULL)
    return iterateLowPriority (type, iter, closure);
  hashSize = sizeof (GNUNET_HashCode);
  hashSize2 = sizeof (GNUNET_HashCode);
  memset (rbind, 0, sizeof (rbind));
  total = -1;
  rbind[0].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[0].buffer = &total;
  rbind[0].is_unsigned = GNUNET_YES;
  if (type != 0)
    {
      if (vhash != NULL)
        {
          ret =
            GNUNET_MYSQL_prepared_statement_run_select
            (count_entry_by_hash_vhash_and_type, 1, rbind, &return_ok, NULL,
             MYSQL_TYPE_BLOB, query, hashSize2, &hashSize2, MYSQL_TYPE_BLOB,
             vhash, hashSize2, &hashSize2, MYSQL_TYPE_LONG, &type, GNUNET_YES,
             -1);
        }
      else
        {
          ret =
            GNUNET_MYSQL_prepared_statement_run_select
            (count_entry_by_hash_and_type, 1, rbind, &return_ok, NULL,
             MYSQL_TYPE_BLOB, query, hashSize2, &hashSize2, MYSQL_TYPE_LONG,
             &type, GNUNET_YES, -1);

        }
    }
  else
    {
      if (vhash != NULL)
        {
          ret =
            GNUNET_MYSQL_prepared_statement_run_select
            (count_entry_by_hash_and_vhash, 1, rbind, &return_ok, NULL,
             MYSQL_TYPE_BLOB, query, hashSize2, &hashSize2, MYSQL_TYPE_BLOB,
             vhash, hashSize2, &hashSize2, -1);

        }
      else
        {
          ret =
            GNUNET_MYSQL_prepared_statement_run_select (count_entry_by_hash,
                                                        1, rbind, &return_ok,
                                                        NULL, MYSQL_TYPE_BLOB,
                                                        query, hashSize2,
                                                        &hashSize2, -1);
        }
    }
  if ((ret != GNUNET_OK) || (-1 == total))
    return GNUNET_SYSERR;
  if ((iter == NULL) || (total == 0))
    return (int) total;

  last_vkey = 0;
  count = 0;
  off = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, total);

  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_LONG;
  rbind[0].buffer = &size;
  rbind[0].is_unsigned = GNUNET_YES;
  rbind[1].buffer_type = MYSQL_TYPE_LONG;
  rbind[1].buffer = &rtype;
  rbind[1].is_unsigned = GNUNET_YES;
  rbind[2].buffer_type = MYSQL_TYPE_LONG;
  rbind[2].buffer = &prio;
  rbind[2].is_unsigned = GNUNET_YES;
  rbind[3].buffer_type = MYSQL_TYPE_LONG;
  rbind[3].buffer = &level;
  rbind[3].is_unsigned = GNUNET_YES;
  rbind[4].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[4].buffer = &expiration;
  rbind[4].is_unsigned = GNUNET_YES;
  rbind[5].buffer_type = MYSQL_TYPE_BLOB;
  rbind[5].buffer = &key;
  rbind[5].buffer_length = hashSize;
  rbind[5].length = &hashSize;
  rbind[6].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[6].buffer = &vkey;
  rbind[6].is_unsigned = GNUNET_YES;
  while (1)
    {
      if (count == 0)
        limit_off = off;
      else
        limit_off = 0;
      if (type != 0)
        {
          if (vhash != NULL)
            {
              ret =
                GNUNET_MYSQL_prepared_statement_run_select
                (select_entry_by_hash_vhash_and_type, 7, rbind, &return_ok,
                 NULL, MYSQL_TYPE_BLOB, query, hashSize, &hashSize,
                 MYSQL_TYPE_BLOB, vhash, hashSize2, &hashSize2,
                 MYSQL_TYPE_LONGLONG, &last_vkey, GNUNET_YES, MYSQL_TYPE_LONG,
                 &type, GNUNET_YES, MYSQL_TYPE_LONG, &limit_off, GNUNET_YES,
                 -1);
            }
          else
            {
              ret =
                GNUNET_MYSQL_prepared_statement_run_select
                (select_entry_by_hash_and_type, 7, rbind, &return_ok, NULL,
                 MYSQL_TYPE_BLOB, query, hashSize, &hashSize,
                 MYSQL_TYPE_LONGLONG, &last_vkey, GNUNET_YES, MYSQL_TYPE_LONG,
                 &type, GNUNET_YES, MYSQL_TYPE_LONG, &limit_off, GNUNET_YES,
                 -1);
            }
        }
      else
        {
          if (vhash != NULL)
            {
              ret =
                GNUNET_MYSQL_prepared_statement_run_select
                (select_entry_by_hash_and_vhash, 7, rbind, &return_ok, NULL,
                 MYSQL_TYPE_BLOB, query, hashSize, &hashSize, MYSQL_TYPE_BLOB,
                 vhash, hashSize2, &hashSize2, MYSQL_TYPE_LONGLONG,
                 &last_vkey, GNUNET_YES, MYSQL_TYPE_LONG, &limit_off,
                 GNUNET_YES, -1);
            }
          else
            {
              ret =
                GNUNET_MYSQL_prepared_statement_run_select
                (select_entry_by_hash, 7, rbind, &return_ok, NULL,
                 MYSQL_TYPE_BLOB, query, hashSize, &hashSize,
                 MYSQL_TYPE_LONGLONG, &last_vkey, GNUNET_YES, MYSQL_TYPE_LONG,
                 &limit_off, GNUNET_YES, -1);
            }
        }
      if (ret != GNUNET_OK)
        break;
      last_vkey = vkey;
      datum = assembleDatum (rbind);
      if (datum == NULL)
        continue;
      count++;
      ret = iter (&key, datum, closure, vkey);
      if (ret == GNUNET_SYSERR)
        {
          GNUNET_free (datum);
          break;
        }
      if (ret == GNUNET_NO)
        {
          do_delete_value (vkey);
          do_delete_entry_by_vkey (vkey);
          GNUNET_mutex_lock (lock);
          content_size -= ntohl (datum->size);
          GNUNET_mutex_unlock (lock);
        }
      GNUNET_free (datum);
      if (count + off == total)
        last_vkey = 0;          /* back to start */
      if (count == total)
        break;
    }
  return count;
}

/**
 * Update the priority for a particular key
 * in the datastore.
 *
 * @param vkey identifies entry in the datastore
 * @param delta change in priority
 * @param expire new expiration value (will be MAX of this value and the old value)
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
update (unsigned long long vkey, int delta, GNUNET_CronTime expire)
{
  return GNUNET_MYSQL_prepared_statement_run (update_entry,
                                              NULL,
                                              MYSQL_TYPE_LONG,
                                              &delta,
                                              GNUNET_NO,
                                              MYSQL_TYPE_LONGLONG,
                                              &expire,
                                              GNUNET_YES,
                                              MYSQL_TYPE_LONGLONG,
                                              &expire,
                                              GNUNET_YES,
                                              MYSQL_TYPE_LONGLONG,
                                              &vkey, GNUNET_YES, -1);
}


/**
 * Get the current on-disk size of the SQ store.
 * Estimates are fine, if that's the only thing
 * available.
 * @return number of bytes used on disk
 */
static unsigned long long
getSize ()
{
  unsigned long long ret;

  GNUNET_mutex_lock (lock);
  ret = content_size;
  if (stats)
    stats->set (stat_size, ret);
  GNUNET_mutex_unlock (lock);
  return ret * 1.2;
}

/**
 * Delete the database.  The next operation is
 * guaranteed to be unloading of the module.
 */
static void
drop ()
{
  if ((GNUNET_OK != GNUNET_MYSQL_run_statement (db,
                                                "DROP TABLE gn080")) ||
      (GNUNET_OK != GNUNET_MYSQL_run_statement (db, "DROP TABLE gn072")))
    return;                     /* error */
  content_size = 0;
}

GNUNET_SQstore_ServiceAPI *
provide_module_sqstore_mysql (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_SQstore_ServiceAPI api;
  GNUNET_State_ServiceAPI *state;
  unsigned long long *sb;
  char *res;

  ectx = capi->ectx;
  coreAPI = capi;
  stats = coreAPI->service_request ("stats");
  if (stats)
    stat_size = stats->create (gettext_noop ("# bytes in datastore"));

  if (GNUNET_OK != iopen ())
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("Failed to load MySQL database module.  Check that MySQL is running and configured properly!\n"));
      if (stats != NULL)
        coreAPI->service_release (stats);
      return NULL;
    }
  lock = GNUNET_mutex_create (GNUNET_NO);
  state = coreAPI->service_request ("state");
  sb = NULL;
  if (sizeof (unsigned long long)
      != state->read (ectx, "mysql-size", (void *) &sb))
    {
      res = GNUNET_MYSQL_run_statement_select (db, SELECT_SIZE);
      if ((res == NULL) || (1 != SSCANF (res, "%llu", &content_size)))
        {
          GNUNET_GE_BREAK (ectx, res == NULL);
          content_size = 0;
        }
      GNUNET_free_non_null (res);
    }
  else
    {
      content_size = *sb;
      GNUNET_free (sb);
      /* no longer valid! remember it by deleting
         the outdated state file! */
      state->unlink (ectx, "mysql-size");
    }
  coreAPI->service_release (state);
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
release_module_sqstore_mysql ()
{
  GNUNET_State_ServiceAPI *state;

  GNUNET_MYSQL_database_close (db);
  db = NULL;
  if (stats != NULL)
    coreAPI->service_release (stats);
  GNUNET_mutex_destroy (lock);
  state = coreAPI->service_request ("state");
  state->write (ectx,
                "mysql-size", sizeof (unsigned long long), &content_size);
  coreAPI->service_release (state);
  ectx = NULL;
  coreAPI = NULL;
}


/**
 * Update mysql database module.
 */
void
update_module_sqstore_mysql (GNUNET_UpdateAPI * uapi)
{
  ectx = uapi->ectx;
  if (GNUNET_OK != iopen ())
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("Failed to load MySQL database module.  Check that MySQL is running and configured properly!\n"));
      return;
    }
  /* run update queries here */
  GNUNET_MYSQL_database_close (db);
  db = NULL;
  ectx = NULL;
}

/* end of mysql.c */
