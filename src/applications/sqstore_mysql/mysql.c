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
      GRANT select,insert,update,delete,create,alter,drop
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
 *   mysql> REPAIR TABLE gn071;
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
#include "gnunet_protocols.h"
#include "gnunet_sqstore_service.h"
#include "gnunet_stats_service.h"
#include "gnunet_state_service.h"
#include <mysql/mysql.h>

#define DEBUG_MYSQL NO

#define DEBUG_TIME_MYSQL NO

#define MAX_DATUM_SIZE 65536

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define DIE_MYSQL(cmd, dbh) do { GE_LOG(ectx, GE_FATAL | GE_ADMIN | GE_IMMEDIATE, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, mysql_error((dbh)->dbf)); abort(); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_MYSQL(level, cmd, dbh) do { GE_LOG(ectx, level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, mysql_error((dbh)->dbf)); } while(0);

static Stats_ServiceAPI *stats;

static CoreAPIForApplication *coreAPI;

static unsigned int stat_size;

/**
 * Size of the mysql database on disk.
 */
static unsigned long long content_size;

/**
 * Lock for updating content_size
 */
static struct MUTEX *lock;

static struct GE_Context *ectx;

/**
 * @brief mysql wrapper
 */
typedef struct
{
  MYSQL *dbf;

  char *cnffile;

  int valid;

  /* stuff dealing with gn072 table */
#define SELECT_VALUE "SELECT value FROM gn072 WHERE vkey=?"
  MYSQL_STMT *select_value;

#define DELETE_VALUE "DELETE FROM gn072 WHERE vkey=?"
  MYSQL_STMT *delete_value;

#define INSERT_VALUE "INSERT INTO gn072 (value) VALUES (?)"
  MYSQL_STMT *insert_value;

  /* stuff dealing with gn071 table */
#define INSERT_ENTRY "INSERT INTO gn071 (size,type,prio,anonLevel,expire,hash,vkey) VALUES (?,?,?,?,?,?,?)"
  MYSQL_STMT *insert_entry;

#define DELETE_ENTRY_BY_VKEY "DELETE FROM gn071 WHERE vkey=?"
  MYSQL_STMT *delete_entry_by_vkey;

#define SELECT_ENTRY_BY_HASH "SELECT * FROM gn071 WHERE hash=? AND vkey > ? ORDER BY vkey ASC LIMIT 1"
  MYSQL_STMT *select_entry_by_hash;

#define SELECT_ENTRY_BY_HASH_AND_TYPE "SELECT * FROM gn071 WHERE hash=? AND vkey > ? AND type=? ORDER BY vkey ASC LIMIT 1"
  MYSQL_STMT *select_entry_by_hash_and_type;

#define COUNT_ENTRY_BY_HASH "SELECT count(*) FROM gn071 WHERE hash=?"
  MYSQL_STMT *count_entry_by_hash;

#define COUNT_ENTRY_BY_HASH_AND_TYPE "SELECT count(*) FROM gn071 WHERE hash=? AND type=?"
  MYSQL_STMT *count_entry_by_hash_and_type;

#define UPDATE_ENTRY "UPDATE gn071 SET prio=prio+?,expire=IF(expire>=?,expire,?) WHERE vkey=?"
  MYSQL_STMT *update_entry;



#define SELECT_IT_LOW_PRIORITY "SELECT * FROM gn071 WHERE ( (prio = ? AND vkey > ?) OR (prio > ? AND vkey != ?) )"\
                               "ORDER BY prio ASC,vkey ASC LIMIT 1"

#define SELECT_IT_NON_ANONYMOUS "SELECT * FROM gn071 WHERE ( (prio = ? AND vkey < ?) OR (prio < ? AND vkey != ?) ) "\
                                "AND anonLevel=0 AND type != 0xFFFFFFFF "\
                                "ORDER BY prio DESC,vkey DESC LIMIT 1"

#define SELECT_IT_EXPIRATION_TIME "SELECT * FROM gn071 WHERE ( (expire = ? AND vkey > ?) OR (expire > ? AND vkey != ?) ) "\
                                  "ORDER BY expire ASC,vkey ASC LIMIT 1"

#define SELECT_IT_MIGRATION_ORDER "SELECT * FROM gn071 WHERE ( (expire = ? AND vkey < ?) OR (expire < ? AND vkey != ?) ) "\
                                  "AND expire > ? AND type!=3 "\
                                  "ORDER BY expire DESC,vkey DESC LIMIT 1"
  MYSQL_STMT *iter[4];

} mysqlHandle;


#define SELECT_SIZE "SELECT sum(size) FROM gn071"

static mysqlHandle *dbh;

/**
 * Close the database connection.
 */
static int
iclose ()
{
#define PEND(h) if (h != NULL) { mysql_stmt_close(h); h = NULL; } else {}
  if (dbh->dbf == NULL)
    return SYSERR;
  PEND (dbh->select_value);
  PEND (dbh->delete_value);
  PEND (dbh->insert_value);
  PEND (dbh->insert_entry);
  PEND (dbh->delete_entry_by_vkey);
  PEND (dbh->select_entry_by_hash);
  PEND (dbh->select_entry_by_hash_and_type);
  PEND (dbh->count_entry_by_hash);
  PEND (dbh->count_entry_by_hash_and_type);
  PEND (dbh->update_entry);
  PEND (dbh->iter[0]);
  PEND (dbh->iter[1]);
  PEND (dbh->iter[2]);
  PEND (dbh->iter[3]);
  mysql_close (dbh->dbf);
  dbh->dbf = NULL;
  dbh->valid = NO;
  return OK;
}

/**
 * Initiate the database connection.  Uses dbh->cnffile for the
 * configuration, so that must be set already.
 *
 * @return OK on success
 */
static int
iopen ()
{
  char *dbname;
  my_bool reconnect = 0;
  unsigned int timeout = 60;    /* in seconds */

  if (dbh->cnffile == NULL)
    return SYSERR;
  dbh->dbf = mysql_init (NULL);
  if (dbh->dbf == NULL)
    return SYSERR;
  mysql_options (dbh->dbf, MYSQL_READ_DEFAULT_FILE, dbh->cnffile);
  mysql_options (dbh->dbf, MYSQL_READ_DEFAULT_GROUP, "client");
  mysql_options (dbh->dbf, MYSQL_OPT_RECONNECT, &reconnect);
  mysql_options (dbh->dbf,
                 MYSQL_OPT_CONNECT_TIMEOUT, (const void *) &timeout);
  mysql_options (dbh->dbf, MYSQL_OPT_READ_TIMEOUT, (const void *) &timeout);
  mysql_options (dbh->dbf, MYSQL_OPT_WRITE_TIMEOUT, (const void *) &timeout);

  dbname = NULL;
  GC_get_configuration_value_string (coreAPI->cfg,
                                     "MYSQL", "DATABASE", "gnunet", &dbname);
  GE_ASSERT (ectx, dbname != NULL);
  mysql_real_connect (dbh->dbf, NULL, NULL, NULL, dbname, 0, NULL, 0);
  FREE (dbname);
  if (mysql_error (dbh->dbf)[0])
    {
      LOG_MYSQL (GE_ERROR | GE_ADMIN | GE_BULK, "mysql_real_connect", dbh);
      iclose ();
      return SYSERR;
    }
  mysql_query (dbh->dbf,
               "SET SESSION net_read_timeout=60, SESSION net_write_timeout=60");
  if (mysql_error (dbh->dbf)[0])
    {
      LOG_MYSQL (GE_ERROR | GE_ADMIN | GE_BULK, "mysql_query", dbh);
      iclose ();
      return SYSERR;
    }
  /* MySQL 5.0.46 fixes a bug in MyISAM (presumably); 
     earlier versions have issues with INDEX over BINARY data,
     which is why we need to use InnoDB for those
     (even though MyISAM would be faster) */
  if (50046 <= mysql_get_server_version (dbh->dbf))
    {
      /* MySQL 5.0.46 fixes bug in MyISAM */
      mysql_query (dbh->dbf,
                   "CREATE TABLE IF NOT EXISTS gn071 ("
                   " size INT(11) UNSIGNED NOT NULL DEFAULT 0,"
                   " type INT(11) UNSIGNED NOT NULL DEFAULT 0,"
                   " prio INT(11) UNSIGNED NOT NULL DEFAULT 0,"
                   " anonLevel INT(11) UNSIGNED NOT NULL DEFAULT 0,"
                   " expire BIGINT UNSIGNED NOT NULL DEFAULT 0,"
                   " hash BINARY(64) NOT NULL DEFAULT '',"
                   " vkey BIGINT UNSIGNED NOT NULL DEFAULT 0,"
                   " INDEX (hash(64)),"
                   " INDEX (vkey),"
                   " INDEX (prio,vkey),"
                   " INDEX (expire,vkey,type),"
                   " INDEX (anonLevel,prio,vkey,type)" ") ENGINE=MyISAM");
    }
  else
    {
      mysql_query (dbh->dbf,
                   "CREATE TABLE IF NOT EXISTS gn071 ("
                   " size INT(11) UNSIGNED NOT NULL DEFAULT 0,"
                   " type INT(11) UNSIGNED NOT NULL DEFAULT 0,"
                   " prio INT(11) UNSIGNED NOT NULL DEFAULT 0,"
                   " anonLevel INT(11) UNSIGNED NOT NULL DEFAULT 0,"
                   " expire BIGINT UNSIGNED NOT NULL DEFAULT 0,"
                   " hash BINARY(64) NOT NULL DEFAULT '',"
                   " vkey BIGINT UNSIGNED NOT NULL DEFAULT 0,"
                   " INDEX (hash(64)),"
                   " INDEX (vkey),"
                   " INDEX (prio,vkey),"
                   " INDEX (expire,vkey,type),"
                   " INDEX (anonLevel,prio,vkey,type)" ") ENGINE=InnoDB");
    }
  if (mysql_error (dbh->dbf)[0])
    {
      LOG_MYSQL (GE_ERROR | GE_ADMIN | GE_BULK, "mysql_query", dbh);
      iclose ();
      return SYSERR;
    }
  mysql_query (dbh->dbf,
               "CREATE TABLE IF NOT EXISTS gn072 ("
               " vkey BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,"
               " value BLOB NOT NULL DEFAULT '') ENGINE=MyISAM");
  if (mysql_error (dbh->dbf)[0])
    {
      LOG_MYSQL (GE_ERROR | GE_ADMIN | GE_BULK, "mysql_query", dbh);
      iclose ();
      return SYSERR;
    }
  mysql_query (dbh->dbf, "SET AUTOCOMMIT = 1");
  if (mysql_error (dbh->dbf)[0])
    {
      LOG_MYSQL (GE_ERROR | GE_ADMIN | GE_BULK, "mysql_query", dbh);
      iclose ();
      return SYSERR;
    }
#define PINIT(a,b) a = mysql_stmt_init(dbh->dbf); if (a == NULL) { iclose(); return SYSERR; } else { \
    if (mysql_stmt_prepare (a, b, strlen(b))) { \
      GE_LOG (ectx, GE_ERROR | GE_BULK | GE_USER, \
	      _("`%s' failed at %s:%d with error: %s"), "mysql_stmt_prepare", __FILE__, __LINE__, \
	      mysql_stmt_error (a));  iclose(); return SYSERR; } }
  PINIT (dbh->select_value, SELECT_VALUE);
  PINIT (dbh->delete_value, DELETE_VALUE);
  PINIT (dbh->insert_value, INSERT_VALUE);
  PINIT (dbh->insert_entry, INSERT_ENTRY);
  PINIT (dbh->delete_entry_by_vkey, DELETE_ENTRY_BY_VKEY);
  PINIT (dbh->select_entry_by_hash, SELECT_ENTRY_BY_HASH);
  PINIT (dbh->select_entry_by_hash_and_type, SELECT_ENTRY_BY_HASH_AND_TYPE);
  PINIT (dbh->count_entry_by_hash, COUNT_ENTRY_BY_HASH);
  PINIT (dbh->count_entry_by_hash_and_type, COUNT_ENTRY_BY_HASH_AND_TYPE);
  PINIT (dbh->update_entry, UPDATE_ENTRY);
  PINIT (dbh->iter[0], SELECT_IT_LOW_PRIORITY);
  PINIT (dbh->iter[1], SELECT_IT_NON_ANONYMOUS);
  PINIT (dbh->iter[2], SELECT_IT_EXPIRATION_TIME);
  PINIT (dbh->iter[3], SELECT_IT_MIGRATION_ORDER);
  dbh->valid = YES;
  return OK;
}

/**
 * Check if DBH handle is valid, return OK if it is.
 * Also tries to re-connect to the DB if the connection
 * is down.
 */
#define CHECK_DBH ((dbh->valid == NO) ? iopen(dbh, YES) : OK)


/**
 * Delete an value from the gn072 table.
 *
 * @param vkey vkey identifying the value to delete
 * @return OK on success, NO if no such value exists, SYSERR on error
 */
static int
delete_value (unsigned long long vkey)
{
  MYSQL_BIND qbind[1];
  int ret;

  memset (qbind, 0, sizeof (qbind));
  qbind[0].is_unsigned = YES;
  qbind[0].buffer_type = MYSQL_TYPE_LONGLONG;
  qbind[0].buffer = &vkey;
  GE_ASSERT (ectx, mysql_stmt_param_count (dbh->delete_value) == 1);
  if (mysql_stmt_bind_param (dbh->delete_value, qbind))
    {
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("`%s' failed at %s:%d with error: %s\n"),
              "mysql_stmt_bind_param",
              __FILE__, __LINE__, mysql_stmt_error (dbh->delete_value));
      iclose ();
      return SYSERR;
    }
  if (mysql_stmt_execute (dbh->delete_value))
    {
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("`%s' failed at %s:%d with error: %s\n"),
              "mysql_stmt_execute",
              __FILE__, __LINE__, mysql_stmt_error (dbh->delete_value));
      iclose ();
      return SYSERR;
    }
  if (mysql_stmt_affected_rows (dbh->delete_value) == 0)
    ret = NO;
  else
    ret = OK;
  mysql_stmt_reset (dbh->delete_value);
  return ret;
}

/**
 * Insert a value into the gn072 table.
 *
 * @param value the value to insert
 * @param size size of the value
 * @param vkey vkey identifying the value henceforth (set)
 * @return OK on success, SYSERR on error
 */
static int
insert_value (const void *value, unsigned int size, unsigned long long *vkey)
{
  MYSQL_BIND qbind[1];
  unsigned long length = size;

  memset (qbind, 0, sizeof (qbind));
  qbind[0].buffer_type = MYSQL_TYPE_BLOB;
  qbind[0].buffer = (void *) value;
  qbind[0].buffer_length = size;
  qbind[0].length = &length;
  GE_ASSERT (ectx, mysql_stmt_param_count (dbh->insert_value) == 1);
  if (mysql_stmt_bind_param (dbh->insert_value, qbind))
    {
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("`%s' failed at %s:%d with error: %s\n"),
              "mysql_stmt_bind_param",
              __FILE__, __LINE__, mysql_stmt_error (dbh->insert_value));
      iclose ();
      return SYSERR;
    }
  if (mysql_stmt_execute (dbh->insert_value))
    {
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("`%s' failed at %s:%d with error: %s\n"),
              "mysql_stmt_execute",
              __FILE__, __LINE__, mysql_stmt_error (dbh->insert_value));
      iclose ();
      return SYSERR;
    }
  *vkey = (unsigned long long) mysql_stmt_insert_id (dbh->insert_value);
  mysql_stmt_reset (dbh->insert_value);
  return OK;
}

/**
 * Delete an entry from the gn071 table.
 *
 * @param vkey vkey identifying the entry to delete
 * @return OK on success, NO if no such value exists, SYSERR on error
 */
static int
delete_entry_by_vkey (unsigned long long vkey)
{
  MYSQL_BIND qbind[1];
  int ret;

  memset (qbind, 0, sizeof (qbind));
  qbind[0].is_unsigned = YES;
  qbind[0].buffer_type = MYSQL_TYPE_LONGLONG;
  qbind[0].buffer = &vkey;
  GE_ASSERT (ectx, mysql_stmt_param_count (dbh->delete_entry_by_vkey) == 1);
  if (mysql_stmt_bind_param (dbh->delete_entry_by_vkey, qbind))
    {
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("`%s' failed at %s:%d with error: %s\n"),
              "mysql_stmt_bind_param",
              __FILE__, __LINE__,
              mysql_stmt_error (dbh->delete_entry_by_vkey));
      iclose ();
      return SYSERR;
    }
  if (mysql_stmt_execute (dbh->delete_entry_by_vkey))
    {
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("`%s' failed at %s:%d with error: %s\n"),
              "mysql_stmt_execute",
              __FILE__, __LINE__,
              mysql_stmt_error (dbh->delete_entry_by_vkey));
      iclose ();
      return SYSERR;
    }
  if (mysql_stmt_affected_rows (dbh->delete_entry_by_vkey) == 0)
    ret = NO;
  else
    ret = OK;
  mysql_stmt_reset (dbh->delete_entry_by_vkey);
  return ret;
}

/**
 * Given a full (SELECT *) result set from gn071 table,
 * assemble it into a Datastore_Value representation.
 *
 * Call *without* holding the lock, but while within
 * mysql_thread_start/end.
 *
 * @param result location where mysql_stmt_fetch stored the results
 * @return NULL on error
 */
static Datastore_Value *
assembleDatum (MYSQL_BIND * result)
{
  Datastore_Value *datum;
  unsigned int contentSize;
  unsigned int type;
  unsigned int prio;
  unsigned int level;
  unsigned long long exp;
  unsigned long long vkey;
  unsigned long length;
  MYSQL_BIND qbind[1];
  MYSQL_BIND rbind[1];

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
      (result[5].buffer_length != sizeof (HashCode512)) ||
      (*result[5].length != sizeof (HashCode512)) ||
      (result[6].buffer_type != MYSQL_TYPE_LONGLONG) ||
      (!result[6].is_unsigned))
    {
      GE_BREAK (NULL, 0);
      return NULL;              /* error */
    }

  contentSize = *(unsigned int *) result[0].buffer;
  if (contentSize < sizeof (Datastore_Value))
    return NULL;                /* error */
  contentSize -= sizeof (Datastore_Value);
  type = *(unsigned int *) result[1].buffer;
  prio = *(unsigned int *) result[2].buffer;
  level = *(unsigned int *) result[3].buffer;
  exp = *(unsigned long long *) result[4].buffer;
  vkey = *(unsigned long long *) result[6].buffer;
  datum = MALLOC (sizeof (Datastore_Value) + contentSize);
  datum->size = htonl (contentSize + sizeof (Datastore_Value));
  datum->type = htonl (type);
  datum->prio = htonl (prio);
  datum->anonymityLevel = htonl (level);
  datum->expirationTime = htonll (exp);

  /* now do query on gn072 */
  length = contentSize;
  memset (qbind, 0, sizeof (qbind));
  qbind[0].is_unsigned = YES;
  qbind[0].buffer_type = MYSQL_TYPE_LONGLONG;
  qbind[0].buffer = &vkey;
  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_BLOB;
  rbind[0].buffer_length = contentSize;
  rbind[0].length = &length;
  rbind[0].buffer = &datum[1];
  MUTEX_LOCK (lock);
  if (OK != CHECK_DBH)
    {
      MUTEX_UNLOCK (lock);
      FREE (datum);
      return NULL;
    }
  GE_ASSERT (ectx, mysql_stmt_param_count (dbh->select_value) == 1);
  if (mysql_stmt_bind_param (dbh->select_value, qbind))
    {
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("`%s' failed at %s:%d with error: %s\n"),
              "mysql_stmt_bind_param",
              __FILE__, __LINE__, mysql_stmt_error (dbh->select_value));
      iclose ();
      MUTEX_UNLOCK (lock);
      FREE (datum);
      return NULL;
    }
  if (mysql_stmt_execute (dbh->select_value))
    {
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("`%s' failed at %s:%d with error: %s\n"),
              "mysql_stmt_execute",
              __FILE__, __LINE__, mysql_stmt_error (dbh->select_value));
      iclose ();
      FREE (datum);
      return NULL;
    }
  GE_ASSERT (ectx, mysql_stmt_field_count (dbh->select_value) == 1);
  if (mysql_stmt_bind_result (dbh->select_value, rbind))
    {
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("`%s' failed at %s:%d with error: %s\n"),
              "mysql_stmt_bind_result",
              __FILE__, __LINE__, mysql_stmt_error (dbh->select_value));
      iclose ();
      MUTEX_UNLOCK (lock);
      FREE (datum);
      return NULL;
    }
  if ((0 != mysql_stmt_fetch (dbh->select_value)) ||
      (rbind[0].buffer_length != contentSize) || (length != contentSize))
    {
      mysql_stmt_reset (dbh->select_value);
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("`%s' failed at %s:%d with error: %s\n"),
              "mysql_stmt_bind_result",
              __FILE__, __LINE__, mysql_stmt_error (dbh->select_value));
      delete_entry_by_vkey (vkey);
      content_size -= ntohl (datum->size);
      MUTEX_UNLOCK (lock);
      FREE (datum);
      return NULL;
    }
  mysql_stmt_reset (dbh->select_value);
  MUTEX_UNLOCK (lock);
  return datum;
}

/**
 * Store an item in the datastore.
 *
 * @return OK on success, SYSERR on error
 */
static int
put (const HashCode512 * key, const Datastore_Value * value)
{
  unsigned long contentSize;
  unsigned long hashSize;
  unsigned int size;
  unsigned int type;
  unsigned int prio;
  unsigned int level;
  unsigned long long expiration;
  unsigned long long vkey;
  MYSQL_BIND qbind[7];
#if DEBUG_MYSQL
  EncName enc;
#endif

  if (((ntohl (value->size) < sizeof (Datastore_Value))) ||
      ((ntohl (value->size) - sizeof (Datastore_Value)) > MAX_DATUM_SIZE))
    {
      GE_BREAK (ectx, 0);
      return SYSERR;
    }
  MUTEX_LOCK (lock);
  mysql_thread_init ();
  if (OK != CHECK_DBH)
    {
      mysql_thread_end ();
      MUTEX_UNLOCK (lock);
      return SYSERR;
    }
  contentSize = ntohl (value->size) - sizeof (Datastore_Value);
  if (OK != insert_value (&value[1], contentSize, &vkey))
    {
      mysql_thread_end ();
      MUTEX_UNLOCK (lock);
      return SYSERR;
    }
  hashSize = sizeof (HashCode512);
  size = ntohl (value->size);
  type = ntohl (value->type);
  prio = ntohl (value->prio);
  level = ntohl (value->anonymityLevel);
  expiration = ntohll (value->expirationTime);
#if DEBUG_MYSQL
  IF_GELOG (ectx, GE_DEBUG | GE_REQUEST | GE_USER, hash2enc (key, &enc));
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Storing in database block with type %u and key %s.\n", type, &enc);
#endif
  GE_ASSERT (ectx, mysql_stmt_param_count (dbh->insert_entry) == 7);
  memset (qbind, 0, sizeof (qbind));
  qbind[0].buffer_type = MYSQL_TYPE_LONG;       /* size */
  qbind[0].buffer = &size;
  qbind[0].is_unsigned = YES;
  qbind[1].buffer_type = MYSQL_TYPE_LONG;       /* type */
  qbind[1].is_unsigned = YES;
  qbind[1].buffer = &type;
  qbind[2].buffer_type = MYSQL_TYPE_LONG;       /* prio */
  qbind[2].is_unsigned = YES;
  qbind[2].buffer = &prio;
  qbind[3].buffer_type = MYSQL_TYPE_LONG;       /* anon level */
  qbind[3].is_unsigned = YES;
  qbind[3].buffer = &level;
  qbind[4].buffer_type = MYSQL_TYPE_LONGLONG;   /* expiration */
  qbind[4].is_unsigned = YES;
  qbind[4].buffer = &expiration;
  qbind[5].buffer_type = MYSQL_TYPE_BLOB;       /* hash */
  qbind[5].buffer = (void *) key;
  qbind[5].length = &hashSize;
  qbind[5].buffer_length = hashSize;
  qbind[6].buffer_type = MYSQL_TYPE_LONGLONG;   /* vkey */
  qbind[6].is_unsigned = YES;
  qbind[6].buffer = &vkey;

  if (mysql_stmt_bind_param (dbh->insert_entry, qbind))
    {
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("`%s' failed at %s:%d with error: %s\n"),
              "mysql_stmt_bind_param",
              __FILE__, __LINE__, mysql_stmt_error (dbh->insert_entry));
      delete_value (vkey);
      iclose ();
      mysql_thread_end ();
      MUTEX_UNLOCK (lock);
      return SYSERR;
    }

  if (mysql_stmt_execute (dbh->insert_entry))
    {
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("`%s' failed at %s:%d with error: %s\n"),
              "mysql_stmt_execute",
              __FILE__, __LINE__, mysql_stmt_error (dbh->insert_entry));
      delete_value (vkey);
      iclose ();
      mysql_thread_end ();
      MUTEX_UNLOCK (lock);
      return SYSERR;
    }
  mysql_thread_end ();
  content_size += ntohl (value->size);
  MUTEX_UNLOCK (lock);
  return OK;
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
 * @param is_prio is the extra ordering by priority (otherwise by expiration)
 * @return the number of results, SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int
iterateHelper (unsigned int type,
               int is_asc,
               int is_prio,
               unsigned int iter_select, Datum_Iterator iter, void *closure)
{
  Datastore_Value *datum;
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
  HashCode512 key;
  cron_t now;
  MYSQL_BIND qbind[5];
  MYSQL_BIND rbind[7];
  MYSQL_STMT *stmt;

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
  memset (qbind, 0, sizeof (qbind));
  if (is_prio)
    {
      qbind[0].buffer_type = MYSQL_TYPE_LONG;
      qbind[0].buffer = &last_prio;
      qbind[0].is_unsigned = YES;
      qbind[2].buffer_type = MYSQL_TYPE_LONG;
      qbind[2].buffer = &last_prio;
      qbind[2].is_unsigned = YES;
    }
  else
    {
      qbind[0].buffer_type = MYSQL_TYPE_LONGLONG;
      qbind[0].buffer = &last_expire;
      qbind[0].is_unsigned = YES;
      qbind[2].buffer_type = MYSQL_TYPE_LONGLONG;
      qbind[2].buffer = &last_expire;
      qbind[2].is_unsigned = YES;
    }
  qbind[1].buffer_type = MYSQL_TYPE_LONGLONG;
  qbind[1].buffer = &last_vkey;
  qbind[1].is_unsigned = YES;
  qbind[3].buffer_type = MYSQL_TYPE_LONGLONG;
  qbind[3].buffer = &last_vkey;
  qbind[3].is_unsigned = YES;
  qbind[4].buffer_type = MYSQL_TYPE_LONGLONG;
  qbind[4].buffer = &now;
  qbind[4].is_unsigned = YES;

  hashSize = sizeof (HashCode512);
  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_LONG;
  rbind[0].buffer = &size;
  rbind[0].is_unsigned = YES;
  rbind[1].buffer_type = MYSQL_TYPE_LONG;
  rbind[1].buffer = &rtype;
  rbind[1].is_unsigned = YES;
  rbind[2].buffer_type = MYSQL_TYPE_LONG;
  rbind[2].buffer = &prio;
  rbind[2].is_unsigned = YES;
  rbind[3].buffer_type = MYSQL_TYPE_LONG;
  rbind[3].buffer = &level;
  rbind[3].is_unsigned = YES;
  rbind[4].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[4].buffer = &expiration;
  rbind[4].is_unsigned = YES;
  rbind[5].buffer_type = MYSQL_TYPE_BLOB;
  rbind[5].buffer = &key;
  rbind[5].buffer_length = hashSize;
  rbind[5].length = &hashSize;
  rbind[6].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[6].buffer = &vkey;
  rbind[6].is_unsigned = YES;

  mysql_thread_init ();
  count = 0;
  while (1)
    {
      MUTEX_LOCK (lock);
      if (OK != CHECK_DBH)
        {
          MUTEX_UNLOCK (lock);
          mysql_thread_end ();
          return SYSERR;
        }
      stmt = dbh->iter[iter_select];
      GE_ASSERT (ectx, mysql_stmt_param_count (stmt) <= 5);
      GE_ASSERT (ectx, mysql_stmt_field_count (stmt) == 7);
      now = get_time ();
      if (mysql_stmt_bind_param (stmt, qbind))
        {
          GE_LOG (ectx,
                  GE_ERROR | GE_BULK | GE_USER,
                  _("`%s' failed at %s:%d with error: %s\n"),
                  "mysql_stmt_bind_param",
                  __FILE__, __LINE__, mysql_stmt_error (stmt));
          iclose ();
          MUTEX_UNLOCK (lock);
          mysql_thread_end ();
          return SYSERR;
        }
      if (mysql_stmt_execute (stmt))
        {
          GE_LOG (ectx,
                  GE_ERROR | GE_BULK | GE_USER,
                  _("`%s' failed at %s:%d with error: %s\n"),
                  "mysql_stmt_execute",
                  __FILE__, __LINE__, mysql_stmt_error (stmt));
          iclose ();
          MUTEX_UNLOCK (lock);
          mysql_thread_end ();
          return SYSERR;
        }
      if (mysql_stmt_bind_result (stmt, rbind))
        {
          GE_LOG (ectx,
                  GE_ERROR | GE_BULK | GE_USER,
                  _("`%s' failed at %s:%d with error: %s\n"),
                  "mysql_stmt_bind_result",
                  __FILE__, __LINE__, mysql_stmt_error (stmt));
          iclose ();
          mysql_thread_end ();
          MUTEX_UNLOCK (lock);
          return SYSERR;
        }
      datum = NULL;
      if (0 != mysql_stmt_fetch (stmt))
        {
          mysql_stmt_reset (stmt);
          MUTEX_UNLOCK (lock);
          break;
        }
      mysql_stmt_reset (stmt);
      MUTEX_UNLOCK (lock);
      last_vkey = vkey;
      last_prio = prio;
      last_expire = expiration;
      count++;
      if (iter != NULL)
        {
          datum = assembleDatum (rbind);
          if (datum == NULL)
            continue;
          if (iter == NULL)
            ret = OK;
          else
            ret = iter (&key, datum, closure, vkey);
          if (ret == SYSERR)
            {
              FREE (datum);
              break;
            }
          if (ret == NO)
            {
              MUTEX_LOCK (lock);
              delete_value (vkey);
              delete_entry_by_vkey (vkey);
              content_size -= ntohl (datum->size);
              MUTEX_UNLOCK (lock);
            }
          FREE (datum);
        }
    }
  mysql_thread_end ();
  return count;
}

/**
 * Iterate over the items in the datastore in ascending
 * order of priority.
 *
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter never NULL
 * @return the number of results, SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int
iterateLowPriority (unsigned int type, Datum_Iterator iter, void *closure)
{
  return iterateHelper (type, YES, YES, 0, iter, closure);
}

/**
 * Iterate over the items in the datastore that
 * have anonymity level 0.
 *
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter never NULL
 * @return the number of results, SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int
iterateNonAnonymous (unsigned int type, Datum_Iterator iter, void *closure)
{
  return iterateHelper (type, NO, YES, 1, iter, closure);
}

/**
 * Iterate over the items in the datastore in ascending
 * order of expiration time.
 *
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter never NULL
 * @return the number of results, SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int
iterateExpirationTime (unsigned int type, Datum_Iterator iter, void *closure)
{
  return iterateHelper (type, YES, NO, 2, iter, closure);
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
  return iterateHelper (0, NO, NO, 3, iter, closure);
}

/**
 * Iterate over the items in the datastore as
 * quickly as possible (in any order).
 *
 * @param iter never NULL
 * @return the number of results, SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int
iterateAllNow (Datum_Iterator iter, void *closure)
{
  return iterateHelper (0, YES, YES, 0, iter, closure);
}

/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param key maybe NULL (to match all entries)
 * @param type entries of which type are relevant?
 *     Use 0 for any type.
 * @param iter maybe NULL (to just count)
 * @return the number of results, SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int
get (const HashCode512 * query,
     unsigned int type, Datum_Iterator iter, void *closure)
{
  int count;
  int ret;
  MYSQL_STMT *stmt;
  unsigned int size;
  unsigned int rtype;
  unsigned int prio;
  unsigned int level;
  unsigned long long expiration;
  unsigned long long vkey;
  unsigned long long last_vkey;
  Datastore_Value *datum;
  HashCode512 key;
  unsigned long hashSize;
  MYSQL_BIND qbind[3];
  MYSQL_BIND rbind[7];
#if DEBUG_MYSQL
  EncName enc;
#endif

  if (query == NULL)
    return iterateLowPriority (type, iter, closure);

#if DEBUG_MYSQL
  IF_GELOG (ectx, GE_DEBUG | GE_REQUEST | GE_USER, hash2enc (query, &enc));
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "MySQL looks for `%s' of type %u\n", &enc, type);
#endif

  hashSize = sizeof (HashCode512);
  memset (qbind, 0, sizeof (qbind));
  qbind[0].buffer_type = MYSQL_TYPE_BLOB;
  qbind[0].buffer = (void *) query;
  qbind[0].length = &hashSize;
  qbind[0].buffer_length = hashSize;
  qbind[1].buffer_type = MYSQL_TYPE_LONGLONG;
  qbind[1].is_unsigned = YES;
  qbind[1].buffer = &last_vkey;
  qbind[2].buffer_type = MYSQL_TYPE_LONG;
  qbind[2].is_unsigned = YES;
  qbind[2].buffer = &type;
  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_LONG;
  rbind[0].buffer = &size;
  rbind[0].is_unsigned = YES;
  rbind[1].buffer_type = MYSQL_TYPE_LONG;
  rbind[1].buffer = &rtype;
  rbind[1].is_unsigned = YES;
  rbind[2].buffer_type = MYSQL_TYPE_LONG;
  rbind[2].buffer = &prio;
  rbind[2].is_unsigned = YES;
  rbind[3].buffer_type = MYSQL_TYPE_LONG;
  rbind[3].buffer = &level;
  rbind[3].is_unsigned = YES;
  rbind[4].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[4].buffer = &expiration;
  rbind[4].is_unsigned = YES;
  rbind[5].buffer_type = MYSQL_TYPE_BLOB;
  rbind[5].buffer = &key;
  rbind[5].buffer_length = hashSize;
  rbind[5].length = &hashSize;
  rbind[6].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[6].buffer = &vkey;
  rbind[6].is_unsigned = YES;


  mysql_thread_init ();
  last_vkey = 0;
  count = 0;
  while (1)
    {
      MUTEX_LOCK (lock);
      if (OK != CHECK_DBH)
        {
          MUTEX_UNLOCK (lock);
          mysql_thread_end ();
          return SYSERR;
        }
      if (type != 0)
        {
          if (iter == NULL)
            stmt = dbh->count_entry_by_hash_and_type;
          else
            stmt = dbh->select_entry_by_hash_and_type;
        }
      else
        {
          if (iter == NULL)
            stmt = dbh->count_entry_by_hash;
          else
            stmt = dbh->select_entry_by_hash;
        }

      GE_ASSERT (ectx, mysql_stmt_param_count (stmt) <= 3);
      if (iter == NULL)
        GE_ASSERT (ectx, mysql_stmt_field_count (stmt) == 1);
      else
        GE_ASSERT (ectx, mysql_stmt_field_count (stmt) == 7);
      if (mysql_stmt_bind_param (stmt, qbind))
        {
          GE_LOG (ectx,
                  GE_ERROR | GE_BULK | GE_USER,
                  _("`%s' failed at %s:%d with error: %s\n"),
                  "mysql_stmt_bind_param",
                  __FILE__, __LINE__, mysql_stmt_error (stmt));
          iclose ();
          mysql_thread_end ();
          MUTEX_UNLOCK (lock);
          return SYSERR;
        }
      if (mysql_stmt_execute (stmt))
        {
          GE_LOG (ectx,
                  GE_ERROR | GE_BULK | GE_USER,
                  _("`%s' failed at %s:%d with error: %s\n"),
                  "mysql_stmt_execute",
                  __FILE__, __LINE__, mysql_stmt_error (stmt));
          iclose ();
          MUTEX_UNLOCK (lock);
          mysql_thread_end ();
          return SYSERR;
        }
      if (mysql_stmt_bind_result (stmt, rbind))
        {
          GE_LOG (ectx,
                  GE_ERROR | GE_BULK | GE_USER,
                  _("`%s' failed at %s:%d with error: %s\n"),
                  "mysql_stmt_bind_result",
                  __FILE__, __LINE__, mysql_stmt_error (stmt));
          iclose ();
          mysql_thread_end ();
          MUTEX_UNLOCK (lock);
          return SYSERR;
        }
      if (0 != mysql_stmt_fetch (stmt))
        {
          mysql_stmt_reset (stmt);
          MUTEX_UNLOCK (lock);
          break;
        }
      last_vkey = vkey;
      if (iter == NULL)
        {
          count = mysql_stmt_affected_rows (stmt);
          mysql_stmt_reset (stmt);
          mysql_thread_end ();
          MUTEX_UNLOCK (lock);

          return count;
        }
      mysql_stmt_reset (stmt);
      MUTEX_UNLOCK (lock);
      datum = assembleDatum (rbind);
      if (datum == NULL)
        continue;
      count++;
      ret = iter (&key, datum, closure, vkey);
      if (ret == SYSERR)
        {
          FREE (datum);
          break;
        }
      if (ret == NO)
        {
          MUTEX_LOCK (lock);
          delete_value (vkey);
          delete_entry_by_vkey (vkey);
          content_size -= ntohl (datum->size);
          MUTEX_UNLOCK (lock);
        }
      FREE (datum);
    }
  mysql_thread_end ();
  return count;
}

/**
 * Update the priority for a particular key
 * in the datastore.
 */
static int
update (unsigned long long vkey, int delta, cron_t expire)
{
  cron_t start;
  MYSQL_BIND qbind[4];

  MUTEX_LOCK (lock);
  mysql_thread_init ();
  if (OK != CHECK_DBH)
    {
      mysql_thread_end ();
      MUTEX_UNLOCK (lock);
      return SYSERR;
    }
  memset (qbind, 0, sizeof (qbind));
  qbind[0].buffer_type = MYSQL_TYPE_LONG;
  qbind[0].buffer = &delta;
  qbind[1].buffer_type = MYSQL_TYPE_LONGLONG;
  qbind[1].buffer = &expire;
  qbind[1].is_unsigned = YES;
  qbind[2].buffer_type = MYSQL_TYPE_LONGLONG;
  qbind[2].is_unsigned = YES;
  qbind[2].buffer = &expire;
  qbind[3].buffer_type = MYSQL_TYPE_LONGLONG;
  qbind[3].is_unsigned = YES;
  qbind[3].buffer = &vkey;
  GE_ASSERT (ectx, mysql_stmt_param_count (dbh->update_entry) == 4);
  if (mysql_stmt_bind_param (dbh->update_entry, qbind))
    {
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("`%s' failed at %s:%d with error: %s\n"),
              "mysql_stmt_bind_param",
              __FILE__, __LINE__, mysql_stmt_error (dbh->update_entry));
      iclose ();
      mysql_thread_end ();
      MUTEX_UNLOCK (lock);
      return SYSERR;
    }
  /* NOTE: as the table entry for 'prio' is defined as unsigned,
   * mysql will zero the value if its about to go negative. (This
   * will generate a warning though, but its probably not seen
   * at all in this context.)
   */
  start = get_time ();
  if (mysql_stmt_execute (dbh->update_entry))
    {
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("`%s' failed at %s:%d with error `%s' after %llums\n"),
              "mysql_stmt_execute",
              __FILE__, __LINE__,
              mysql_stmt_error (dbh->update_entry), get_time () - start);
      iclose ();
      mysql_thread_end ();
      MUTEX_UNLOCK (lock);
      return SYSERR;
    }
  mysql_stmt_reset (dbh->update_entry);
  mysql_thread_end ();
  MUTEX_UNLOCK (lock);
  return OK;
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

  MUTEX_LOCK (lock);
  ret = content_size;
  if (stats)
    stats->set (stat_size, ret);
  MUTEX_UNLOCK (lock);
  return ret * 2;               /* FIXME: measure again! */
}

/**
 * Delete the database.  The next operation is
 * guaranteed to be unloading of the module.
 */
static void
drop ()
{
  int ok;

  ok = YES;
  MUTEX_LOCK (lock);
  mysql_thread_init ();
  if (OK != CHECK_DBH)
    {
      mysql_thread_end ();
      MUTEX_UNLOCK (lock);
      return;
    }
  mysql_query (dbh->dbf, "DROP TABLE gn071");
  if (mysql_error (dbh->dbf)[0])
    {
      LOG_MYSQL (GE_ERROR | GE_ADMIN | GE_BULK, "mysql_query", dbh);
      ok = NO;
    }
  mysql_query (dbh->dbf, "DROP TABLE gn072");
  if (mysql_error (dbh->dbf)[0])
    {
      LOG_MYSQL (GE_ERROR | GE_ADMIN | GE_BULK, "mysql_query", dbh);
      ok = NO;
    }
  if (ok == YES)
    content_size = 0;
  iclose ();
  mysql_thread_end ();
  MUTEX_UNLOCK (lock);
}

SQstore_ServiceAPI *
provide_module_sqstore_mysql (CoreAPIForApplication * capi)
{
  static SQstore_ServiceAPI api;
  State_ServiceAPI *state;
  char *cnffile;
  FILE *fp;
  struct passwd *pw;
  size_t nX;
  char *home_dir;
  unsigned long long *sb;
  MYSQL_RES *sql_res;
  MYSQL_ROW sql_row;

  ectx = capi->ectx;
  coreAPI = capi;
  stats = coreAPI->requestService ("stats");
  if (stats)
    stat_size = stats->create (gettext_noop ("# bytes in datastore"));

  /* verify that .my.cnf can be found */
#ifndef WINDOWS
  pw = getpwuid (getuid ());
  if (!pw)
    GE_DIE_STRERROR (ectx, GE_FATAL | GE_ADMIN | GE_IMMEDIATE, "getpwuid");
  home_dir = STRDUP (pw->pw_dir);
#else
  home_dir = (char *) MALLOC (_MAX_PATH + 1);
  plibc_conv_to_win_path ("~/", home_dir);
#endif
  nX = strlen (home_dir) + 10;
  cnffile = MALLOC (nX);
  SNPRINTF (cnffile, nX, "%s/.my.cnf", home_dir);
  FREE (home_dir);
  GC_get_configuration_value_filename (capi->cfg,
                                       "MYSQL", "CONFIG", cnffile, &home_dir);
  FREE (cnffile);
  cnffile = home_dir;
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          _("Trying to use file `%s' for MySQL configuration.\n"), cnffile);
  fp = FOPEN (cnffile, "r");
  if (!fp)
    {
      GE_LOG_STRERROR_FILE (ectx,
                            GE_ERROR | GE_ADMIN | GE_BULK, "fopen", cnffile);
      if (stats != NULL)
        coreAPI->releaseService (stats);
      FREE (cnffile);
      return NULL;
    }
  else
    {
      fclose (fp);
    }
  dbh = MALLOC (sizeof (mysqlHandle));
  memset (dbh, 0, sizeof (mysqlHandle));
  dbh->cnffile = cnffile;
  if (OK != iopen ())
    {
      FREE (cnffile);
      FREE (dbh);
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _
              ("Failed to load MySQL database module.  Check that MySQL is running and configured properly!\n"));
      dbh = NULL;
      if (stats != NULL)
        coreAPI->releaseService (stats);
      return NULL;
    }

  lock = MUTEX_CREATE (NO);
  state = coreAPI->requestService ("state");
  sb = NULL;
  if (sizeof (unsigned long long)
      != state->read (ectx, "mysql-size", (void *) &sb))
    {
      /* need to recompute! */
      sql_res = NULL;
      mysql_query (dbh->dbf, SELECT_SIZE);
      if ((mysql_error (dbh->dbf)[0]) ||
          (!(sql_res = mysql_use_result (dbh->dbf))) ||
          (!(sql_row = mysql_fetch_row (sql_res))))
        {
          LOG_MYSQL (GE_ERROR | GE_ADMIN | GE_BULK, "mysql_query", dbh);
          content_size = 0;
          iclose (dbh);
        }
      else
        {
          if ((mysql_num_fields (sql_res) != 1) || (sql_row[0] == NULL))
            {
              GE_BREAK (ectx, mysql_num_fields (sql_res) == 1);
              content_size = 0;
            }
          else
            {
              if (1 != SSCANF (sql_row[0], "%llu", &content_size))
                {
                  GE_BREAK (ectx, 0);
                  content_size = 0;
                }
            }
        }
      if (sql_res != NULL)
        mysql_free_result (sql_res);
    }
  else
    {
      content_size = *sb;
      FREE (sb);
      /* no longer valid! remember it by deleting
         the outdated state file! */
      state->unlink (ectx, "mysql-size");
    }
  coreAPI->releaseService (state);
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
  State_ServiceAPI *state;

  iclose (dbh);
  FREE (dbh->cnffile);
  FREE (dbh);
  dbh = NULL;
  if (stats != NULL)
    coreAPI->releaseService (stats);
  MUTEX_DESTROY (lock);
  state = coreAPI->requestService ("state");
  state->write (ectx,
                "mysql-size", sizeof (unsigned long long), &content_size);
  coreAPI->releaseService (state);
  mysql_library_end ();
  ectx = NULL;
  coreAPI = NULL;
}


/**
 * Update mysql database module.
 */
void
update_module_sqstore_mysql (UpdateAPI * uapi)
{
  char *cnffile;
  FILE *fp;
  struct passwd *pw;
  size_t nX;
  char *home_dir;

  ectx = uapi->ectx;
#ifndef WINDOWS
  pw = getpwuid (getuid ());
  if (!pw)
    GE_DIE_STRERROR (ectx, GE_FATAL | GE_ADMIN | GE_IMMEDIATE, "getpwuid");
  home_dir = STRDUP (pw->pw_dir);
#else
  home_dir = (char *) MALLOC (_MAX_PATH + 1);
  plibc_conv_to_win_path ("~/", home_dir);
#endif
  nX = strlen (home_dir) + 10;
  cnffile = MALLOC (nX);
  SNPRINTF (cnffile, nX, "%s/.my.cnf", home_dir);
  FREE (home_dir);
  GC_get_configuration_value_filename (uapi->cfg,
                                       "MYSQL", "CONFIG", cnffile, &home_dir);
  FREE (cnffile);
  cnffile = home_dir;
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          _("Trying to use file `%s' for MySQL configuration.\n"), cnffile);
  fp = FOPEN (cnffile, "r");
  if (!fp)
    {
      GE_LOG_STRERROR_FILE (ectx,
                            GE_ERROR | GE_ADMIN | GE_BULK, "fopen", cnffile);
      FREE (cnffile);
      return;
    }
  else
    {
      fclose (fp);
    }
  dbh = MALLOC (sizeof (mysqlHandle));
  memset (dbh, 0, sizeof (mysqlHandle));
  dbh->cnffile = cnffile;
  if (OK != iopen ())
    {
      FREE (cnffile);
      FREE (dbh);
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _
              ("Failed to load MySQL database module.  Check that MySQL is running and configured properly!\n"));
      dbh = NULL;
      return;
    }
  if ((0 == mysql_query (dbh->dbf,
                         "ALTER TABLE gn070 ADD COLUMN vkey BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT"))
      && (0 ==
          mysql_query (dbh->dbf,
                       "INSERT INTO gn071 (size,type,prio,anonLevel,expire,hash,vkey) (SELECT size,type,prio,anonLevel,expire,hash,vkey FROM gn070)"))
      && (0 ==
          mysql_query (dbh->dbf,
                       "INSERT INTO gn072 (vkey,value) (SELECT vkey,value FROM gn070)")))
    mysql_query (dbh->dbf, "DROP TABLE gn070");

  iclose (dbh);
  FREE (dbh->cnffile);
  FREE (dbh);
  dbh = NULL;
  mysql_library_end ();
  ectx = NULL;
}

/* end of mysql.c */
