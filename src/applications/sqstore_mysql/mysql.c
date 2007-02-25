/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * it uses prepared statements.
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
 *   1) by shutting down mysqld (mandatory!) and running
 *   # myisamchk -r *.MYI
 *   in /var/lib/mysql/gnunet/ (or wherever the tables are stored).
 *   Another repair command is "mysqlcheck". The usable command
 *   may depend on your mysql build/version. Or,
 *   2) by executing
 *   mysql> REPAIR TABLE gn070;
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
#include "gnunet_sqstore_service.h"
#include "gnunet_stats_service.h"
#include "gnunet_state_service.h"
#include <mysql/mysql.h>

#define DEBUG_MYSQL NO
#define DEBUG_TIME_MYSQL NO

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

static Stats_ServiceAPI * stats;

static CoreAPIForApplication * coreAPI;

static unsigned int stat_size;

/**
 * Size of the mysql database on disk.
 */
static unsigned long long content_size;

/**
 * Lock for updating content_size
 */
static struct MUTEX * lock;

static struct GE_Context * ectx;

/**
 * @brief mysql wrapper
 */
typedef struct {
  MYSQL * dbf;

  char * cnffile;

  int prepare;

  MYSQL_STMT * insert;

  MYSQL_BIND bind[7];

  MYSQL_STMT * select;

  MYSQL_STMT * selectc;

  MYSQL_STMT * selects;

  MYSQL_STMT * selectsc;

  MYSQL_BIND sbind[2];

  MYSQL_STMT * deleteh;

  MYSQL_STMT * deleteg;

  MYSQL_BIND dbind[7];

  MYSQL_STMT * update;

  MYSQL_BIND ubind[4];

  struct MUTEX * DATABASE_Lock_;

} mysqlHandle;

#define SELECT_SIZE "SELECT sum(size) FROM gn070"

#define INSERT_SAMPLE "INSERT INTO gn070 (size,type,prio,anonLevel,expire,hash,value) VALUES (?,?,?,?,?,?,?)"

#define SELECT_SAMPLE "SELECT * FROM gn070 WHERE hash=?"

#define SELECT_SAMPLE_COUNT "SELECT count(*) FROM gn070 WHERE hash=?"

#define SELECT_TYPE_SAMPLE "SELECT * FROM gn070 WHERE hash=? AND type=?"

#define SELECT_TYPE_SAMPLE_COUNT "SELECT count(*) FROM gn070 WHERE hash=? AND type=?"

/**
 * Select to prepare for key-based deletion.
 */
#define SELECT_HASH_SAMPLE "SELECT * FROM gn070 WHERE hash=? ORDER BY prio ASC LIMIT 1"

#define DELETE_GENERIC_SAMPLE "DELETE FROM gn070 WHERE hash=? AND size=? AND type=? AND prio=? AND anonLevel=? AND expire=? AND value=? ORDER BY prio ASC LIMIT 1"

#define UPDATE_SAMPLE "UPDATE gn070 SET prio=prio+?,expire=MAX(expire,?) WHERE hash=? AND value=?"

static mysqlHandle * dbh;

/**
 * Given a full (SELECT *) sql_row from gn070 table in database
 * order, assemble it into a Datastore_Datum representation.
 *
 */
static Datastore_Datum * assembleDatum(MYSQL_RES * res,
				       MYSQL_ROW sql_row,
				       mysqlHandle * dbhI) {
  Datastore_Datum * datum;
  int contentSize;
  unsigned long * lens;
  unsigned int type;
  unsigned int prio;
  unsigned int level;
  unsigned long long exp;

  contentSize = atol(sql_row[0]) - sizeof(Datastore_Value);
  if (contentSize < 0)
    return NULL; /* error */

  lens = mysql_fetch_lengths(res);
  if ( (lens[5] != sizeof(HashCode512)) ||
       (lens[6] != contentSize) ||
       (sscanf(sql_row[1], "%u", &type) != 1) ||
       (sscanf(sql_row[2], "%u", &prio) != 1) ||
       (sscanf(sql_row[3], "%u", &level) != 1) ||
       (SSCANF(sql_row[4], "%llu", &exp) != 1) ) {
    mysql_free_result(res);
    if ( (lens[5] != sizeof(HashCode512)) ||
	 (lens[6] != contentSize) ) {
      char scratch[512];

      GE_LOG(ectx,
	     GE_WARNING | GE_BULK | GE_USER,
	     _("Invalid data in %s.  Trying to fix (by deletion).\n"),
	     _("mysql datastore"));
      SNPRINTF(scratch,
	       512,
	       "DELETE FROM gn070 WHERE NOT ((LENGTH(hash)=%u) AND (size=%u + LENGTH(value)))",
	       sizeof(HashCode512),
	       sizeof(Datastore_Value));
      if (0 != mysql_query(dbhI->dbf, scratch))
	LOG_MYSQL(GE_ERROR | GE_ADMIN | GE_BULK, "mysql_query", dbhI);
    } else {
      GE_BREAK(ectx, 0); /* should really never happen */
    }
    return NULL;
  }
  datum = MALLOC(sizeof(Datastore_Datum) + contentSize);
  datum->value.size = htonl(contentSize + sizeof(Datastore_Value));
  datum->value.type = htonl(type);
  datum->value.prio = htonl(prio);
  datum->value.anonymityLevel = htonl(level);
  datum->value.expirationTime = htonll(exp);
  memcpy(&datum->key,
  	 sql_row[5],
	 sizeof(HashCode512));
  memcpy(&datum[1],
         sql_row[6],
	 contentSize);
  return datum;
}

/**
 * Initiate the database connection.
 * Uses dbhI->cnffile for the configuration,
 * so that must be set already.
 * @return OK on success
 */
static int iopen(mysqlHandle * dbhI,
		 int prepare) {
  char * dbname;

  if (dbhI->cnffile == NULL)
    return SYSERR;
  dbhI->dbf = mysql_init(NULL);
  if (dbhI->dbf == NULL)
    return SYSERR;
  mysql_options(dbhI->dbf,
  		MYSQL_READ_DEFAULT_FILE,
		dbh->cnffile);
  mysql_options(dbhI->dbf,
		MYSQL_READ_DEFAULT_GROUP,
		"client");
  dbname = NULL;
  GC_get_configuration_value_string(coreAPI->cfg,
				    "MYSQL",
				    "DATABASE",
				    "gnunet",
				    &dbname);
  GE_ASSERT(ectx, dbname != NULL);
  mysql_real_connect(dbhI->dbf,
		     NULL,
		     NULL,
		     NULL,
		     dbname,
		     0,
		     NULL,
		     0);
  FREE(dbname);
  if (mysql_error(dbhI->dbf)[0]) {
    LOG_MYSQL(GE_ERROR | GE_ADMIN | GE_BULK,
	      "mysql_real_connect",
	      dbhI);
    dbhI->dbf = NULL;
    return SYSERR;
  }
  if (prepare) {
    mysql_query(dbhI->dbf,
		"CREATE TABLE IF NOT EXISTS gn070 ("
		" size INT(11) NOT NULL DEFAULT 0,"
		" type INT(11) NOT NULL DEFAULT 0,"
		" prio INT(11) NOT NULL DEFAULT 0,"
		" anonLevel INT(11) NOT NULL DEFAULT 0,"
		" expire BIGINT NOT NULL DEFAULT 0,"
		" hash TINYBLOB NOT NULL DEFAULT '',"
		" value BLOB NOT NULL DEFAULT '',"
		" INDEX (hash(64)),"
		" INDEX (prio),"
		" INDEX (expire)"
		") TYPE=InnoDB");
    if (mysql_error(dbhI->dbf)[0]) {
      LOG_MYSQL(GE_ERROR | GE_ADMIN | GE_BULK,
		"mysql_query",
		dbhI);
      mysql_close(dbhI->dbf);
      dbhI->dbf = NULL;
      return SYSERR;
    }
    mysql_query(dbhI->dbf,
		"SET AUTOCOMMIT = 1");
    if (mysql_error(dbhI->dbf)[0]) {
      LOG_MYSQL(GE_ERROR | GE_ADMIN | GE_BULK,
		"mysql_query",
		dbhI);
      mysql_close(dbhI->dbf);
      dbhI->dbf = NULL;
      return SYSERR;
    }
    dbhI->insert = mysql_stmt_init(dbhI->dbf);
    dbhI->select = mysql_stmt_init(dbhI->dbf);
    dbhI->selectc = mysql_stmt_init(dbhI->dbf);
    dbhI->selects = mysql_stmt_init(dbhI->dbf);
    dbhI->selectsc = mysql_stmt_init(dbhI->dbf);
    dbhI->update = mysql_stmt_init(dbhI->dbf);
    dbhI->deleteh = mysql_stmt_init(dbhI->dbf);
    dbhI->deleteg = mysql_stmt_init(dbhI->dbf);
    if ( (dbhI->insert == NULL) ||
	 (dbhI->update == NULL) ||
	 (dbhI->select == NULL) ||
	 (dbhI->selectc == NULL) ||
	 (dbhI->selects == NULL) ||
	 (dbhI->selectsc == NULL) ||
	 (dbhI->deleteh == NULL) ||
	 (dbhI->deleteg == NULL) ) {
      GE_BREAK(ectx, 0);
      if (dbhI->insert != NULL)
	mysql_stmt_close(dbhI->insert);
      if (dbhI->update != NULL)
	mysql_stmt_close(dbhI->update);
      if (dbhI->select != NULL)
	mysql_stmt_close(dbhI->select);
      if (dbhI->selectc != NULL)
	mysql_stmt_close(dbhI->selectc);
      if (dbhI->selects != NULL)
	mysql_stmt_close(dbhI->selects);
      if (dbhI->selectsc != NULL)
	mysql_stmt_close(dbhI->selectsc);
      mysql_close(dbhI->dbf);
      dbhI->dbf = NULL;
      return SYSERR;
    }
    if (mysql_stmt_prepare(dbhI->insert,
			   INSERT_SAMPLE,
			   strlen(INSERT_SAMPLE)) ||
	mysql_stmt_prepare(dbhI->select,
			   SELECT_SAMPLE,
			   strlen(SELECT_SAMPLE)) ||
	mysql_stmt_prepare(dbhI->selectc,
			   SELECT_SAMPLE_COUNT,
			   strlen(SELECT_SAMPLE_COUNT)) ||
	mysql_stmt_prepare(dbhI->selects,
			   SELECT_TYPE_SAMPLE,
			   strlen(SELECT_TYPE_SAMPLE)) ||
	mysql_stmt_prepare(dbhI->selectsc,
			   SELECT_TYPE_SAMPLE_COUNT,
			   strlen(SELECT_TYPE_SAMPLE_COUNT)) ||
	mysql_stmt_prepare(dbhI->update,
			   UPDATE_SAMPLE,
			   strlen(UPDATE_SAMPLE)) ||
	mysql_stmt_prepare(dbhI->deleteh,
			   SELECT_HASH_SAMPLE,
			   strlen(SELECT_HASH_SAMPLE)) ||
	mysql_stmt_prepare(dbhI->deleteg,
			   DELETE_GENERIC_SAMPLE,
			   strlen(DELETE_GENERIC_SAMPLE)) ) {
      GE_LOG(ectx, GE_ERROR | GE_BULK | GE_USER,
	  _("`%s' failed at %s:%d with error: %s\n"),
	  "mysql_stmt_prepare",
	  __FILE__, __LINE__,
	  mysql_stmt_error(dbhI->insert));
      mysql_stmt_close(dbhI->insert);
      mysql_stmt_close(dbhI->select);
      mysql_stmt_close(dbhI->selectc);
      mysql_stmt_close(dbhI->selects);
      mysql_stmt_close(dbhI->selectsc);
      mysql_stmt_close(dbhI->update);
      mysql_stmt_close(dbhI->deleteh);
      mysql_stmt_close(dbhI->deleteg);
      mysql_close(dbhI->dbf);
      dbhI->dbf = NULL;
      return SYSERR;
    }
    memset(dbhI->bind,
	   0,
	   sizeof(dbhI->bind));
    dbhI->bind[0].buffer_type = MYSQL_TYPE_LONG; /* size */
    dbhI->bind[1].buffer_type = MYSQL_TYPE_LONG; /* type */
    dbhI->bind[2].buffer_type = MYSQL_TYPE_LONG; /* prio */
    dbhI->bind[3].buffer_type = MYSQL_TYPE_LONG; /* anon level */
    dbhI->bind[4].buffer_type = MYSQL_TYPE_LONGLONG; /* expiration */
    dbhI->bind[5].buffer_type = MYSQL_TYPE_TINY_BLOB; /* hash */
    dbhI->bind[6].buffer_type = MYSQL_TYPE_BLOB; /* value */
    memset(dbhI->sbind,
	   0,
	   sizeof(dbhI->sbind));
    dbhI->sbind[0].buffer_type = MYSQL_TYPE_TINY_BLOB; /* hash */
    dbhI->sbind[1].buffer_type = MYSQL_TYPE_LONG; /* type */
    memset(dbhI->dbind,
	   0,
	   sizeof(dbhI->dbind));
    dbhI->dbind[0].buffer_type = MYSQL_TYPE_TINY_BLOB; /* hash */
    dbhI->dbind[1].buffer_type = MYSQL_TYPE_LONG; /* size */
    dbhI->dbind[2].buffer_type = MYSQL_TYPE_LONG; /* type */
    dbhI->dbind[3].buffer_type = MYSQL_TYPE_LONG; /* prio */
    dbhI->dbind[4].buffer_type = MYSQL_TYPE_LONG; /* anon level */
    dbhI->dbind[5].buffer_type = MYSQL_TYPE_LONGLONG; /* expiration */
    dbhI->dbind[6].buffer_type = MYSQL_TYPE_BLOB; /* value */
    memset(dbhI->ubind,
	   0,
	   sizeof(dbhI->ubind));
    dbhI->ubind[0].buffer_type = MYSQL_TYPE_LONG;
    dbhI->ubind[1].buffer_type = MYSQL_TYPE_LONG;
    dbhI->ubind[2].buffer_type = MYSQL_TYPE_BLOB;
    dbhI->ubind[3].buffer_type = MYSQL_TYPE_BLOB;
    dbhI->prepare = YES;
  } else
    dbhI->prepare = NO;
  dbhI->DATABASE_Lock_ = MUTEX_CREATE(NO);
  return OK;
}

/**
 * Close the database connection.
 */
static int iclose(mysqlHandle * dbhI) {
  if (dbhI->dbf == NULL)
    return SYSERR;
  if (dbhI->prepare == YES) {
    mysql_stmt_free_result(dbhI->update);
    mysql_stmt_free_result(dbhI->insert);
    mysql_stmt_free_result(dbhI->select);
    mysql_stmt_free_result(dbhI->selectc);
    mysql_stmt_free_result(dbhI->selects);
    mysql_stmt_free_result(dbhI->selectsc);
    mysql_stmt_free_result(dbhI->deleteh);
    mysql_stmt_free_result(dbhI->deleteg);
    mysql_stmt_close(dbhI->update);
    mysql_stmt_close(dbhI->insert);
    mysql_stmt_close(dbhI->select);
    mysql_stmt_close(dbhI->selectc);
    mysql_stmt_close(dbhI->selects);
    mysql_stmt_close(dbhI->selectsc);
    mysql_stmt_close(dbhI->deleteh);
    mysql_stmt_close(dbhI->deleteg);
  }
  MUTEX_DESTROY(dbhI->DATABASE_Lock_);
  mysql_close(dbhI->dbf);
  dbhI->dbf = NULL;
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
 * @return the number of results, SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int iterateHelper(unsigned int type,
			 const char * query,
			 Datum_Iterator iter,
			 void * closure) {
  MYSQL_RES *sql_res;
  MYSQL_ROW sql_row;
  Datastore_Datum * datum;
  char * scratch;
  char typestr[32];
  int count = 0;
  mysqlHandle dbhI;
  cron_t now;

  dbhI.cnffile = dbh->cnffile; /* shared */
  if (OK != iopen(&dbhI, NO))
    return SYSERR;

  MUTEX_LOCK(dbhI.DATABASE_Lock_);

  mysql_query(dbhI.dbf,
	      "SET AUTOCOMMIT = 0");
  mysql_query(dbhI.dbf,
	      "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED");
  if (type==0) {
    typestr[0] = '\0';
  } else {
    SNPRINTF(typestr,
             32,
             "WHERE type=%u ",
	     type);
  }
  now = get_time();
  scratch = MALLOC(256);
  SNPRINTF(scratch,
	   256,	
	   query,
	   typestr,
	   now);
  mysql_query(dbhI.dbf,
	      scratch);
  FREE(scratch);
  if (mysql_error(dbhI.dbf)[0]) {
    LOG_MYSQL(GE_ERROR | GE_ADMIN | GE_BULK,
	      "mysql_query",
	      &dbhI);
    MUTEX_UNLOCK(dbhI.DATABASE_Lock_);
    iclose(&dbhI);
    return SYSERR;
  }
  if (!(sql_res=mysql_use_result(dbhI.dbf))) {
    MUTEX_UNLOCK(dbhI.DATABASE_Lock_);
    iclose(&dbhI);
    return SYSERR;
  }
  while ((sql_row=mysql_fetch_row(sql_res))) {
    datum = assembleDatum(sql_res,
			  sql_row,
			  &dbhI);
    if (datum == NULL) {
      MUTEX_UNLOCK(dbhI.DATABASE_Lock_);
      iclose(&dbhI);
      return count;
    }
    if ( (iter != NULL) &&
	 (SYSERR == iter(&datum->key,
			 &datum->value,
			 closure) ) ) {
      count = SYSERR;
      FREE(datum);
      break;
    }
    FREE(datum);
    count++;
  }
  if (mysql_error(dbhI.dbf)[0]) {
    LOG_MYSQL(GE_ERROR | GE_ADMIN | GE_BULK,
	      "mysql_query",
	      &dbhI);
    mysql_free_result(sql_res);
    MUTEX_UNLOCK(dbhI.DATABASE_Lock_);
    iclose(&dbhI);
    return SYSERR;
  }		
  mysql_free_result(sql_res);
  MUTEX_UNLOCK(dbhI.DATABASE_Lock_);
  iclose(&dbhI);
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
static int iterateLowPriority(unsigned int type,
			      Datum_Iterator iter,
			      void * closure) {
  return iterateHelper(type,
		       "SELECT SQL_NO_CACHE * FROM gn070"
		       " %s"
		       "ORDER BY prio ASC",
		       iter,
		       closure);
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
static int iterateExpirationTime(unsigned int type,
			         Datum_Iterator iter,
			         void * closure) {
  return iterateHelper(type,
		       "SELECT SQL_NO_CACHE * FROM gn070"
		       " %s"
		       " ORDER BY expire ASC",
		       iter,
		       closure);
}

/**
 * Iterate over the items in the datastore in migration
 * order.
 *
 * @param iter never NULL
 * @return the number of results, SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int iterateMigrationOrder(Datum_Iterator iter,
			         void * closure) {
  return iterateHelper(0,
		       "SELECT SQL_NO_CACHE * FROM gn070"
		       " %s WHERE expire > %llu"
		       " ORDER BY expire DESC",
		       iter,
		       closure);
}

/**
 * Iterate over the items in the datastore as
 * quickly as possible (in any order).
 *
 * @param iter never NULL
 * @return the number of results, SYSERR if the
 *   iter is non-NULL and aborted the iteration
 */
static int iterateAllNow(Datum_Iterator iter,
			 void * closure) {
  return iterateHelper(0,
		       "SELECT SQL_NO_CACHE * FROM gn070",
		       iter,
		       closure);
}

#define MAX_DATUM_SIZE 65536

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
static int get(const HashCode512 * query,
	       unsigned int type,	
	       Datum_Iterator iter,
	       void * closure) {
  MYSQL_RES * sql_res;
  int count;
  MYSQL_STMT * stmt;
  unsigned int size;
  unsigned int rtype;
  unsigned int prio;
  unsigned int level;
  unsigned long long expiration;
  unsigned long datasize;
  unsigned long twenty;
  Datastore_Value * datum;
  HashCode512 key;
  unsigned long hashSize;
#if DEBUG_MYSQL
  EncName enc;
#endif

  if (query == NULL)
    return iterateLowPriority(type, iter, closure);

#if DEBUG_MYSQL
  IF_GELOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   hash2enc(query,
		    &enc));
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "MySQL looks for `%s' of type %u\n",
	 &enc,
	 type);
#endif
  MUTEX_LOCK(dbh->DATABASE_Lock_);
  if (type != 0) {
    if (iter == NULL)
      stmt = dbh->selectsc;
    else
      stmt = dbh->selects;
  } else {
    if (iter == NULL)
      stmt = dbh->selectc;
    else
      stmt = dbh->select;
  }
  hashSize = sizeof(HashCode512);
  dbh->sbind[0].buffer = (char*) query;
  dbh->sbind[1].buffer = (char*) &type;
  dbh->sbind[0].length = &hashSize;
  GE_ASSERT(ectx, mysql_stmt_param_count(stmt) <= 2);
  sql_res = mysql_stmt_result_metadata(stmt);
  if (! sql_res) {
    GE_LOG(ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("`%s' failed at %s:%d with error: %s\n"),
	   "mysql_stmt_result_metadata",
	   __FILE__, __LINE__,
	   mysql_stmt_error(stmt));
    MUTEX_UNLOCK(dbh->DATABASE_Lock_);
    return SYSERR;
  }
  if (7 != mysql_num_fields(sql_res)) {
    GE_BREAK(ectx, 0);
    MUTEX_UNLOCK(dbh->DATABASE_Lock_);
    return SYSERR;
  }
  if (mysql_stmt_bind_param(stmt,
			    dbh->sbind)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("`%s' failed at %s:%d with error: %s\n"),
	   "mysql_stmt_bind_param",
	   __FILE__, __LINE__,
	   mysql_stmt_error(stmt));
    MUTEX_UNLOCK(dbh->DATABASE_Lock_);
    return SYSERR;
  }
  if (mysql_stmt_execute(stmt)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("`%s' failed at %s:%d with error: %s\n"),
	   "mysql_stmt_execute",
	   __FILE__, __LINE__,
	   mysql_stmt_error(stmt));
    MUTEX_UNLOCK(dbh->DATABASE_Lock_);
    return SYSERR;
  }

  datum = MALLOC(sizeof(Datastore_Value) + MAX_DATUM_SIZE);
  twenty = sizeof(HashCode512);
  dbh->bind[0].buffer = (char*) &size;
  dbh->bind[1].buffer = (char*) &rtype;
  dbh->bind[2].buffer = (char*) &prio;
  dbh->bind[3].buffer = (char*) &level;
  dbh->bind[4].buffer = (char*) &expiration;
  dbh->bind[5].buffer = (char*) &key;
  dbh->bind[6].buffer = (char*) &datum[1];
  dbh->bind[5].length = &twenty;
  dbh->bind[6].length = &datasize;
  dbh->bind[5].buffer_length = sizeof(HashCode512);
  dbh->bind[6].buffer_length = MAX_DATUM_SIZE;
  if (mysql_stmt_bind_result(stmt,
			     dbh->bind)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("`%s' failed at %s:%d with error: %s\n"),
	   "mysql_stmt_bind_result",
	   __FILE__, __LINE__,
	   mysql_stmt_error(stmt));
    MUTEX_UNLOCK(dbh->DATABASE_Lock_);
    FREE(datum);
    return SYSERR;
  }
  if (mysql_stmt_store_result(stmt)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("`%s' failed at %s:%d with error: %s\n"),
	   "mysql_stmt_store_result",
	   __FILE__, __LINE__,
	   mysql_stmt_error(stmt));
    MUTEX_UNLOCK(dbh->DATABASE_Lock_);
    FREE(datum);
    return SYSERR;
  }
  datasize = MAX_DATUM_SIZE;
  count = 0;
  while (0 == mysql_stmt_fetch(stmt)) {
    if ( (twenty != sizeof(HashCode512)) ||
	 (datasize != size - sizeof(Datastore_Value)) ) {
      char scratch[512];

      mysql_free_result(sql_res);
      GE_LOG(ectx,
	     GE_WARNING | GE_BULK | GE_USER,
	     _("Invalid data in %s.  Trying to fix (by deletion).\n"),
	     _("mysql datastore"));
      SNPRINTF(scratch,
	       512,
	       "DELETE FROM gn070 WHERE NOT ((LENGTH(hash)=%u) AND (size=%u + LENGTH(value)))",
	       sizeof(HashCode512),
	       sizeof(Datastore_Value));
      if (0 != mysql_query(dbh->dbf, scratch))
	LOG_MYSQL(GE_ERROR | GE_ADMIN | GE_BULK, "mysql_query", dbh);

      FREE(datum);
      MUTEX_UNLOCK(dbh->DATABASE_Lock_);
      return count;
    }
    count++;
    if (iter != NULL) {
      datum->size = htonl(size);
      datum->type = htonl(rtype);
      datum->prio = htonl(prio);
      datum->anonymityLevel = htonl(level);
      datum->expirationTime = htonll(expiration);
#if DEBUG_MYSQL
      GE_LOG(ectx,
	     GE_DEBUG | GE_REQUEST | GE_USER,
	     "Found in database block with type %u.\n",
	     ntohl(*(int*)&datum[1]));
#endif
      if( SYSERR == iter(&key,
			 datum,
			 closure) ) {
        count = SYSERR;
	break;
      }
    }
    datasize = MAX_DATUM_SIZE;
  }
  if (mysql_stmt_errno(stmt)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("`%s' failed at %s:%d with error: %s\n"),
	   "mysql_stmt_fetch",
	   __FILE__, __LINE__,
	   mysql_stmt_error(stmt));
  }
  mysql_free_result(sql_res);
  FREE(datum);
  MUTEX_UNLOCK(dbh->DATABASE_Lock_);

#if DEBUG_MYSQL
  IF_GELOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   hash2enc(query,
		    &enc));
  if (count > 0) {
    GE_LOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "MySQL found %d results for `%s' of type %u.\n",
	   count,
	   &enc,
	   type);
  } else {
    GE_LOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "MySQL iteration aborted looking for `%s' of type %u.\n",
	   &enc,
	   type);
  }
#endif
  return count;
}

/**
 * Store an item in the datastore.
 *
 * @return OK on success, SYSERR on error
 */
static int put(const HashCode512 * key,
	       const Datastore_Value * value) {
  unsigned long contentSize;
  unsigned long hashSize;
  unsigned int size;
  unsigned int type;
  unsigned int prio;
  unsigned int level;
  unsigned long long expiration;
#if DEBUG_MYSQL
  EncName enc;
#endif

  if ( (ntohl(value->size) < sizeof(Datastore_Value)) ) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  MUTEX_LOCK(dbh->DATABASE_Lock_);
  contentSize = ntohl(value->size)-sizeof(Datastore_Value);
  hashSize = sizeof(HashCode512);
  size = ntohl(value->size);
  type = ntohl(value->type);
  prio = ntohl(value->prio);
  level = ntohl(value->anonymityLevel);
  expiration = ntohll(value->expirationTime);
#if DEBUG_MYSQL
  IF_GELOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   hash2enc(key,
		    &enc));
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "Storing in database block with type %u and key %s.\n",
	 type,
	 &enc);
#endif
  dbh->bind[0].buffer = (char*) &size;
  dbh->bind[1].buffer = (char*) &type;
  dbh->bind[2].buffer = (char*) &prio;
  dbh->bind[3].buffer = (char*) &level;
  dbh->bind[4].buffer = (char*) &expiration;
  dbh->bind[5].buffer = (char*) key;
  dbh->bind[6].buffer = (char*) &value[1];
  dbh->bind[5].length = &hashSize;
  dbh->bind[6].length = &contentSize;

  if (mysql_stmt_bind_param(dbh->insert,
			    dbh->bind)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("`%s' failed at %s:%d with error: %s\n"),
	   "mysql_stmt_bind_param",
	   __FILE__, __LINE__,
	   mysql_stmt_error(dbh->insert));
    MUTEX_UNLOCK(dbh->DATABASE_Lock_);
    return SYSERR;
  }

  if (mysql_stmt_execute(dbh->insert)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("`%s' failed at %s:%d with error: %s\n"),
	   "mysql_stmt_execute",
	   __FILE__, __LINE__,
	   mysql_stmt_error(dbh->insert));
    MUTEX_UNLOCK(dbh->DATABASE_Lock_);
    return SYSERR;
  }
  MUTEX_UNLOCK(dbh->DATABASE_Lock_);
  MUTEX_LOCK(lock);
  content_size += ntohl(value->size);
  MUTEX_UNLOCK(lock);
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
  int count;
  unsigned long twenty;
  MYSQL_STMT * stmt;
  unsigned int size;
  unsigned int type;
  unsigned int prio;
  unsigned int anon;
  unsigned long long expiration;
  unsigned long datasize;
  Datastore_Value * svalue;
  MYSQL_RES * sql_res;
  unsigned int rtype;
  unsigned int level;
  HashCode512 skey;
#if DEBUG_MYSQL
  EncName enc;

  IF_GELOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   hash2enc(key,
		    &enc));
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "MySQL is executing deletion request for content of query `%s' and type %u\n",
	 &enc,
	 value == NULL ? 0 : ntohl(value->type));
#endif
  MUTEX_LOCK(dbh->DATABASE_Lock_);
  twenty = sizeof(HashCode512);
  svalue = NULL;
  if (value == NULL) {
    stmt = dbh->deleteh;
    dbh->dbind[0].buffer = (char*) key;
    dbh->dbind[0].length = &twenty;
    GE_ASSERT(ectx, mysql_stmt_param_count(stmt) <= 1);

    sql_res = mysql_stmt_result_metadata(stmt);
    if (! sql_res) {
      GE_LOG(ectx,
	     GE_ERROR | GE_BULK | GE_USER,
	     _("`%s' failed at %s:%d with error: %s\n"),
	     "mysql_stmt_result_metadata",
	     __FILE__, __LINE__,
	     mysql_stmt_error(stmt));
      MUTEX_UNLOCK(dbh->DATABASE_Lock_);
      return SYSERR;
    }
    if (7 != mysql_num_fields(sql_res)) {
      GE_BREAK(ectx, 0);
      MUTEX_UNLOCK(dbh->DATABASE_Lock_);
      return SYSERR;
    }
    if (mysql_stmt_bind_param(stmt,
			      dbh->dbind)) {
      GE_LOG(ectx,
	     GE_ERROR | GE_BULK | GE_USER,
	     _("`%s' failed at %s:%d with error: %s\n"),
	     "mysql_stmt_bind_param",
	     __FILE__, __LINE__,
	     mysql_stmt_error(stmt));
      MUTEX_UNLOCK(dbh->DATABASE_Lock_);
      return SYSERR;
    }
    if (mysql_stmt_execute(stmt)) {
      GE_LOG(ectx,
	     GE_ERROR | GE_BULK | GE_USER,
	     _("`%s' failed at %s:%d with error: %s\n"),
	     "mysql_stmt_execute",
	     __FILE__, __LINE__,
	     mysql_stmt_error(stmt));
      MUTEX_UNLOCK(dbh->DATABASE_Lock_);
      return SYSERR;
    }
    svalue = MALLOC(sizeof(Datastore_Value) + MAX_DATUM_SIZE);
    twenty = sizeof(HashCode512);
    dbh->bind[0].buffer = (char*) &size;
    dbh->bind[1].buffer = (char*) &rtype;
    dbh->bind[2].buffer = (char*) &prio;
    dbh->bind[3].buffer = (char*) &level;
    dbh->bind[4].buffer = (char*) &expiration;
    dbh->bind[5].buffer = (char*) &skey;
    dbh->bind[6].buffer = (char*) &svalue[1];
    dbh->bind[5].length = &twenty;
    dbh->bind[6].length = &datasize;
    dbh->bind[5].buffer_length = sizeof(HashCode512);
    dbh->bind[6].buffer_length = MAX_DATUM_SIZE;
    if (mysql_stmt_bind_result(stmt,
			       dbh->bind)) {
      GE_LOG(ectx,
	     GE_ERROR | GE_BULK | GE_USER,
	     _("`%s' failed at %s:%d with error: %s\n"),
	     "mysql_stmt_bind_result",
	     __FILE__, __LINE__,
	     mysql_stmt_error(stmt));
      MUTEX_UNLOCK(dbh->DATABASE_Lock_);
      FREE(svalue);
      return SYSERR;
    }
    if (mysql_stmt_store_result(stmt)) {
      GE_LOG(ectx,
	     GE_ERROR | GE_BULK | GE_USER,
	     _("`%s' failed at %s:%d with error: %s\n"),
	     "mysql_stmt_store_result",
	     __FILE__, __LINE__,
	     mysql_stmt_error(stmt));
      MUTEX_UNLOCK(dbh->DATABASE_Lock_);
      FREE(svalue);
      return SYSERR;
    }
    datasize = MAX_DATUM_SIZE;
    if (0 != mysql_stmt_fetch(stmt)) {
      GE_LOG(ectx,
	     GE_ERROR | GE_BULK | GE_USER,
	     _("`%s' failed at %s:%d with error: %s\n"),
	     "mysql_stmt_fetch",
	     __FILE__, __LINE__,
	     mysql_stmt_error(stmt));
      MUTEX_UNLOCK(dbh->DATABASE_Lock_);
      FREE(svalue);
      return SYSERR;
    }
    if ( (twenty != sizeof(HashCode512)) ||
	 (datasize != size - sizeof(Datastore_Value)) ) {
      char scratch[512];

      mysql_free_result(sql_res);
      GE_LOG(ectx,
	     GE_WARNING | GE_BULK | GE_USER,
	     _("Invalid data in %s.  Trying to fix (by deletion).\n"),
	     _("mysql datastore"));
      SNPRINTF(scratch,
	       512,
	       "DELETE FROM gn070 WHERE NOT ((LENGTH(hash)=%u) AND (size=%u + LENGTH(value)))",
	       sizeof(HashCode512),
	       sizeof(Datastore_Value));
      if (0 != mysql_query(dbh->dbf, scratch))
	LOG_MYSQL(GE_ERROR | GE_ADMIN | GE_BULK,
		  "mysql_query", dbh);
      FREE(svalue);
      MUTEX_UNLOCK(dbh->DATABASE_Lock_);
      return 1;
    }
    mysql_free_result(sql_res);
    svalue->size = htonl(size);
    svalue->type = htonl(rtype);
    svalue->prio = htonl(prio);
    svalue->anonymityLevel = htonl(level);
    svalue->expirationTime = htonll(expiration);
    value = svalue;
  }

  stmt = dbh->deleteg;
  type = ntohl(value->type);
  size = ntohl(value->size);
  prio = ntohl(value->prio);
  anon = ntohl(value->anonymityLevel);
  expiration = ntohll(value->expirationTime);
  datasize = ntohl(value->size) - sizeof(Datastore_Value);
  dbh->dbind[0].buffer = (char*) key;
  dbh->dbind[0].length = &twenty;
  dbh->dbind[1].buffer = (char*) &size;
  dbh->dbind[2].buffer = (char*) &type;
  dbh->dbind[3].buffer = (char*) &prio;
  dbh->dbind[4].buffer = (char*) &anon;
  dbh->dbind[5].buffer = (char*) &expiration;
  dbh->dbind[6].buffer = (char*) &value[1];
  dbh->dbind[6].length = &datasize;
#if 0
  dbh->dbind[0].buffer_length = sizeof(HashCode512);
  dbh->dbind[6].buffer_length = size - sizeof(Datastore_Value);
#endif
  GE_ASSERT(ectx, mysql_stmt_param_count(stmt) <= 7);
  if (mysql_stmt_bind_param(stmt,
			    dbh->dbind)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("`%s' failed at %s:%d with error: %s\n"),
	   "mysql_stmt_bind_param",
	   __FILE__, __LINE__,
	   mysql_stmt_error(stmt));
    MUTEX_UNLOCK(dbh->DATABASE_Lock_);
    if (svalue != NULL)
      FREE(svalue);
    return SYSERR;
  }
  if (mysql_stmt_execute(stmt)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("`%s' failed at %s:%d with error: %s\n"),
	   "mysql_stmt_execute",
	   __FILE__, __LINE__,
	   mysql_stmt_error(stmt));
    MUTEX_UNLOCK(dbh->DATABASE_Lock_);
    if (svalue != NULL)
      FREE(svalue);
    return SYSERR;
  }
  count = mysql_stmt_affected_rows(stmt);
  MUTEX_UNLOCK(dbh->DATABASE_Lock_);
#if DEBUG_MYSQL
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "MySQL DELETE operation affected %d rows.\n",
	 count);
#endif
  MUTEX_LOCK(lock);
  content_size -= ntohl(value->size);
  MUTEX_UNLOCK(lock);
  if (svalue != NULL)
    FREE(svalue);
  return count;
}

/**
 * Update the priority for a particular key
 * in the datastore.
 */
static int update(const HashCode512 * key,
		  const Datastore_Value * value,
		  int delta,
		  cron_t expire) {
  unsigned long contentSize;
  unsigned long twenty;

  twenty = sizeof(HashCode512);
  MUTEX_LOCK(dbh->DATABASE_Lock_);
  contentSize = ntohl(value->size)-sizeof(Datastore_Value);
  dbh->ubind[0].buffer = (char*) &delta;
  dbh->ubind[1].buffer = (char*) &expire;
  dbh->ubind[2].buffer = (char*) key;
  dbh->ubind[2].length = &twenty;
  dbh->ubind[3].buffer = (char*) &value[1];
  dbh->ubind[3].length = &contentSize;
  GE_ASSERT(ectx, 
	    mysql_stmt_param_count(dbh->update) <= 4);
  if (mysql_stmt_bind_param(dbh->update,
			    dbh->ubind)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("`%s' failed at %s:%d with error: %s\n"),
	   "mysql_stmt_bind_param",
	   __FILE__, __LINE__,
	   mysql_stmt_error(dbh->update));
    MUTEX_UNLOCK(dbh->DATABASE_Lock_);
    return SYSERR;
  }
  /* NOTE: as the table entry for 'prio' is defined as unsigned,
   * mysql will zero the value if its about to go negative. (This
   * will generate a warning though, but its probably not seen
   * at all in this context.)
   */
  if (mysql_stmt_execute(dbh->update)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("`%s' failed at %s:%d with error: %s\n"),
	   "mysql_stmt_execute",
	   __FILE__, __LINE__,
	   mysql_stmt_error(dbh->update));
    MUTEX_UNLOCK(dbh->DATABASE_Lock_);
    return SYSERR;
  }
  MUTEX_UNLOCK(dbh->DATABASE_Lock_);
  return OK;
}

/**
 * Get the current on-disk size of the SQ store.
 * Estimates are fine, if that's the only thing
 * available.
 * @return number of bytes used on disk
 */
static unsigned long long getSize() {
  unsigned long long ret;

  MUTEX_LOCK(lock);
  ret = content_size;
  if (stats)
    stats->set(stat_size, ret);
  MUTEX_UNLOCK(lock);
  return ret * 2; /* common overhead seems to be 100%! */
}

/**
 * Delete the database.  The next operation is
 * guaranteed to be unloading of the module.
 */
static void drop() {
  mysql_query(dbh->dbf,
	      "DROP TABLE gn070");
  if (mysql_error(dbh->dbf)[0]) {
    LOG_MYSQL(GE_ERROR | GE_ADMIN | GE_BULK,
	      "mysql_query",
	      dbh);
  } else
    content_size = 0;
}

SQstore_ServiceAPI *
provide_module_sqstore_mysql(CoreAPIForApplication * capi) {
  static SQstore_ServiceAPI api;
  State_ServiceAPI * state;
  char * cnffile;
  FILE * fp;
  struct passwd * pw;
  size_t nX;
  char * home_dir;
  unsigned long long * sb;
  MYSQL_RES *sql_res;
  MYSQL_ROW sql_row;

  ectx = capi->ectx;
  coreAPI = capi;
  stats = coreAPI->requestService("stats");
  if (stats)
    stat_size
      = stats->create(gettext_noop("# bytes in datastore"));

  /* verify that .my.cnf can be found */
#ifndef WINDOWS
  pw = getpwuid(getuid());
  if(!pw)
    GE_DIE_STRERROR(ectx,
		    GE_FATAL | GE_ADMIN | GE_IMMEDIATE,
		    "getpwuid");
  home_dir = STRDUP(pw->pw_dir);
#else
  home_dir = (char *) MALLOC(_MAX_PATH + 1);
  plibc_conv_to_win_path("~/", home_dir);
#endif
  nX = strlen(home_dir)+10;
  cnffile = MALLOC(nX);
  SNPRINTF(cnffile,
	   nX,
	   "%s/.my.cnf",
	   home_dir);
  FREE(home_dir);
  GC_get_configuration_value_filename(capi->cfg,
				      "MYSQL",
				      "CONFIG",
				      cnffile,
				      &home_dir);
  FREE(cnffile);
  cnffile = home_dir;
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 _("Trying to use file `%s' for MySQL configuration.\n"),
	 cnffile);
  fp = FOPEN(cnffile, "r");
  if (!fp) {
    GE_LOG_STRERROR_FILE(ectx,
			 GE_ERROR | GE_ADMIN | GE_BULK,
			 "fopen",
			 cnffile);
    if (stats != NULL)
      coreAPI->releaseService(stats);
    FREE(cnffile);
    return NULL;
  } else {
    fclose(fp);
  }

  dbh = MALLOC(sizeof(mysqlHandle));
  dbh->cnffile = cnffile;
  if (OK != iopen(dbh, YES)) {
    FREE(cnffile);
    FREE(dbh);
    GE_LOG(ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("Failed to load MySQL database module.  Check that MySQL is running and configured properly!\n"));
    dbh = NULL;
    if (stats != NULL)
      coreAPI->releaseService(stats);
    return NULL;
  }

  lock = MUTEX_CREATE(NO);
  state = coreAPI->requestService("state");
  sb = NULL;
  if (sizeof(unsigned long long)
      != state->read(ectx,
		     "mysql-size",
		     (void*) &sb)) {

    /* need to recompute! */
    sql_res = NULL;
    mysql_query(dbh->dbf,
		SELECT_SIZE);
    if ( (mysql_error(dbh->dbf)[0]) ||
	 (!(sql_res=mysql_use_result(dbh->dbf))) ||
	 (!(sql_row=mysql_fetch_row(sql_res))) ) {
      LOG_MYSQL(GE_ERROR | GE_ADMIN | GE_BULK,
		"mysql_query",
		dbh);
      content_size = 0;
    } else {
      if ( (mysql_num_fields(sql_res) != 1) ||
	   (sql_row[0] == NULL) ) {
	GE_BREAK(ectx, mysql_num_fields(sql_res) == 1);
	content_size = 0;
      } else {
	if (1 != SSCANF(sql_row[0],
			"%llu",
			&content_size)) {
	  GE_BREAK(ectx, 0);
	  content_size = 0;
	}
      }
    }
    if (sql_res != NULL)
      mysql_free_result(sql_res);
  } else {
    content_size = *sb;
    FREE(sb);
    /* no longer valid! remember it by deleting
       the outdated state file! */
    state->unlink(ectx,
		  "mysql-size");
  }
  coreAPI->releaseService(state);
  api.getSize = &getSize;
  api.put = &put;
  api.get = &get;
  api.iterateLowPriority = &iterateLowPriority;
  api.iterateExpirationTime = &iterateExpirationTime;
  api.iterateMigrationOrder = &iterateMigrationOrder;
  api.iterateAllNow = &iterateAllNow;
  api.del = &del;
  api.drop = &drop;
  api.update = &update;
  return &api;
}

/**
 * Shutdown the module.
 */
void release_module_sqstore_mysql() {
  State_ServiceAPI * state;
  iclose(dbh);
  FREE(dbh->cnffile);
  FREE(dbh);
  dbh = NULL;

  if (stats != NULL)
    coreAPI->releaseService(stats);
  MUTEX_DESTROY(lock);
  state = coreAPI->requestService("state");
  state->write(ectx,
	       "mysql-size",
	       sizeof(unsigned long long),
	       &content_size);
  coreAPI->releaseService(state);
  mysql_library_end();
  ectx = NULL;
  coreAPI = NULL;
}

/* end of mysql.c */
