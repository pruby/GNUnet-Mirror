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
 * @file applications/sqstore_mysql/mysql.c
 * @author Igor Wronsky
 *
 * Database: MySQL
 *
 * NOTE: This db module does NOT work with mysql v3.23.49 due to a bug
 * in mysql.  All later versions should be fine, including the 4.0.x
 * series. Current devel version is 4.0.22 on debian/unstable.
 *
 * HIGHLIGHTS
 *
 * Pros
 * + On up-to-date hardware where mysql can be used comfortably, this
 *   module will have better performance than the other db choices
 *   (according to our tests). 
 * + Its often possible to recover the mysql database from internal 
 *   inconsistencies. The other db choices do not support repair 
 *   (gnunet-check cannot fix problems internal to the dbmgr!). 
 *   For example, we have seen several cases where power failure 
 *   has ruined a gdbm database beyond repair. 
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
 *    # mysql -u root -p 
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
 *    # mysql -u $USER
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
 * EFFICIENCY ISSUES
 *
 * If you suffer from too slow index/insert speeds, 
 * you might try to define /etc/gnunet.conf option
 *
 *   [MYSQL]
 *   DELAYED = YES
 *
 * for small efficiency boost. The option will let MySQL bundle multiple 
 * inserts before actually writing them to disk. You shouldn't use this 
 * option unless you're an (my)sql expert and really know what you're doing. 
 * Especially, if you run into any trouble due to this, you're on your own.
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
#include <mysql/mysql.h>

#define DEBUG_MYSQL NO
#define DEBUG_TIME_MYSQL NO

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define DIE_MYSQL(cmd, dbh) do { errexit(_("'%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, mysql_error((dbh)->dbf)); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_MYSQL(level, cmd, dbh) do { LOG(level, _("'%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, mysql_error((dbh)->dbf)); } while(0);




/**
 * @brief mysql wrapper
 */
typedef struct {
  MYSQL * dbf; 
  Mutex DATABASE_Lock_;
  int avgLength_ID;	   /* which column contains the Avg_row_length  
                            * in SHOW TABLE STATUS resultset */
  int useDelayed;          /* use potentially unsafe delayed inserts? */
  char * cnffile;  
  MYSQL_STMT * insert;
  MYSQL_BIND bind[7];
  MYSQL_STMT * select;
  MYSQL_STMT * selectc;
  MYSQL_STMT * selects;
  MYSQL_STMT * selectsc;
  MYSQL_BIND sbind[2];
  
} mysqlHandle;

#define INSERT_SAMPLE "INSERT INTO gn070 (size,type,prio,anonLevel,expire,hash,value) VALUES (?,?,?,?,?,?,?)"
#define INSERT_SAMPLE_DELAYED "INSERT DELAYED INTO gn070 (size,type,prio,anonLevel,expire,hash,value) VALUES (?,?,?,?,?,?,?)"

#define SELECT_SAMPLE "SELECT * FROM gn070 WHERE hash=?"
#define SELECT_SAMPLE_COUNT "SELECT count(*) FROM gn070 WHERE hash=?"
#define SELECT_TYPE_SAMPLE "SELECT * FROM gn070 WHERE hash=? AND type=?"
#define SELECT_TYPE_SAMPLE_COUNT "SELECT count(*) FROM gn070 WHERE hash=? AND type=?"

static mysqlHandle * dbh;

/**
 * Given a full (SELECT *) sql_row from gn070 table in database 
 * order, assemble it into a Datastore_Datum representation.
 *
 */
static Datastore_Datum * assembleDatum(MYSQL_RES * res,
				       MYSQL_ROW sql_row) {
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
  if ( (lens[5] != sizeof(HashCode160)) ||
       (lens[6] != contentSize) ||
       (sscanf(sql_row[1], "%u", &type) != 1) ||
       (sscanf(sql_row[2], "%u", &prio) != 1) ||
       (sscanf(sql_row[3], "%u", &level) != 1) ||
       (sscanf(sql_row[4], "%llu", &exp) != 1) ) {
    LOG(LOG_WARNING,
	"SQL Database corrupt, ignoring result.\n");
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
	 sizeof(HashCode160)); 
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
static int iopen(mysqlHandle * dbhI) {
  char * scratch;

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
  mysql_real_connect(dbhI->dbf,
		     NULL,
		     NULL,
		     NULL,
		     "gnunet",
		     0,
		     NULL,
		     0);
  if (mysql_error(dbhI->dbf)[0]) {
    LOG_MYSQL(LOG_ERROR, 
	      "mysql_real_connect",
	      dbhI);
    dbhI->dbf = NULL;
    return SYSERR;
  }

  scratch = MALLOC(1024);
  SNPRINTF(scratch,
	   1024,
	   "CREATE TABLE IF NOT EXISTS gn070 ("
	   "  size INT(11) UNSIGNED NOT NULL DEFAULT 0,"
	   "  type INT(11) UNSIGNED NOT NULL DEFAULT 0,"
	   "  prio INT(11) UNSIGNED NOT NULL DEFAULT 0,"
	   "  anonLevel INT(11) UNSIGNED NOT NULL DEFAULT 0,"
	   "  expire BIGINT UNSIGNED NOT NULL DEFAULT 0," 
	   "  hash TINYBLOB BINARY NOT NULL DEFAULT '',"
	   "  value MEDIUMBLOB NOT NULL DEFAULT '',"
	   "  INDEX (hash(20)),"
	   "  INDEX (prio),"
	   "  INDEX (expire)"
	   ") TYPE=MyISAM");
  mysql_query(dbhI->dbf,
  	      scratch);
  if (mysql_error(dbhI->dbf)[0]) {
    LOG_MYSQL(LOG_ERROR, 
	      "mysql_query",
	      dbhI);
    mysql_close(dbhI->dbf);
    dbhI->dbf = NULL;
    FREE(scratch);
    return SYSERR;
  }
  FREE(scratch);


  dbhI->insert = mysql_stmt_init(dbhI->dbf);
  dbhI->select = mysql_stmt_init(dbhI->dbf);
  dbhI->selectc = mysql_stmt_init(dbhI->dbf);
  dbhI->selects = mysql_stmt_init(dbhI->dbf);
  dbhI->selectsc = mysql_stmt_init(dbhI->dbf);
  if ( (dbhI->insert == NULL) ||
       (dbhI->select == NULL) ||
       (dbhI->selectc == NULL) ||
       (dbhI->selects == NULL) ||
       (dbhI->selectsc == NULL) ) {       
    BREAK();
    if (dbhI->insert != NULL)
      mysql_stmt_close(dbhI->insert);
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
			 dbh->useDelayed
			 ? INSERT_SAMPLE_DELAYED
			 : INSERT_SAMPLE,
			 strlen(dbh->useDelayed 
				? INSERT_SAMPLE_DELAYED 
				: INSERT_SAMPLE)) ||
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
			 strlen(SELECT_TYPE_SAMPLE_COUNT)) ) {
    LOG(LOG_ERROR,
	_("'%s' failed at %s:%d with error: %s\n"),
	"mysql_stmt_prepare",
	__FILE__, __LINE__,
	mysql_stmt_error(dbhI->insert));
    mysql_stmt_close(dbhI->insert);
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
  dbhI->bind[6].buffer_type = MYSQL_TYPE_MEDIUM_BLOB; /* value */
  memset(dbhI->sbind,
	 0,
	 sizeof(dbhI->sbind));
  dbhI->sbind[0].buffer_type = MYSQL_TYPE_TINY_BLOB; /* hash */
  dbhI->sbind[1].buffer_type = MYSQL_TYPE_LONG; /* type */
  
  MUTEX_CREATE(&dbhI->DATABASE_Lock_);
  return OK;
}

/**
 * Close the database connection.
 */
static int iclose(mysqlHandle * dbhI) {
  if (dbhI->dbf == NULL)
    return SYSERR;
  mysql_stmt_free_result(dbhI->insert);
  mysql_stmt_free_result(dbhI->select);
  mysql_stmt_free_result(dbhI->selectc);
  mysql_stmt_free_result(dbhI->selects);
  mysql_stmt_free_result(dbhI->selectsc);
  mysql_stmt_close(dbhI->insert);
  mysql_stmt_close(dbhI->select);
  mysql_stmt_close(dbhI->selectc);
  mysql_stmt_close(dbhI->selects);
  mysql_stmt_close(dbhI->selectsc);
  MUTEX_DESTROY(&dbhI->DATABASE_Lock_);
  mysql_close(dbhI->dbf);
  dbhI->dbf = NULL;
  return OK;
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
  MYSQL_RES *sql_res;
  MYSQL_ROW sql_row;
  Datastore_Datum * datum;
  char * scratch;
  char typestr[32];
  int count = 0;
  mysqlHandle dbhI;

  dbhI.cnffile = dbh->cnffile; /* shared */
  if (OK != iopen(&dbhI))
    return SYSERR;

  MUTEX_LOCK(&dbhI.DATABASE_Lock_);

  if (type==0) {
    typestr[0] = 0;
  } else {
    SNPRINTF(typestr, 
             32,
             "WHERE type=%u", type);
  }
  
  scratch = MALLOC(256);
  SNPRINTF(scratch,
	   256,
	   "SELECT * FROM gn070"
	   " %s"
	   " ORDER BY prio ASC",
	   typestr);
  mysql_query(dbhI.dbf, 
	      scratch);
  FREE(scratch);
  if (mysql_error(dbhI.dbf)[0]) {
    LOG_MYSQL(LOG_ERROR, "mysql_query", &dbhI);
    MUTEX_UNLOCK(&dbhI.DATABASE_Lock_);  
    iclose(&dbhI);
    return(SYSERR);
  }
  
  if (!(sql_res=mysql_use_result(dbhI.dbf))) {
    MUTEX_UNLOCK(&dbhI.DATABASE_Lock_);
    iclose(&dbhI);
    return(SYSERR);
  }

  while ((sql_row=mysql_fetch_row(sql_res))) {   
    datum = assembleDatum(sql_res,
			  sql_row);
    if (datum == NULL) {
      LOG(LOG_WARNING,
	  _("Invalid data in MySQL database.  Please verify integrity!\n"));
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
		
  mysql_free_result(sql_res);
  MUTEX_UNLOCK(&dbhI.DATABASE_Lock_);
  iclose(&dbhI);
  return count;
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
  MYSQL_RES *sql_res;
  MYSQL_ROW sql_row;
  Datastore_Datum * datum;
  char * scratch;
  char typestr[32];
  int count = 0;   
  mysqlHandle dbhI;

  dbhI.cnffile = dbh->cnffile; /* shared */
  if (OK != iopen(&dbhI))
    return SYSERR;

  MUTEX_LOCK(&dbhI.DATABASE_Lock_);
  if (type==0) {
    typestr[0] = 0;
  } else {
    SNPRINTF(typestr, 
             32,
	     "WHERE type=%u", type);
  }
  
  scratch = MALLOC(256);
  SNPRINTF(scratch,
	   256,
	   "SELECT * FROM gn070"
	   " %s"
	   " ORDER BY expire ASC",
	   typestr);
  mysql_query(dbhI.dbf, 
	      scratch);
  FREE(scratch);
  if (mysql_error(dbhI.dbf)[0]) {
    LOG_MYSQL(LOG_ERROR, "mysql_query", &dbhI);
    MUTEX_UNLOCK(&dbhI.DATABASE_Lock_);
    iclose(&dbhI);
    return(SYSERR);
  }
  
  if (!(sql_res=mysql_use_result(dbhI.dbf))) {
    MUTEX_UNLOCK(&dbhI.DATABASE_Lock_);
    iclose(&dbhI);
    return(SYSERR);
  }

  while ((sql_row=mysql_fetch_row(sql_res))) {   
    datum = assembleDatum(sql_res,
			  sql_row);
    if (datum == NULL) {
      LOG(LOG_WARNING,
	  _("Invalid data in MySQL database.  Please verify integrity!\n"));
      continue; 
    }
    if (SYSERR == iter(&datum->key, &datum->value, closure) ) {
      count = SYSERR;
      FREE(datum);
      break;
    }
    FREE(datum);
    count++;
  }		
  mysql_free_result(sql_res);
  MUTEX_UNLOCK(&dbhI.DATABASE_Lock_);
  iclose(&dbhI);
  return count;
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
static int get(const HashCode160 * query,
	       unsigned int type,	     
	       Datum_Iterator iter,
	       void * closure) {
  static unsigned long twenty = sizeof(HashCode160);
  MYSQL_RES * sql_res;
  int count;
  MYSQL_STMT * stmt;
  unsigned int size;
  unsigned int rtype;
  unsigned int prio;
  unsigned int level;
  unsigned long long expiration;
  unsigned long datasize;
  Datastore_Value * datum;
  HashCode160 key;

  if (query == NULL) 
    return iterateLowPriority(type, iter, closure);

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
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
  dbh->sbind[0].buffer = (char*) query;
  dbh->sbind[1].buffer = (char*) &type;
  dbh->sbind[0].length = &twenty;
  
  if (mysql_stmt_bind_param(stmt,
			    dbh->sbind)) {
    LOG(LOG_ERROR,
	_("'%s' failed at %s:%d with error: %s\n"),
	"mysql_stmt_bind_param",
	__FILE__, __LINE__,
	mysql_stmt_error(stmt));    
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  } 
  if (mysql_stmt_execute(dbh->insert)) {
    LOG(LOG_ERROR,
	_("'%s' failed at %s:%d with error: %s\n"),
	"mysql_stmt_execute",
	__FILE__, __LINE__,
	mysql_stmt_error(dbh->insert));    
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }  
  
  datum = MALLOC(sizeof(Datastore_Value) + MAX_DATUM_SIZE);  
  dbh->bind[0].buffer = (char*) &size;
  dbh->bind[1].buffer = (char*) &rtype;
  dbh->bind[2].buffer = (char*) &prio;
  dbh->bind[3].buffer = (char*) &level;
  dbh->bind[4].buffer = (char*) &expiration;
  dbh->bind[5].buffer = (char*) &key;
  dbh->bind[6].buffer = (char*) &datum[1];
  dbh->bind[5].length = &twenty;
  dbh->bind[6].length = &datasize;
  sql_res = mysql_stmt_result_metadata(stmt);
  if (mysql_stmt_bind_result(stmt,
			     dbh->bind)) {
    LOG(LOG_ERROR,
	_("'%s' failed at %s:%d with error: %s\n"),
	"mysql_stmt_bind_result",
	__FILE__, __LINE__,
	mysql_stmt_error(dbh->insert));    
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    FREE(datum);
    return SYSERR;
  }
  datasize = MAX_DATUM_SIZE;
  count = 0;
  while (mysql_stmt_fetch(stmt)) {
    count++;

    if (iter != NULL) {
      datum->size = htonl(size);
      datum->type = htonl(rtype);
      datum->prio = htonl(prio);
      datum->anonymityLevel = htonl(level);
      datum->expirationTime = htonll(expiration);
      if (datasize != size - sizeof(Datastore_Value))
	BREAK();
	LOG(LOG_WARNING,
	    _("Invalid data in MySQL database.  Please verify integrity!\n"));
	continue; 
      }
      LOG(LOG_DEBUG,
	  "Found in database block with type %u.\n",
	  ntohl(*(int*)&datum[1]));
      
      if( SYSERR == iter(&key,
			 datum, 
			 closure) ) {
        count = SYSERR;
	break;
      } 
    datasize = MAX_DATUM_SIZE;
  }
  mysql_free_result(sql_res);
  FREE(datum);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  
  return count;
}

/**
 * Store an item in the datastore.
 *
 * @return OK on success, SYSERR on error
 */
static int put(const HashCode160 * key, 
	       const Datastore_Value * value) {
  static unsigned long twenty = sizeof(HashCode160);
  unsigned int contentSize;
  unsigned long currentSize;
  unsigned int size;
  unsigned int type;
  unsigned int prio;
  unsigned int level;
  unsigned long long expiration;
  EncName enc;

  if ( (ntohl(value->size) <= sizeof(Datastore_Value)) ) {
    BREAK();
    return SYSERR;
  }
  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  
  contentSize = ntohl(value->size)-sizeof(Datastore_Value);

  size = ntohl(value->size);
  type = ntohl(value->type);
  prio = ntohl(value->prio);
  level = ntohl(value->anonymityLevel);
  expiration = ntohll(value->expirationTime);

  IFLOG(LOG_DEBUG,
	hash2enc(key, 
		 &enc));
  LOG(LOG_DEBUG,
      "Storing in database block with type %u and key %s.\n",
      type,
      &enc);
  dbh->bind[0].buffer = (char*) &size;
  dbh->bind[1].buffer = (char*) &type;
  dbh->bind[2].buffer = (char*) &prio;
  dbh->bind[3].buffer = (char*) &level;
  dbh->bind[4].buffer = (char*) &expiration;
  dbh->bind[5].buffer = (char*) key;
  dbh->bind[6].buffer = (char*) &value[1];
  dbh->bind[5].length = &twenty;
  dbh->bind[6].length = &currentSize;
  currentSize = contentSize;

  if (mysql_stmt_bind_param(dbh->insert,
			    dbh->bind)) {
    LOG(LOG_ERROR,
	_("'%s' failed at %s:%d with error: %s\n"),
	"mysql_stmt_bind_param",
	__FILE__, __LINE__,
	mysql_stmt_error(dbh->insert));    
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  } 


  if (mysql_stmt_execute(dbh->insert)) {
    LOG(LOG_ERROR,
	_("'%s' failed at %s:%d with error: %s\n"),
	"mysql_stmt_execute",
	__FILE__, __LINE__,
	mysql_stmt_error(dbh->insert));    
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }  
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
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
  char * escapedHash;
  char * escapedBlock;
  char * scratch;
  size_t n;
  int count;
  int contentSize;

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  contentSize = ntohl(value->size)-sizeof(Datastore_Value);
  escapedHash = MALLOC(2*sizeof(HashCode160)+1);
  mysql_escape_string(escapedHash, 
                      (char *)key, 
		      sizeof(HashCode160));
  escapedBlock = MALLOC(2*contentSize+1);
  mysql_escape_string(escapedBlock, 
                      (char *)&value[1],
		      contentSize);

  n = sizeof(HashCode160)*2+contentSize*2+200+1;
  scratch=MALLOC(n);
  if(value == NULL) {
    SNPRINTF(scratch, 
  	     n,
	     "DELETE FROM gn070 WHERE hash='%s'",	
	     escapedHash);
  } else {
    SNPRINTF(scratch, 
  	     n,
	     "DELETE FROM gn070 WHERE hash='%s'"
	     " AND size=%u AND type=%u AND prio=%u"
	     " AND anonLevel=%u AND expire=%lld"
	     " AND value='%s'",
	     escapedHash,
	     ntohl(value->size),
	     ntohl(value->type),
	     ntohl(value->prio),
	     ntohl(value->anonymityLevel), 
	     ntohll(value->expirationTime),
	     escapedBlock);
  }
  mysql_query(dbh->dbf, scratch);
  FREE(escapedHash);
  FREE(escapedBlock);
  FREE(scratch);
  if(mysql_error(dbh->dbf)[0]) {
    LOG_MYSQL(LOG_ERROR, 
	      "mysql_query", 
	      dbh);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }
  count = mysql_affected_rows(dbh->dbf);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  return count;
}

/**
 * Update the priority for a particular key
 * in the datastore.
 *
 */
static int update(const HashCode160 * key,
		  const Datastore_Value * value,
		  int delta) {
  char * escapedHash;
  char * escapedBlock;
  char * scratch;
  int n;
  int contentSize;
  
  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  contentSize = ntohl(value->size)-sizeof(Datastore_Value);

  escapedHash = MALLOC(2*sizeof(HashCode160)+1);
  mysql_escape_string(escapedHash, 
  	              (char *)key, 
 	     	      sizeof(HashCode160));
  escapedBlock = MALLOC(2*contentSize+1);
  mysql_escape_string(escapedBlock, 
		      (char *)&value[1],
		      contentSize);
  n = contentSize*2+sizeof(HashCode160)*2+100+1;
  scratch = MALLOC(n);
 
  /* NOTE: as the table entry for 'prio' is defined as unsigned,
   * mysql will zero the value if its about to go negative. (This 
   * will generate a warning though, but its probably not seen
   * at all in this context.)
   */
  SNPRINTF(scratch,
	   n,
	   "UPDATE gn070"
	   " SET prio=prio+%d"
	   " WHERE hash='%s'"
	   " AND value='%s'", 
	   delta,
	   escapedHash,
	   escapedBlock);
  mysql_query(dbh->dbf, 
	      scratch);
  FREE(scratch);
  FREE(escapedHash);
  FREE(escapedBlock);
  if (mysql_error(dbh->dbf)[0]) {
    LOG_MYSQL(LOG_ERROR, "mysql_query", dbh);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return(SYSERR);
  }
  
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  return OK;
}


/**
 * Get the current on-disk size of the SQ store.
 * Estimates are fine, if that's the only thing
 * available.
 * @return number of bytes used on disk
 */
static unsigned long long getSize() {
  char * scratch;
  MYSQL_RES * sql_res;
  MYSQL_ROW sql_row;
  long long avgRowLen = -1;
  long long rowsInTable = 0;
  unsigned long long bytesUsed;

  MUTEX_LOCK(&dbh->DATABASE_Lock_);

  /* find out average row length in bytes */
  /* FIXME: probably unnecessary to check avg row length every time */
  scratch = MALLOC(512);
  SNPRINTF(scratch, 
	   512,
	   "SHOW TABLE STATUS FROM gnunet LIKE 'gn070'");
  mysql_query(dbh->dbf,
  	      scratch);
  if (mysql_error(dbh->dbf)[0]) {
    DIE_MYSQL("mysql_query", dbh); /* this MUST not fail... */
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    FREE(scratch);
    return SYSERR;	/* shouldn't get here */
  }
  if ((sql_res=mysql_store_result(dbh->dbf))) {
    int rows = mysql_num_fields(sql_res);
    sql_row = mysql_fetch_row(sql_res);
    if (sql_row == NULL) {
      LOG(LOG_ERROR, 
	  _("Query '%s' had no results.\n"), 
	  scratch);
      FREE(scratch);
      GNUNET_ASSERT(0); /* not allowed to fail*/
      MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
      return SYSERR;	/* shouldn't get here */
    }
    GNUNET_ASSERT( (dbh->avgLength_ID < rows) &&
 	           (dbh->avgLength_ID >= 0) ); 
    if (sql_row[dbh->avgLength_ID] != NULL) 
      avgRowLen = atoll(sql_row[dbh->avgLength_ID]);
    else
      avgRowLen = -1;
    
    mysql_free_result(sql_res);
  }
  GNUNET_ASSERT(avgRowLen >= 0);
  /* find number of entries (rows) */
  SNPRINTF(scratch, 
	   512,
	   "SELECT count(*) FROM gn070");
  mysql_query(dbh->dbf,
  	      scratch);
  FREE(scratch);
  if (!(sql_res=mysql_store_result(dbh->dbf))) {
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    DIE_MYSQL("mysql_store_result", dbh);
  }

  if ((sql_row=mysql_fetch_row(sql_res))) {
    int cols = mysql_num_fields(sql_res);
    GNUNET_ASSERT(cols > 0);
    if (sql_row[0] != NULL)
      rowsInTable = atoll(sql_row[0]);
    else
      rowsInTable = 0;
  }
  mysql_free_result(sql_res);
     
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);

  bytesUsed = rowsInTable * avgRowLen;

#if DEBUG_MYSQL
  LOG(LOG_DEBUG, 
      "estimateContentAvailable (q=%d)\n",
      kbUsed);
#endif

  return(bytesUsed);
}

/**
 * Delete the database.  The next operation is
 * guaranteed to be unloading of the module.
 */
static void drop() {
  char * scratch;
  
  scratch = MALLOC(128);
  SNPRINTF(scratch,
	   128,
	   "DROP TABLE gn070"); 
  mysql_query(dbh->dbf,
  	      scratch);
  FREE(scratch);
}




SQstore_ServiceAPI *
provide_module_sqstore_mysql(CoreAPIForApplication * capi) {
  static SQstore_ServiceAPI api;

  MYSQL_RES * sql_res;
  char * scratch;
  char * cnffile;
  FILE * fp;
  struct passwd * pw;
  size_t nX;

  /* verify that .my.cnf can be found */
  pw = getpwuid(getuid());
  if(!pw) 
    DIE_STRERROR("getpwuid");
  nX = strlen(pw->pw_dir)+1024;
  cnffile = MALLOC(nX);
  SNPRINTF(cnffile, nX, "%s/.my.cnf", pw->pw_dir);
  LOG(LOG_DEBUG, 
      _("Trying to use file '%s' for MySQL configuration.\n"),
      cnffile);
  fp = FOPEN(cnffile, "r");
  if (!fp) {
    LOG_FILE_STRERROR(LOG_ERROR, "fopen", cnffile);
    FREE(cnffile);
    return NULL;
  } else {
    fclose(fp);
  }

  dbh = MALLOC(sizeof(mysqlHandle));
  dbh->cnffile = cnffile;
  if (testConfigurationString("MYSQL",
			      "DELAYED",
			      "YES"))
    dbh->useDelayed = YES;
  else
    dbh->useDelayed = NO;

  if (OK != iopen(dbh)) {
    FREE(cnffile);
    FREE(dbh);
    dbh = NULL;
    return NULL;
  }

  scratch = MALLOC(1024);

  /* Find out which column contains the avg row length field and assume
   * that mysqld always gives it in the same order across calls :) */
  SNPRINTF(scratch, 
	   1024,
	   "SHOW TABLE STATUS FROM gnunet LIKE 'gn070'");
  mysql_query(dbh->dbf,
  	      scratch);
  FREE(scratch);
  if (mysql_error(dbh->dbf)[0]) {
    LOG_MYSQL(LOG_ERROR, 
	      "mysql_query",
	      dbh);
    iclose(dbh);
    FREE(dbh);
    FREE(cnffile);
    return NULL;
  }
  if((sql_res=mysql_store_result(dbh->dbf))) {
    MYSQL_FIELD * sql_fields;
    int num_fields;
    int j;
    int found = NO;

    num_fields=mysql_num_fields(sql_res);
    if(num_fields<=0) {
      LOG(LOG_ERROR, "ERROR: num_fields<=0\n");
      iclose(dbh);
      FREE(dbh);
      FREE(cnffile);
      return NULL;
    }
    sql_fields=mysql_fetch_fields(sql_res); 
    if(sql_fields==NULL) {
      LOG(LOG_ERROR, "ERROR: sql_fields==0\n");
      iclose(dbh);
      FREE(dbh);
      FREE(cnffile);
      return NULL;
    }
    dbh->avgLength_ID = -1;
    for(j=0;j<num_fields;j++) {
      if(strcmp(sql_fields[j].name,"Avg_row_length")==0) {
        found = YES;
        dbh->avgLength_ID=j;
	break;
      }
    }
    GNUNET_ASSERT(dbh->avgLength_ID != -1);
    mysql_free_result(sql_res);
    if (found == NO) {
      BREAK();
      /* avg_row_length not found in SHOW TABLE STATUS */
      iclose(dbh);
      FREE(dbh);
      FREE(cnffile);
      return NULL;
    }
    /* FIXME: mysql manual doesn't mention if sql_fields should be freed?*/
  } else {
    LOG(LOG_ERROR, "ERROR: couldn't store res row for SHOW TABLE STATUS\n");
    BREAK();
    iclose(dbh);
    FREE(dbh);
    FREE(cnffile);
    return NULL;
  }

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
void release_module_sqstore_mysql() {
  iclose(dbh);
  FREE(dbh->cnffile);
  FREE(dbh);
  dbh = NULL;
}

/* end of mysql.c */
