/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @author Igor Wronsky
 * @file applications/afs/module/high_mysql.c
 *
 * Database: MySQL
 *
 * NOTE: This db module does NOT work with mysql v3.23.49 due to a bug
 * in mysql.  All later versions should be fine, including the 4.0.x
 * series. Current devel version is 4.0.16-log on debian/unstable.
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
 *    DATABASETYPE = "mysql"
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
 *   mysql> REPAIR TABLE data1024of
 *   for each table in the gnunet database (USE gnunet; SHOW TABLES;) 
 *
 * EFFICIENCY ISSUES
 *
 * If you suffer from too slow index/insert speeds, 
 * you might try to define /etc/gnunet.conf option
 *
 *   [AFS]
 *   MYSQL_DELAYED = YES
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

#include "high_backend.h"
#include "platform.h"
#include <mysql/mysql.h>

#define DEBUG_MYSQL NO
#define DEBUG_TIME_MYSQL NO

/** 
 * Popularity of _known_ 3hash keywords can be tracked by creating 
 * the following table and enabling TRACK_3HASH_QUERIES. In addition,
 * you'll have to fill the table with <name,hash> pairs yourself
 * (not provided). Tracking is not generally recommended as
 * it may harm your deniability.
 *
   USE gnunet;
   CREATE TABLE `dictionary` (
     `name` tinyblob NOT NULL,
     `hash` varchar(40) binary NOT NULL default '',
     `hits` smallint(5) unsigned NOT NULL default '0',
     PRIMARY KEY  (`hash`),
     UNIQUE KEY `unique_name` (`name`(32))
   ) TYPE=MyISAM
 *
 */
#define TRACK_3HASH_QUERIES NO



/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define DIE_MYSQL(cmd, dbh) do { errexit(_("'%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, mysql_error(dbh->dbf)); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_MYSQL(level, cmd, dbh) do { LOG(level, _("'%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, mysql_error(dbh->dbf)); } while(0);




/**
 * @brief mysql wrapper
 */
typedef struct {
  MYSQL * dbf; 
  unsigned int i;	   /* database index */
  unsigned int n;          /* total number of databases */
  Mutex DATABASE_Lock_;
  int avgLength_ID;	   /* which column contains the Avg_row_length  
                            * in SHOW TABLE STATUS resultset */
  int useDelayed;          /* use potentially unsafe delayed inserts? */
} mysqlHandle;

/**
 * @param i index of the database
 * @param n total number of databases
 */
HighDBHandle initContentDatabase(unsigned int i,
				 unsigned int n) {
  MYSQL_RES * sql_res;
  mysqlHandle * dbh;
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
    return NULL;
  } else {
    fclose(fp);
  }

  dbh = MALLOC(sizeof(mysqlHandle));
  dbh->dbf = mysql_init(NULL);
  dbh->i = i;
  dbh->n = n;
  if(dbh->dbf == NULL) {
    LOG(LOG_ERROR, 
	_("Unable to initialize MySQL.\n"));
    FREE(dbh);
    return NULL;
  }
  if(testConfigurationString("AFS",
  			     "MYSQL_DELAYED",
			     "YES"))
    dbh->useDelayed = YES;
  else
    dbh->useDelayed = NO;

  mysql_options(dbh->dbf,
  		MYSQL_READ_DEFAULT_FILE,
		cnffile);
  mysql_options(dbh->dbf, 
		MYSQL_READ_DEFAULT_GROUP, 
		"client");
  mysql_real_connect(dbh->dbf,
		     NULL,
		     NULL,
		     NULL,
		     "gnunet",
		     0,
		     NULL,
		     0);
  if (mysql_error(dbh->dbf)[0]) {
    LOG_MYSQL(LOG_ERROR, 
	      "mysql_real_connect",
	      dbh);
    FREE(dbh);
    return NULL;
  }    

  scratch = MALLOC(1024);
  SNPRINTF(scratch,
	   1024,
	   "CREATE TABLE IF NOT EXISTS data%uof%u ("
	   "  hash tinyblob NOT NULL default'',"
	   "  priority int(11) NOT NULL default 0,"
	   "  type tinyint NOT NULL default 0,"
	   "  fileIndex smallint NOT NULL default 0,"
	   "  fileOffset int(11) NOT NULL default 0,"
	   "  doubleHash tinyblob NOT NULL default '',"
	   "  content mediumblob NOT NULL default '',"
	   "  PRIMARY KEY (hash(20)),"
	   "  KEY priority (priority)"
	   ") TYPE=MyISAM",
	   dbh->n,
	   dbh->i);
  mysql_query(dbh->dbf,
  	      scratch);
  if (mysql_error(dbh->dbf)[0]) {
    LOG_MYSQL(LOG_ERROR, 
	      "mysql_query",
	      dbh);
    FREE(dbh);
    FREE(scratch);
    return NULL;
  }
  MUTEX_CREATE_RECURSIVE(&dbh->DATABASE_Lock_);	

  /* Find out which column contains the avg row length field and assume
   * that mysqld always gives it in the same order across calls :) */
  SNPRINTF(scratch, 
	   1024,
	   "SHOW TABLE STATUS FROM gnunet LIKE 'data%uof%u'",
	   dbh->n,
	   dbh->i);
  mysql_query(dbh->dbf,
  	      scratch);
  FREE(scratch);
  if (mysql_error(dbh->dbf)[0]) {
    LOG_MYSQL(LOG_ERROR, 
	      "mysql_query",
	      dbh);
    FREE(dbh);
    return NULL;
  }
  if((sql_res=mysql_store_result(dbh->dbf))) {
    MYSQL_FIELD * sql_fields;
    int num_fields;
    int j;
    int found = NO;

    num_fields=mysql_num_fields(sql_res);
    sql_fields=mysql_fetch_fields(sql_res); 
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
      FREE(dbh);
      return NULL;
    }
    /* FIXME: mysql manual doesn't mention if sql_fields should be freed?*/
  }
  return dbh;
}

/**
 * Normal shutdown of the storage module
 *
 * @param handle the database
 */
void doneContentDatabase(HighDBHandle handle) {
  mysqlHandle * dbh = handle;
 
  MUTEX_DESTROY(&dbh->DATABASE_Lock_);
  mysql_close(dbh->dbf);
  FREE(dbh);
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
int forEachEntryInDatabase(HighDBHandle handle,
 		           EntryCallback callback,
	    	           void * data) {
  mysqlHandle * dbh = handle;
  MYSQL_RES *sql_res;
  MYSQL_ROW sql_row;
  ContentIndex ce;
  void * result;
  char * scratch;
  int count = 0;
  int len;

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  scratch = MALLOC(256);
  SNPRINTF(scratch,
	   256,
	   "SELECT content,type,priority,doubleHash,fileOffset,fileIndex,hash "
	   "FROM data%uof%u",
	   dbh->n,
	   dbh->i);
  mysql_query(dbh->dbf, 
	      scratch);
  FREE(scratch);
  if (mysql_error(dbh->dbf)[0]) {
    LOG_MYSQL(LOG_ERROR, "mysql_query", dbh);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return(SYSERR);
  }
  
  if (!(sql_res=mysql_use_result(dbh->dbf))) {
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return(SYSERR);
  }

  while ((sql_row=mysql_fetch_row(sql_res))) {   
    len = mysql_fetch_lengths(sql_res)[0];
    if (len > 0) {
      result = MALLOC(len);
      memcpy(result,
	     sql_row[0],
	     len);
    } else
      result = NULL;
    
    ce.type = htons(atol(sql_row[1]));
    ce.importance = htonl(atol(sql_row[2]));
    if (ntohs(ce.type)==LOOKUP_TYPE_3HASH) {
      if (mysql_fetch_lengths(sql_res)[3] == sizeof(HashCode160))
	memcpy(&ce.hash, 
	       sql_row[3],
	       sizeof(HashCode160));
    } else {
      memcpy(&ce.hash, 
	     sql_row[6],
	     sizeof(HashCode160));
    }
    ce.fileOffset = htonl(atol(sql_row[4]));
    ce.fileNameIndex = htons(atol(sql_row[5]));       
    callback((HashCode160*)sql_row[6],
	     &ce,
	     result, /* freed by callback */
	     len,
	     data);
    count++;
  }
		
  mysql_free_result(sql_res);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  return count;
}

/**
 * Get the number of entries in the database.
 *
 * @param handle the database
 * @return the number of entries
 */
int countContentEntries(HighDBHandle handle) {
  mysqlHandle * dbh = handle;
  MYSQL_RES * sql_res;
  MYSQL_ROW sql_row;
  char * scratch;
  int count=0;

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  scratch = MALLOC(128);
  SNPRINTF(scratch, 
	   128,
	   "SELECT count(*) FROM data%uof%u",
	   dbh->n,
	   dbh->i);
  mysql_query(dbh->dbf,
  	      scratch);
  FREE(scratch);
  if (!(sql_res=mysql_store_result(dbh->dbf))) {
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return(SYSERR);
  }

  if ((sql_row=mysql_fetch_row(sql_res))) {
    count = atol(sql_row[0]);
  }
  mysql_free_result(sql_res);
     
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  return count;
}

/**
 * Read the contents of a bucket to a buffer.
 *
 * @param handle the database
 * @param query the hashcode representing the entry
 * @param ce the meta-data of the entry (set)
 * @param result the buffer to write the result to 
 *        (*result should be NULL, sufficient space is allocated)
 * @param prio by how much should the priority of the content be changed
 *           (if it is found)
 * @return the number of bytes read on success, -1 on failure
 */ 
int readContent(HighDBHandle handle,
		const HashCode160 * query,
	        ContentIndex * ce,
	        void ** result,
		int prio) {
  mysqlHandle * dbh = handle;
  MYSQL_RES * sql_res;
  MYSQL_ROW sql_row;
  char * escapedHash;
  char * scratch;
  int len;

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  escapedHash = MALLOC(sizeof(HashCode160)*2+1);
  mysql_escape_string(escapedHash, 
		      (char *)query, 
		      sizeof(HashCode160));
  scratch = MALLOC(256);
  SNPRINTF(scratch, 
	   256,
	   "SELECT content,type,priority,doubleHash,fileOffset,fileIndex "
	   "FROM data%uof%u WHERE hash='%s'",
	   dbh->n,
	   dbh->i,
	   escapedHash);
  mysql_query(dbh->dbf, 
	      scratch);
  if (mysql_error(dbh->dbf)[0]) {
    LOG_MYSQL(LOG_ERROR, "mysql_query", dbh);
    FREE(escapedHash);
    FREE(scratch);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }

  if (!(sql_res=mysql_store_result(dbh->dbf))) {
    LOG_MYSQL(LOG_ERROR, "mysql_store_result", dbh);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    FREE(escapedHash);
    FREE(scratch);
    return SYSERR;
  }

  if (!(sql_row=mysql_fetch_row(sql_res))) {
    /* not error, just data not found */
    mysql_free_result(sql_res);
    FREE(escapedHash);
    FREE(scratch);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }
    
  len = mysql_fetch_lengths(sql_res)[0];
  if (len > 0) {
    *result = MALLOC(len);
    memcpy(*result,
	   sql_row[0],
	   len);
  } else
    *result = NULL;

  ce->type = htons(atol(sql_row[1]));
  ce->importance = htonl(atol(sql_row[2]));
  if (ntohs(ce->type)==LOOKUP_TYPE_3HASH) {
    if (mysql_fetch_lengths(sql_res)[3] == sizeof(HashCode160))
      memcpy(&ce->hash, 
  	     sql_row[3],
	     sizeof(HashCode160));
  } else {
    memcpy(&ce->hash, 
    	   query,
	   sizeof(HashCode160));
  }
  ce->fileOffset = htonl(atol(sql_row[4]));
  ce->fileNameIndex = htons(atol(sql_row[5]));

  mysql_free_result(sql_res);

#if TRACK_3HASH_QUERIES
  if (ntohs(ce->type)==LOOKUP_TYPE_3HASH) {
    HexName hex;

    hash2hex(query,
	     &hex);
    SNPRINTF(scratch,
	     256,
	     "UPDATE dictionary SET hits=hits+1 WHERE hash='%s'",
	     (char*)&hex);
    mysql_query(dbh->dbf,scratch);
  }
#endif

  if (prio != 0) {
    SNPRINTF(scratch, 
	     256,
	     "UPDATE data%uof%u SET priority=priority+%d WHERE hash='%s'",
	     dbh->n,
	     dbh->i,
	     prio,
	     escapedHash);
    mysql_query(dbh->dbf,scratch); 
  }

  FREE(escapedHash);
  FREE(scratch);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  return len;
}

/**
 * Write content to the db.  Overwrites existing data.
 * If ce->type is LOOKUP_TYPE_3HASH, ce->hash will contain
 * a double hash which must be converted to 3HASH, later to be 
 * retrievable by 3HASH, but the 2HASH must be stored so it can
 * be retrieved by readContent(). For indexed content,
 * ce->fileOffset and ce->fileNameIndex must be stored.
 * Note that block can be NULL for on-demand encoded content
 * (in this case, len must also be 0).
 *
 * @param handle the database
 * @param ce the meta-data for the entry
 * @param len the size of the block
 * @param block the data to store
 * @return SYSERR on error, OK if ok.
 */
int writeContent(HighDBHandle handle,
		 const ContentIndex * ce,
		 unsigned int len,
		 const void * block) {
  mysqlHandle * dbh = handle;
  HashCode160 tripleHash;
  char * doubleHash;
  char * escapedBlock;
  char * escapedHash;
  char * scratch;
  int n;

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  
  escapedHash = MALLOC(2*sizeof(HashCode160)+1);
  
  if(ntohs(ce->type) == LOOKUP_TYPE_3HASH) {
    hash(&ce->hash, 
    	 sizeof(HashCode160),
	 &tripleHash);
    mysql_escape_string(escapedHash, 
			(char *)&tripleHash, 
			sizeof(HashCode160));
    doubleHash = MALLOC(2*sizeof(HashCode160)+1);
    mysql_escape_string(doubleHash, 
			(char *)&ce->hash, 
			sizeof(HashCode160));
  } else {
    doubleHash = NULL;
    mysql_escape_string(escapedHash, 
			(char *)&ce->hash, 
			sizeof(HashCode160));
  }
  
  escapedBlock = MALLOC(2*len+1);
  mysql_escape_string(escapedBlock, 
		      (char *)block, 
		      len);
  n = len*2+sizeof(HexName)*2+sizeof(HashCode160)*2+100+1;
  scratch = MALLOC(n);
  SNPRINTF(scratch, 
	   n,
	   "REPLACE %s INTO data%uof%u "
	   "(content,hash,priority,fileOffset,fileIndex,doubleHash,type)"
	   " VALUES ('%s','%s','%u','%u','%u','%s',%u)",
	   (dbh->useDelayed == YES ? "DELAYED" : ""),
	   dbh->n,
	   dbh->i,
	   (len > 0 ? escapedBlock : ""),
	   escapedHash,
	   ntohl(ce->importance),
	   ntohl(ce->fileOffset),
	   ntohs(ce->fileNameIndex),
	   (doubleHash ? doubleHash : ""),
	   ntohs(ce->type));
  mysql_query(dbh->dbf, scratch);
  FREE(scratch);
  FREE(escapedBlock);
  FREE(escapedHash);
  FREENONNULL(doubleHash);
  if(mysql_error(dbh->dbf)[0]) {
    LOG_MYSQL(LOG_ERROR, "mysql_query", dbh);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }
    
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  return OK;
}

/**
 * Free space in the database by removing one block
 *
 * @param handle the database
 * @param name hashcode for the block to be deleted
 */
int unlinkFromDB(HighDBHandle handle,
		 const HashCode160 * name) {
  mysqlHandle * dbh = handle;
  char * escapedHash;
  char * scratch;
  size_t n;

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  escapedHash = MALLOC(2*sizeof(HashCode160)+1);
  mysql_escape_string(escapedHash, (char *)name, sizeof(HashCode160));
  n = sizeof(HashCode160)*2+100+1;
  scratch=MALLOC(n);
  SNPRINTF(scratch, 
	   n,
	   "DELETE FROM data%uof%u WHERE hash='%s'",	
	   dbh->n,
	   dbh->i,
	   escapedHash);
  mysql_query(dbh->dbf,scratch);
  FREE(escapedHash);
  FREE(scratch);
  if(mysql_error(dbh->dbf)[0]) {
    LOG_MYSQL(LOG_ERROR, "mysql_query", dbh);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  return OK;
}

/**
 * Get a random content block from MySQL database. 
 * Tries to use indexes efficiently.
 *
 * Code supplied by H. Pagenhardt
 *
 * @param handle the database
 * @param ce the meta-data of the random content (set)
 * @return OK on success, SYSERR on error
 */
int getRandomContent(HighDBHandle handle,
                     ContentIndex * ce,
		     CONTENT_Block ** data) {
  mysqlHandle * dbh = handle;
  MYSQL_RES * sql_res;
  MYSQL_ROW sql_row;
  char * escapedHash;
  char * hash;
  char * scratch;
  int i;
  int found;
  size_t n;
#if DEBUG_TIME_MYSQL
  cron_t startTime;
  cron_t endTime;
  static cron_t spentTime=0;
  static int calls = 0;

  calls++;
  cronTime(&startTime);
#endif

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  hash = MALLOC(sizeof(HashCode160));
  escapedHash = MALLOC(2*sizeof(HashCode160)+1);
  n = 2*sizeof(HashCode160)+256+1;
  scratch = MALLOC(n);

  found = NO;
  for (i=0;i<sizeof(HashCode160);i++)
    hash[i] = randomi(256);
  mysql_escape_string(escapedHash, hash, sizeof(HashCode160));
  SNPRINTF(scratch,
	  n,
          "SELECT hash,type,priority,fileOffset,fileIndex,content "
          "FROM data%uof%u "
          "WHERE hash >= '%s' "
          "AND (type = %d OR type = %d) "
          "LIMIT 1",
          dbh->n,
          dbh->i,
          escapedHash,
          LOOKUP_TYPE_CHK,
          LOOKUP_TYPE_CHKS);
  mysql_query(dbh->dbf, scratch);
  if(mysql_error(dbh->dbf)[0]) {
    LOG_MYSQL(LOG_ERROR, "mysql_query", dbh);
    FREE(scratch);
    FREE(escapedHash);
    FREE(hash);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }
  if(!(sql_res=mysql_store_result(dbh->dbf))) {
    LOG_MYSQL(LOG_ERROR, "mysql_store_result", dbh);
    FREE(scratch);
    FREE(escapedHash);
    FREE(hash);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }
  if (mysql_num_rows(sql_res)==0) {
    mysql_free_result(sql_res);
    SNPRINTF(scratch,
	     n,
	     "SELECT hash,type,priority,fileOffset,fileIndex,content "
	     "FROM data%uof%u "
	     "WHERE hash >= '' "
	     "AND (type = %d OR type = %d) "
	     "LIMIT 1",
	     dbh->n,
	     dbh->i,
	     LOOKUP_TYPE_CHK,
	     LOOKUP_TYPE_CHKS);
    mysql_query(dbh->dbf, scratch);
    if(mysql_error(dbh->dbf)[0]) {
      LOG_MYSQL(LOG_ERROR, "mysql_query", dbh);
      FREE(scratch);
      FREE(escapedHash);
      FREE(hash);
      MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
      return SYSERR;
    }
    if(!(sql_res=mysql_store_result(dbh->dbf))) {
      LOG_MYSQL(LOG_ERROR, "mysql_store_result", dbh);
      FREE(scratch);
      FREE(escapedHash);
      FREE(hash);
      MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
      return SYSERR;
    }
  }
  if(mysql_num_rows(sql_res)>0) {
    if(!(sql_row=mysql_fetch_row(sql_res))) {
      LOG_MYSQL(LOG_ERROR, "mysql_num_rows", dbh);
      FREE(scratch);
      FREE(escapedHash);
      FREE(hash);
      mysql_free_result(sql_res);
      MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
      return SYSERR;
    }
    memcpy(&ce->hash,
           sql_row[0],
           sizeof(HashCode160));
    ce->type = htons(atol(sql_row[1]));
    ce->importance = htonl(atol(sql_row[2]));
    ce->fileOffset = htonl(atol(sql_row[3]));
    ce->fileNameIndex = htons(atol(sql_row[4]));
    if(ntohs(ce->fileNameIndex)==0) {
      *data = MALLOC(sizeof(CONTENT_Block));
      memcpy(*data,
	     sql_row[5],
	     sizeof(CONTENT_Block));
    }
    found = YES;
    mysql_free_result(sql_res);
  }

  FREE(scratch);
  FREE(escapedHash);
  FREE(hash);

  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  
#if DEBUG_TIME_MYSQL
  cronTime(&endTime);
  spentTime = spentTime + (endTime-startTime);
  LOG(LOG_DEBUG, 
      "Spent total %lldms / %d calls\n", spentTime, calls);
#endif 
  
  if(found==YES) {
    return OK;
  } else {
    LOG(LOG_DEBUG,
        "'%s' did not find anything!\n",
	__FUNCTION__);
    return SYSERR;
  }
}

/**
 * Get the lowest priority value of all content in the store.
 *
 * @param handle the database
 * @return the lowest priority
 */
unsigned int getMinimumPriority(HighDBHandle handle) {
  mysqlHandle * dbh = handle;
  MYSQL_RES * sql_res;
  MYSQL_ROW sql_row;
  char * scratch;
  unsigned int minPrio = 0;
  
  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  scratch = MALLOC(256);
 
  SNPRINTF(scratch, 
	   256,
	   "SELECT MIN(priority) FROM data%uof%u",
	   dbh->n,
	   dbh->i);
  mysql_query(dbh->dbf, scratch);
  FREE(scratch);
  if (!(sql_res=mysql_store_result(dbh->dbf))) {
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return 0;
  }
  if (mysql_num_rows(sql_res)==0) {
    mysql_free_result(sql_res);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return 0; /* no entries in DB */
  }
  if (NULL != (sql_row=mysql_fetch_row(sql_res))) {
    if (sql_row[0] != NULL)
      minPrio = atol(sql_row[0]);  
    else
      minPrio = 0; /* error? */
  }
  mysql_free_result(sql_res);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);

  return minPrio;
}

/**
 * Deletes some least important content
 * 
 * @param handle the database
 * @param count the number of entries to delete
 * @param callback method to call on each deleted entry
 * @param closure extra argument to callback
 * @return OK on success, SYSERR on error
 */
int deleteContent(HighDBHandle handle,
		  unsigned int count,
		  EntryCallback callback,
		  void * closure) {
  mysqlHandle * dbh = handle;
  MYSQL_RES * sql_res;
  MYSQL_ROW sql_row;
  HashCode160 * deleteThese;
  char * escapedHash;
  char * scratch;
  int i=0;
 
  MUTEX_LOCK(&dbh->DATABASE_Lock_);

  scratch = MALLOC(256);
 
  /* Collect hashes to delete */
  SNPRINTF(scratch, 
	   256,
	   "SELECT hash FROM data%uof%u "
	   "ORDER BY priority ASC LIMIT %d",
	   dbh->n,
	   dbh->i,
	   count);
  mysql_query(dbh->dbf, scratch);
  if (mysql_error(dbh->dbf)[0]) {
    LOG_MYSQL(LOG_ERROR, "mysql_query", dbh);
    FREE(scratch);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }
  if (!(sql_res=mysql_use_result(dbh->dbf))) {
    FREE(scratch);
    LOG_MYSQL(LOG_ERROR, "mysql_use_result", dbh);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }

  deleteThese = MALLOC(count*sizeof(HashCode160));
  i=0;
  while ((sql_row=mysql_fetch_row(sql_res))) {
    memcpy(&deleteThese[i++],
           sql_row[0],
	   sizeof(HashCode160));
  }
  mysql_free_result(sql_res);
 
  /* Delete collected hashes */
  count=i;
  escapedHash = MALLOC(2*sizeof(HashCode160)+1);
  for(i=0;i<count;i++) {    
    ContentIndex ce;
    void * data;
    int dlen;
    
    data = NULL;
    dlen = readContent(handle,
		       &deleteThese[i],
		       &ce,
		       &data,
		       0);
    if (dlen >= 0) {
      if (callback != NULL) {
	callback(&deleteThese[i],
		 &ce,
		 data,
		 dlen,
		 closure);
      } else {
	FREENONNULL(data);
      }
    }

    mysql_escape_string(escapedHash, 	
                        (char *)&deleteThese[i],
			sizeof(HashCode160));
    SNPRINTF(scratch, 
	     256,
	     "DELETE FROM data%uof%u WHERE hash='%s'",
	     dbh->n,
	     dbh->i,
	     escapedHash);
    mysql_query(dbh->dbf,scratch);
    if(mysql_error(dbh->dbf)[0])
      LOG_MYSQL(LOG_ERROR, "mysql_query", dbh);
  }
    
  FREE(escapedHash);  
  FREE(scratch);
  FREE(deleteThese);
  
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  
  return OK;
}


/**
 * Estimate how many blocks can be stored in the DB
 * before the quota is reached.
 *
 * NOTE: this function can not be performed relying on
 * Data_length+Index_length from "SHOW TABLE STATUS" because
 * those values seem not to be decreasing in real time.
 * On mysql 4.0.16, Avg_row_len seems to be updating in real
 * time w.r.t. insertions and deletions.
 *
 * @param handle the database
 * @param quota the number of kb available for the DB
 * @return number of blocks left
 */ 
int estimateAvailableBlocks(HighDBHandle handle,
			    unsigned int quota) {
  mysqlHandle * dbh = handle;
  char * scratch;
  MYSQL_RES * sql_res;
  MYSQL_ROW sql_row;
  long long avgRowLen = -1;
  long long rowsInTable = 0;
  unsigned int kbUsed;

  MUTEX_LOCK(&dbh->DATABASE_Lock_);

  /* find out average row length in bytes */
  /* FIXME: probably unnecessary to check avg row length every time */
  scratch = MALLOC(512);
  SNPRINTF(scratch, 
	   512,
	   "SHOW TABLE STATUS FROM gnunet LIKE 'data%uof%u'",
	   dbh->n,
	   dbh->i);
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
	   "SELECT count(*) FROM data%uof%u",
	   dbh->n,
	   dbh->i);
  mysql_query(dbh->dbf,
  	      scratch);
  FREE(scratch);
  if (!(sql_res=mysql_store_result(dbh->dbf))) 
    DIE_MYSQL("mysql_store_result", dbh);

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

  kbUsed = (unsigned int)((rowsInTable * avgRowLen) / 1024);

#if DEBUG_MYSQL
  LOG(LOG_DEBUG, 
      "estimateContentAvailable (q=%d,u=%ud,rem=%d)\n",
      quota,
      kbUsed,
      quota-kbUsed);
#endif

  return quota - kbUsed;
}

/**
 * Close and delete the database.
 *
 * @param handle the database
 */
void deleteDatabase(HighDBHandle handle) {
  mysqlHandle * dbh = handle;
  char * scratch;
  
  MUTEX_DESTROY(&dbh->DATABASE_Lock_);
  scratch = MALLOC(128);
  SNPRINTF(scratch,
	   128,
	   "DROP TABLE data%uof%u", 
	   dbh->n,
	   dbh->i);
  mysql_query(dbh->dbf,
  	      scratch);
  FREE(scratch);
  mysql_close(dbh->dbf);
  FREE(dbh);
}

/* end of high_mysql.c */
