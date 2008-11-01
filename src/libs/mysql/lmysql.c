/*
     This file is part of GNUnet.
     (C) 2008 Christian Grothoff (and other contributing authors)

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
 * @file libs/mysql/lmysql.c
 * @author Christian Grothoff
 *
 * NOTE: This library does NOT work with mysql prior to 4.1 since
 * it uses prepared statements.
 *
 * SETUP INSTRUCTIONS:
 *
 * 1) Access mysql as root,
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
 * 2) In the $HOME directory of $USER, create a ".my.cnf" file
 *    with the following lines
 *    <pre>

      [client]
      user=$USER
      password=$the_password_you_like

 *    </pre>
 *
 * Thats it -- now you can configure your datastores in GNUnet to
 * use MySQL. Note that .my.cnf file is a security risk unless its on
 * a safe partition etc. The $HOME/.my.cnf can of course be a symbolic
 * link. Even greater security risk can be achieved by setting no
 * password for $USER.  Luckily $USER has only priviledges to mess
 * up GNUnet's tables, nothing else (unless you give him more,
 * of course).<p>
 *
 * 3) Still, perhaps you should briefly try if the DB connection
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
 * REPAIRING TABLES:
 * - Its probably healthy to check your tables for inconsistencies
 *   every now and then.
 * - If you get odd SEGVs on gnunetd startup, it might be that the mysql
 *   databases have been corrupted.
 * - The tables can be verified/fixed in two ways;
 *   1) by running mysqlcheck -A, or
 *   2) by executing (inside of mysql using the GNUnet database):
 *   mysql> SHOW TABLES;
 *   mysql> REPAIR TABLE gnXXX;  
 *
 * Make sure to replace XXX with the actual names of all tables.
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

#define DEBUG_MYSQL GNUNET_NO

#define DEBUG_TIME_MYSQL GNUNET_NO

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define DIE_MYSQL(cmd, dbh) do { GNUNET_GE_LOG(ectx, GNUNET_GE_FATAL | GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, mysql_error((dbh)->dbf)); abort(); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_MYSQL(level, cmd, dbh) do { GNUNET_GE_LOG(ectx, level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, mysql_error((dbh)->dbf)); } while(0);

struct GNUNET_MysqlStatementHandle
{
  struct GNUNET_MysqlStatementHandle * next;

  struct GNUNET_MysqlDatabaseHandle * db;
  
  char * query;

  MYSQL_STMT * statement;

  int valid;
  
};

/**
 * @brief mysql database handle
 */
struct GNUNET_MysqlDatabaseHandle
{
  struct GNUNET_MysqlDatabaseHandle * next;

  MYSQL *dbf;

  char *cnffile;

  struct GNUNET_GE_Context * ectx;

  struct GNUNET_GC_Configuration * cfg;

  struct GNUNET_MysqlStatementHandle * statements;

  int valid;

};

/**
 * Lock for DB access.
 */
static struct GNUNET_Mutex *lock;

/**
 * Linked list of users of the DB right now.
 */
static struct GNUNET_MysqlDatabaseHandle * dbs;

/**
 * Obtain the location of ".my.cnf".
 * @return NULL on error
 */
static char *
get_my_cnf_path(struct GNUNET_GE_Context * ectx,
		struct GNUNET_GC_Configuration * cfg)
{
  char *cnffile;
  char *home_dir;
  struct stat st;
  size_t nX;
#ifndef WINDOWS
  struct passwd *pw;
#endif

#ifndef WINDOWS
  pw = getpwuid (getuid ());
  if (!pw)
    GNUNET_GE_DIE_STRERROR (ectx,
                            GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                            GNUNET_GE_IMMEDIATE, "getpwuid");
  home_dir = GNUNET_strdup (pw->pw_dir);
#else
  home_dir = (char *) GNUNET_malloc (_MAX_PATH + 1);
  plibc_conv_to_win_path ("~/", home_dir);
#endif
  nX = strlen (home_dir) + 10;
  cnffile = GNUNET_malloc (nX);
  GNUNET_snprintf (cnffile, nX, "%s/.my.cnf", home_dir);
  GNUNET_free (home_dir);
  GNUNET_GC_get_configuration_value_filename (cfg,
                                              "MYSQL", "CONFIG", cnffile,
                                              &home_dir);
  GNUNET_free (cnffile);
  cnffile = home_dir;
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _("Trying to use file `%s' for MySQL configuration.\n"),
                 cnffile);
  if ( (0 != STAT(cnffile, &st)) ||
       (0 != ACCESS(cnffile, R_OK)) ||
       (! S_ISREG(st.st_mode)) )
    {
      GNUNET_GE_LOG (ectx,
		     GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
		     GNUNET_GE_BULK, 
		     "Could not access file `%s'\n",
		     cnffile);
      GNUNET_free (cnffile);
      return NULL;
    }
  return cnffile;
}

/**
 * Close all database connections and their
 * prepared statements (we got a DB disconnect
 * error).
 */
static int
iclose ()
{
  struct GNUNET_MysqlDatabaseHandle * dpos;
  struct GNUNET_MysqlStatementHandle * spos;

  dpos = dbs;
  while (dpos != NULL)
    {
      spos = dpos->statements;
      while (spos != NULL)
	{
	  if (spos->statement != NULL) 
	    { 
	      mysql_stmt_close(spos->statement); 
	      spos->statement = NULL;
	    }
	  spos->valid = GNUNET_NO;	  
	  spos = spos->next;
	}
      mysql_close (dpos->dbf);
      dpos->dbf = NULL;
      dpos->valid = GNUNET_NO;      
      dpos = dpos->next;
    }
  return GNUNET_OK;
}

/**
 * Open a connection with MySQL (the connection maybe
 * internally be shared between clients of this library).
 *
 * @return NULL on error
 */
struct GNUNET_MysqlDatabaseHandle *
GNUNET_MYSQL_database_open(struct GNUNET_GE_Context * ectx,
			   struct GNUNET_GC_Configuration * cfg)
{
  struct GNUNET_MysqlDatabaseHandle * ret;
  char *dbname;
  my_bool reconnect = 0;
  unsigned int timeout = 60;    /* in seconds */
  
  GNUNET_mutex_lock(lock);
  ret = GNUNET_malloc(sizeof(struct GNUNET_MysqlDatabaseHandle));
  memset(ret, 0, sizeof(struct GNUNET_MysqlDatabaseHandle));
  ret->dbf = mysql_init (NULL);
  if (ret->dbf == NULL)
    {
      GNUNET_free(ret);
      GNUNET_mutex_unlock(lock);
      return NULL;
    }
  ret->ectx = ectx;
  ret->cfg = cfg;
  ret->cnffile = get_my_cnf_path(ectx, cfg);
  if (ret->cnffile == NULL)
    {
      mysql_close (ret->dbf);
      GNUNET_free(ret);
      GNUNET_mutex_unlock(lock);
      return NULL;
    }
  mysql_options (ret->dbf, MYSQL_READ_DEFAULT_FILE, ret->cnffile);
  mysql_options (ret->dbf, MYSQL_READ_DEFAULT_GROUP, "client");
  mysql_options (ret->dbf, MYSQL_OPT_RECONNECT, &reconnect);
  mysql_options (ret->dbf,
                 MYSQL_OPT_CONNECT_TIMEOUT, (const void *) &timeout);
  mysql_options (ret->dbf, MYSQL_OPT_READ_TIMEOUT, (const void *) &timeout);
  mysql_options (ret->dbf, MYSQL_OPT_WRITE_TIMEOUT, (const void *) &timeout);

  dbname = NULL;
  GNUNET_GC_get_configuration_value_string (cfg,
                                            "MYSQL", "DATABASE", "gnunet",
                                            &dbname);
  GNUNET_GE_ASSERT (ectx, dbname != NULL);
  mysql_real_connect (ret->dbf, NULL, NULL, NULL, dbname, 0, NULL, 0);
  GNUNET_free (dbname);
  if (mysql_error (ret->dbf)[0])
    {
      LOG_MYSQL (GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                 "mysql_real_connect", ret);
      mysql_close (ret->dbf);
      GNUNET_free(ret->cnffile);
      GNUNET_free(ret);      
      GNUNET_mutex_unlock(lock);
      return NULL;
    }
  ret->next = dbs;
  dbs = ret;
  GNUNET_mutex_unlock(lock);
  return ret;
}


/**
 * Close the database connection.
 */
void
GNUNET_MYSQL_database_close(struct GNUNET_MysqlDatabaseHandle * dbh)
{
  struct GNUNET_MysqlDatabaseHandle * prev;
  
  GNUNET_mutex_lock(lock);
  while (dbh->statements != NULL)
    GNUNET_MYSQL_prepared_statement_destroy(dbh->statements);
  GNUNET_free (dbh->cnffile);
  if (dbs != dbh)
    {
      prev = dbs;
      while ( (prev != NULL) &&
	      (prev->next != dbh) )
	prev = prev->next;
      GNUNET_GE_ASSERT(NULL, prev != NULL);
      prev->next = dbh->next;
    }
  else
    dbs = dbh->next;
  mysql_close (dbh->dbf);
  GNUNET_free (dbh);
}

/**
 * Run the given MySQL statement.  
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_MYSQL_run_statement(struct GNUNET_MysqlDatabaseHandle * dbh,
			   const char * statement)
{
  return GNUNET_SYSERR;
}

/**
 * Prepare a statement.
 *
 * @return NULL on error
 */
struct GNUNET_MysqlStatementHandle *
GNUNET_MYSQL_prepared_statement_create(struct GNUNET_MysqlDatabaseHandle * dbh,
				       const char * statement)
{
  return NULL;
}

/**
 * Free a prepared statement.
 */
void
GNUNET_MYSQL_prepared_statement_destroy(struct GNUNET_MysqlStatementHandle * s)
{
}

/**
 * Run a prepared SELECT statement.
 *
 * @param result_size number of elements in results array
 * @param results pointer to already initialized MYSQL_BIND
 *        array (of sufficient size) for passing results
 * @param processor function to call on each result
 * @param processor_cls extra argument to processor
 * @param ... pairs and triplets of "MYSQL_TYPE_XXX" keys and their respective
 *        values (size + buffer-reference for pointers); terminated
 *        with "-1"
 * @return GNUNET_SYSERR on error, otherwise
 *         the number of successfully affected (or queried) rows
 */
int
GNUNET_MYSQL_prepared_statement_run_select(struct GNUNET_MysqlStatementHandle * s,
					   unsigned int result_size,
					   MYSQL_BIND * results,
					   GNUNET_MysqlDataProcessor processor,
					   void * processor_cls,
					   ...)
{
  return GNUNET_SYSERR;
}


/**
 * Run a prepared statement that does NOT produce results.
 *
 * @param ... pairs and triplets of "MYSQL_TYPE_XXX" keys and their respective
 *        values (size + buffer-reference for pointers); terminated
 *        with "-1"
 * @return GNUNET_SYSERR on error, otherwise
 *         the number of successfully affected rows
 */
int
GNUNET_MYSQL_prepared_statement_run(struct GNUNET_MysqlStatementHandle * s,
				    ...)
{
  MYSQL_BIND qbind[42];
  unsigned long length = 42;

  memset (qbind, 0, sizeof (qbind));
  qbind[0].buffer_type = MYSQL_TYPE_BLOB;
  qbind[0].buffer = (void *) NULL;
  qbind[0].buffer_length = 42;
  qbind[0].length = &length;
  GNUNET_GE_ASSERT (s->db->ectx, mysql_stmt_param_count (s->statement) == 1);
  if (mysql_stmt_bind_param (s->statement, qbind))
    {
      GNUNET_GE_LOG (s->db->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "mysql_stmt_bind_param",
                     __FILE__, __LINE__,
                     mysql_stmt_error (s->statement));
      iclose ();
      return GNUNET_SYSERR;
    }
  if (mysql_stmt_execute (s->statement))
    {
      GNUNET_GE_LOG (s->db->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "mysql_stmt_execute",
                     __FILE__, __LINE__,
                     mysql_stmt_error (s->statement));
      iclose ();
      return GNUNET_SYSERR;
    }
  // *vkey = (unsigned long long) mysql_stmt_insert_id (dbh->insert_value);
  mysql_stmt_reset (s->statement);
  return GNUNET_OK;
}

void __attribute__ ((constructor)) GNUNET_mysql_ltdl_init ()
{
  lock = GNUNET_mutex_create (GNUNET_YES);
}

void __attribute__ ((destructor)) GNUNET_mysql_ltdl_fini ()
{
  GNUNET_mutex_destroy (lock);
  mysql_library_end ();
  lock = NULL;
}


/* end of lmysql.c */
