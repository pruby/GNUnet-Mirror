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
 * @file include/gnunet_mysql.h
 * @brief wrapper around mysql
 * @author Christian Grothoff
 *
 * This wrapper is required because libmysql does not
 * work nicely when shared between multiple plugins
 * using prepared statements.
 */

#ifndef GNUNET_MYSQL_H
#define GNUNET_MYSQL_H

#include "gnunet_util.h"
#include <mysql/mysql.h>

struct GNUNET_MysqlStatementHandle;

struct GNUNET_MysqlDatabaseHandle;

/**
 * Open a connection with MySQL (the connection maybe
 * internally be shared between clients of this library).
 *
 * @return NULL on error
 */
struct GNUNET_MysqlDatabaseHandle *GNUNET_MYSQL_database_open (struct
                                                               GNUNET_GE_Context
                                                               *ectx,
                                                               struct
                                                               GNUNET_GC_Configuration
                                                               *gc);

/**
 * Close the database connection.
 */
void GNUNET_MYSQL_database_close (struct GNUNET_MysqlDatabaseHandle *dbh);

/**
 * Run the given MySQL statement.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_MYSQL_run_statement (struct GNUNET_MysqlDatabaseHandle *dbh,
                            const char *statement);


/**
 * Run the given MySQL SELECT statement.  The statement
 * must have only a single result (one column, one row).
 *
 * @return result on success, NULL on error
 */
char *GNUNET_MYSQL_run_statement_select (struct GNUNET_MysqlDatabaseHandle
                                         *dbh, const char *statement);


/**
 * Create a prepared statement.
 *
 * @return NULL on error
 */
struct GNUNET_MysqlStatementHandle
  *GNUNET_MYSQL_prepared_statement_create (struct GNUNET_MysqlDatabaseHandle
                                           *dbh, const char *statement);

/**
 * Free a prepared statement.
 */
void
GNUNET_MYSQL_prepared_statement_destroy (struct GNUNET_MysqlStatementHandle
                                         *s);

/**
 * Type of a callback that will be called for each
 * data set returned from MySQL.
 *
 * @param cls user-defined argument
 * @param num_values number of elements in values
 * @param values values returned by MySQL
 * @return GNUNET_OK to continue iterating, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_MysqlDataProcessor) (void *cls,
                                          unsigned int num_values,
                                          MYSQL_BIND * values);

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
GNUNET_MYSQL_prepared_statement_run_select (struct GNUNET_MysqlStatementHandle
                                            *s, unsigned int result_size,
                                            MYSQL_BIND * results,
                                            GNUNET_MysqlDataProcessor
                                            processor, void *processor_cls,
                                            ...);


/**
 * Run a prepared statement that does NOT produce results.
 *
 * @param ... pairs and triplets of "MYSQL_TYPE_XXX" keys and their respective
 *        values (size + buffer-reference for pointers); terminated
 *        with "-1"
 * @param insert_id NULL or address where to store the row ID of whatever
 *        was inserted (only for INSERT statements!)
 * @return GNUNET_SYSERR on error, otherwise
 *         the number of successfully affected rows
 */
int
GNUNET_MYSQL_prepared_statement_run (struct GNUNET_MysqlStatementHandle *s,
                                     unsigned long long *insert_id, ...);




/* ifndef GNUNET_MYSQL_H */
#endif
/* end of gnunet_mysql.h */
