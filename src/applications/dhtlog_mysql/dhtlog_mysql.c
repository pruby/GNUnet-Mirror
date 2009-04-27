/*
     This file is part of GNUnet.
     (C) 2006 - 2009 Christian Grothoff (and other contributing authors)

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
 * @file applications/dhtlog_mysql/dhtlog_mysql.c
 * @brief MySQL logging service to record DHT operations
 * @author Nathan Evans
 *
 * Database: MySQL
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_mysql.h"
#include "gnunet_dhtlog_service.h"

#define DEBUG_DHTLOG GNUNET_YES

static unsigned long long max_varchar_len;

static char *blank;

static GNUNET_CoreAPIForPlugins *coreAPI;

static struct GNUNET_GC_Configuration *dhtlog_cfg;


/**
 * Handle for the MySQL database.
 */
static struct GNUNET_MysqlDatabaseHandle *db;


#define INSERT_QUERIES_STMT "INSERT INTO queries (trialuid, querytype, hops, dhtkey, dhtqueryid, succeeded, node) "\
                          "VALUES (?, ?, ?, ?, ?, ?, ?)"
static struct GNUNET_MysqlStatementHandle *insert_query;

#define INSERT_ROUTES_STMT "INSERT INTO routes (trialuid, querytype, hops, dhtkey, dhtqueryid, succeeded, node, from_node, to_node) "\
                          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
static struct GNUNET_MysqlStatementHandle *insert_route;

#define INSERT_NODES_STMT "INSERT INTO nodes (trialuid, nodeid) "\
                          "VALUES (?, ?)"
static struct GNUNET_MysqlStatementHandle *insert_node;

#define INSERT_TRIALS_STMT "INSERT INTO trials (starttime, numnodes, topology) "\
                          "VALUES (NOW(), ?, ?)"
static struct GNUNET_MysqlStatementHandle *insert_trial;

#define UPDATE_TRIALS_STMT "UPDATE trials set endtime=NOW() where trialuid=?"
static struct GNUNET_MysqlStatementHandle *update_trial;

#define GET_TRIAL_STMT "SELECT MAX( trialuid ) FROM trials"
static struct GNUNET_MysqlStatementHandle *get_trial;

/*
 * Creates tables if they don't already exist for dht logging
 */
static int
itable ()
{
#define MRUNS(a) (GNUNET_OK != GNUNET_MYSQL_run_statement (db, a) )
  if (MRUNS ("CREATE TABLE IF NOT EXISTS `nodes` ("
             "`nodeuid` int(10) unsigned NOT NULL auto_increment,"
             "`trialuid` int(11) NOT NULL,"
             "`nodeid` varchar(255) NOT NULL,"
             "PRIMARY KEY  (`nodeuid`)"
             ") ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
    return GNUNET_SYSERR;

  if (MRUNS ("CREATE TABLE IF NOT EXISTS `queries` ("
             "`trialuid` int(11) NOT NULL,"
             "`queryuid` int(10) unsigned NOT NULL auto_increment,"
             "`dhtqueryid` bigint(20) NOT NULL,"
             "`querytype` enum('1','2','3') NOT NULL,"
             "`hops` int(10) unsigned NOT NULL,"
             "`succeeded` tinyint NOT NULL,"
             "`node` varchar(255) NOT NULL,"
             "`time` timestamp NOT NULL default CURRENT_TIMESTAMP,"
             "`dhtkey` varchar(255) NOT NULL,"
             "PRIMARY KEY  (`queryuid`)"
             ") ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
    return GNUNET_SYSERR;

  if (MRUNS ("CREATE TABLE IF NOT EXISTS `routes` ("
             "`trialuid` int(11) NOT NULL,"
             "`queryuid` int(10) unsigned NOT NULL auto_increment,"
             "`dhtqueryid` bigint(20) NOT NULL,"
             "`querytype` enum('1','2','3') NOT NULL,"
             "`hops` int(10) unsigned NOT NULL,"
             "`succeeded` tinyint NOT NULL,"
             "`node` varchar(255) NOT NULL,"
             "`time` timestamp NOT NULL default CURRENT_TIMESTAMP,"
             "`dhtkey` varchar(255) NOT NULL,"
             "`from_node` varchar(255) NOT NULL,"
             "`to_node` varchar(255) NOT NULL,"
             "PRIMARY KEY  (`queryuid`)"
             ") ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
    return GNUNET_SYSERR;

  if (MRUNS ("CREATE TABLE IF NOT EXISTS `trials` ("
             "`trialuid` int(10) unsigned NOT NULL auto_increment,"
             "`numnodes` int(10) unsigned NOT NULL,"
             "`topology` varchar(55) NOT NULL,"
             "`starttime` datetime NOT NULL,"
             "`endtime` datetime NOT NULL,"
             "PRIMARY KEY  (`trialuid`),"
             "UNIQUE KEY `trialuid` (`trialuid`)"
             ") ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
    return GNUNET_SYSERR;
  return GNUNET_OK;
#undef MRUNS
}

/*
 * Initialize the prepared statements for use with dht test logging
 */
static int
iopen ()
{
  int ret;
  if (db != NULL)
    return GNUNET_OK;
  db = GNUNET_MYSQL_database_open (coreAPI->ectx, dhtlog_cfg);
  if (db == NULL)
    return GNUNET_SYSERR;

  ret = itable ();
#define PINIT(a,b) (NULL == (a = GNUNET_MYSQL_prepared_statement_create(db, b)))
  if (PINIT (insert_query, INSERT_QUERIES_STMT) ||
      PINIT (insert_route, INSERT_ROUTES_STMT) ||
      PINIT (insert_trial, INSERT_TRIALS_STMT) ||
      PINIT (insert_node, INSERT_NODES_STMT) ||
      PINIT (update_trial, UPDATE_TRIALS_STMT) ||
      PINIT (get_trial, GET_TRIAL_STMT))
    {
      GNUNET_MYSQL_database_close (db);
      db = NULL;
      return GNUNET_SYSERR;
    }
#undef PINIT
  return ret;
}

static int
return_ok (void *cls, unsigned int num_values, MYSQL_BIND * values)
{
  return GNUNET_OK;
}

/*
 * Inserts the specified trial into the dhttests.trials table
 */
static int
add_trial (unsigned long long *trialuid, int num_nodes, char *topology)
{

  int ret;
  unsigned long long t_len;
  t_len = strlen (topology);

  if (GNUNET_OK !=
      (ret = GNUNET_MYSQL_prepared_statement_run (insert_trial,
                                                  trialuid,
                                                  MYSQL_TYPE_LONG,
                                                  &num_nodes,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_VAR_STRING,
                                                  topology,
                                                  max_varchar_len,
                                                  &t_len, -1)))
    {
      if (ret == GNUNET_SYSERR)
        {
          return GNUNET_SYSERR;
        }
    }

  return GNUNET_OK;
}

static int
get_current_trial (unsigned long long *trialuid)
{
  MYSQL_BIND rbind[1];

  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_LONG;
  rbind[0].is_unsigned = 1;
  rbind[0].buffer = trialuid;

  if ((GNUNET_OK !=
       GNUNET_MYSQL_prepared_statement_run_select (get_trial,
                                                   1,
                                                   rbind,
                                                   return_ok, NULL, -1)))
    {
      return GNUNET_SYSERR;
    }

  return GNUNET_OK;
}

/*
 * Inserts the specified node into the dhttests.nodes table
 */
static int
add_node (unsigned long long *nodeuid, unsigned long long trialuid,
          GNUNET_PeerIdentity * node)
{
  GNUNET_EncName encPeer;
  unsigned long long p_len;
  int ret;

  if (node == NULL)
    return GNUNET_SYSERR;

  GNUNET_hash_to_enc (&node->hashPubKey, &encPeer);
  p_len = strlen ((char *) &encPeer);
  if (GNUNET_OK !=
      (ret = GNUNET_MYSQL_prepared_statement_run (insert_node,
                                                  nodeuid,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &trialuid,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_VAR_STRING,
                                                  &encPeer,
                                                  max_varchar_len,
                                                  &p_len, -1)))
    {
      if (ret == GNUNET_SYSERR)
        {
          return GNUNET_SYSERR;
        }
    }
  return GNUNET_OK;
}

/*
 * Update dhttests.trials table with current server time as end time
 */
static int
update_trials (unsigned long long trialuid)
{
  int ret;

  if (GNUNET_OK !=
      (ret = GNUNET_MYSQL_prepared_statement_run (update_trial,
                                                  NULL,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &trialuid, GNUNET_YES, -1)))
    {
      if (ret == GNUNET_SYSERR)
        {
          return GNUNET_SYSERR;
        }
    }
  if (ret > 0)
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
}

/*
 * Inserts the specified query into the dhttests.queries table
 */
static int
add_query (unsigned long long *sqlqueryuid, unsigned long long queryid,
           unsigned long long trialuid, unsigned int type, unsigned int hops,
           int succeeded, GNUNET_PeerIdentity * node, GNUNET_HashCode * key)
{
//trialuid, type, key, dhtqueryid, succeeded, node
  GNUNET_EncName encPeer;
  GNUNET_EncName encKey;
  unsigned long long p_len, k_len;
  int ret;

  GNUNET_hash_to_enc (&node->hashPubKey, &encPeer);
  GNUNET_hash_to_enc (key, &encKey);
  p_len = strlen ((char *) &encPeer);
  k_len = strlen ((char *) &encKey);

  if (GNUNET_OK !=
      (ret = GNUNET_MYSQL_prepared_statement_run (insert_query,
                                                  sqlqueryuid,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &trialuid,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &type,
                                                  GNUNET_NO,
                                                  MYSQL_TYPE_LONG,
                                                  &hops,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_VAR_STRING,
                                                  &encKey,
                                                  max_varchar_len,
                                                  &k_len,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &queryid,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &succeeded,
                                                  GNUNET_NO,
                                                  MYSQL_TYPE_VAR_STRING,
                                                  &encPeer,
                                                  max_varchar_len,
                                                  &p_len, -1)))
    {
      if (ret == GNUNET_SYSERR)
        {
          return GNUNET_SYSERR;
        }
    }
  if (ret > 0)
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
}

/*
 * Inserts the specified route information into the dhttests.routes table
 */
static int
add_route (unsigned long long *sqlqueryuid, unsigned long long queryid,
           unsigned long long trialuid, unsigned int type, unsigned int hops,
           int succeeded, GNUNET_PeerIdentity * node, GNUNET_HashCode * key,
           GNUNET_PeerIdentity * from_node, GNUNET_PeerIdentity * to_node)
{
//trialuid, querytype, dhtkey, dhtqueryid, succeeded, node, from_node, to_node
  GNUNET_EncName encPeer;
  GNUNET_EncName encKey;
  GNUNET_EncName encFromNode;
  GNUNET_EncName encToNode;
  unsigned long long p_len, k_len, from_len, to_len;
  int ret;

  GNUNET_hash_to_enc (&node->hashPubKey, &encPeer);
  GNUNET_hash_to_enc (key, &encKey);
  if (from_node != NULL)
    GNUNET_hash_to_enc (&from_node->hashPubKey, &encFromNode);
  else
    strcpy ((char *) &encFromNode, "");

  if (from_node != NULL)
    GNUNET_hash_to_enc (&from_node->hashPubKey, &encFromNode);
  else
    strcpy ((char *) &encFromNode, "");

  p_len = strlen ((char *) &encPeer);
  k_len = strlen ((char *) &encKey);
  from_len = strlen ((char *) &encFromNode);
  to_len = strlen ((char *) &encToNode);

  if (GNUNET_OK !=
      (ret = GNUNET_MYSQL_prepared_statement_run (insert_route,
                                                  sqlqueryuid,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &trialuid,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &type,
                                                  GNUNET_NO,
                                                  MYSQL_TYPE_LONG,
                                                  &hops,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_VAR_STRING,
                                                  &encKey,
                                                  max_varchar_len,
                                                  &k_len,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &queryid,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &succeeded,
                                                  GNUNET_NO,
                                                  MYSQL_TYPE_VAR_STRING,
                                                  &encPeer,
                                                  max_varchar_len,
                                                  &p_len,
                                                  MYSQL_TYPE_VAR_STRING,
                                                  &encFromNode,
                                                  max_varchar_len,
                                                  &from_len,
                                                  MYSQL_TYPE_VAR_STRING,
                                                  &encToNode,
                                                  max_varchar_len,
                                                  &to_len, -1)))
    {
      if (ret == GNUNET_SYSERR)
        {
          return GNUNET_SYSERR;
        }
    }
  if (ret > 0)
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
}

/*
 * Provides the dhtlog api
 */
GNUNET_dhtlog_ServiceAPI *
provide_module_dhtlog_mysql (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_dhtlog_ServiceAPI api;
  dhtlog_cfg = GNUNET_GC_create ();
  coreAPI = capi;
  max_varchar_len = 255;
  blank = "";
#if DEBUG_DHTLOG
  GNUNET_GE_LOG (capi->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "MySQL DHT Logger: initializing database\n");
  fprintf (stderr, "MySQL DHT Logger: initializing database\n");
#endif
  GNUNET_GC_set_configuration_value_string (dhtlog_cfg,
                                            NULL,
                                            "MYSQL", "DATABASE", "dhttests");
  if (iopen () != GNUNET_OK)
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_IMMEDIATE | GNUNET_GE_USER,
                     _
                     ("Failed to initialize MySQL database connection for dhtlog.\n"));
      return NULL;
    }

  api.insert_trial = &add_trial;
  api.insert_query = &add_query;
  api.update_trial = &update_trials;
  api.insert_route = &add_route;
  api.insert_node = &add_node;
  api.get_trial = &get_current_trial;

  return &api;
}

/**
 * Shutdown the module.
 */
void
release_module_dhtlog_mysql ()
{

#if DEBUG_DHTLOG
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "MySQL DHT Logger: database shutdown\n");
  fprintf (stderr, "MySQL DHT Logger: database shutdown\n");
#endif
  GNUNET_MYSQL_database_close (db);
  db = NULL;
  coreAPI = NULL;
}

/* end of dhtlog_mysql.c */
