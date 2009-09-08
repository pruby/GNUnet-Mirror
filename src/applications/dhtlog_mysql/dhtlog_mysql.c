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

static unsigned long max_varchar_len;

static char *blank;

static GNUNET_CoreAPIForPlugins *coreAPI;

static struct GNUNET_GC_Configuration *dhtlog_cfg;

static unsigned long long current_trial = 0;    /* I like to assign 0, just to remember */

/**
 * Handle for the MySQL database.
 */
static struct GNUNET_MysqlDatabaseHandle *db;


#define INSERT_QUERIES_STMT "INSERT INTO queries (trialuid, querytype, hops, dhtkeyuid, dhtqueryid, succeeded, nodeuid) "\
                          "VALUES (?, ?, ?, ?, ?, ?, ?)"
static struct GNUNET_MysqlStatementHandle *insert_query;

#define INSERT_ROUTES_STMT "INSERT INTO routes (trialuid, querytype, hops, dvhops, dhtkeyuid, dhtqueryid, succeeded, nodeuid, from_node, to_node) "\
                          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
static struct GNUNET_MysqlStatementHandle *insert_route;

#define INSERT_NODES_STMT "INSERT INTO nodes (trialuid, nodeid, nodebits) "\
                          "VALUES (?, ?, ?)"
static struct GNUNET_MysqlStatementHandle *insert_node;

#define INSERT_TRIALS_STMT "INSERT INTO trials (starttime, numnodes, topology, topology_modifier, logNMultiplier, puts, gets, concurrent, settle_time, num_rounds, malicious_getters, malicious_putters, malicious_droppers, maxnetbps, message) "\
                          "VALUES (NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
static struct GNUNET_MysqlStatementHandle *insert_trial;

#define INSERT_DHTKEY_STMT "INSERT INTO dhtkeys (dhtkey, trialuid, keybits) "\
                          "VALUES (?, ?, ?)"
static struct GNUNET_MysqlStatementHandle *insert_dhtkey;

#define UPDATE_TRIALS_STMT "UPDATE trials set endtime=NOW(), totalMessagesDropped = ?, totalBytesDropped = ?, unknownPeers = ?, where trialuid = ?"
static struct GNUNET_MysqlStatementHandle *update_trial;

#define UPDATE_CONNECTIONS_STMT "UPDATE trials set totalConnections = ? where trialuid = ?"
static struct GNUNET_MysqlStatementHandle *update_connection;

#define GET_TRIAL_STMT "SELECT MAX( trialuid ) FROM trials"
static struct GNUNET_MysqlStatementHandle *get_trial;

#define GET_DHTKEYUID_STMT "SELECT dhtkeyuid FROM dhtkeys where dhtkey = ? and trialuid = ?"
static struct GNUNET_MysqlStatementHandle *get_dhtkeyuid;

#define GET_NODEUID_STMT "SELECT nodeuid FROM nodes where trialuid = ? and nodeid = ?"
static struct GNUNET_MysqlStatementHandle *get_nodeuid;


/*
 * Creates tables if they don't already exist for dht logging
 */
static int
itable ()
{
#define MRUNS(a) (GNUNET_OK != GNUNET_MYSQL_run_statement (db, a) )

  if (MRUNS ("CREATE TABLE IF NOT EXISTS `dhtkeys` ("
             "dhtkeyuid int(10) unsigned NOT NULL auto_increment COMMENT 'Unique Key given to each query',"
             "`dhtkey` varchar(255) NOT NULL COMMENT 'The ASCII value of the key being searched for',"
             "trialuid int(10) unsigned NOT NULL,"
             "keybits blob NOT NULL,"
             "UNIQUE KEY `dhtkeyuid` (`dhtkeyuid`)"
             ") ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
    return GNUNET_SYSERR;

  if (MRUNS ("CREATE TABLE IF NOT EXISTS `nodes` ("
             "`nodeuid` int(10) unsigned NOT NULL auto_increment,"
             "`trialuid` int(10) unsigned NOT NULL,"
             "`nodeid` varchar(255) NOT NULL,"
             "PRIMARY KEY  (`nodeuid`)"
             ") ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
    return GNUNET_SYSERR;

  if (MRUNS ("CREATE TABLE IF NOT EXISTS `queries` ("
             "`trialuid` int(10) unsigned NOT NULL,"
             "`queryuid` int(10) unsigned NOT NULL auto_increment,"
             "`dhtqueryid` bigint(20) NOT NULL,"
             "`querytype` enum('1','2','3') NOT NULL,"
             "`hops` int(10) unsigned NOT NULL,"
             "`succeeded` tinyint NOT NULL,"
             "`nodeuid` int(10) unsigned NOT NULL,"
             "`time` timestamp NOT NULL default CURRENT_TIMESTAMP,"
             "`dhtkeyuid` int(10) unsigned NOT NULL,"
             "PRIMARY KEY  (`queryuid`)"
             ") ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
    return GNUNET_SYSERR;

  if (MRUNS ("CREATE TABLE IF NOT EXISTS `routes` ("
             "`trialuid` int(10) unsigned NOT NULL,"
             "`queryuid` int(10) unsigned NOT NULL auto_increment,"
             "`dhtqueryid` bigint(20) NOT NULL,"
             "`querytype` enum('1','2','3') NOT NULL,"
             "`hops` int(10) unsigned NOT NULL,"
             "`succeeded` tinyint NOT NULL,"
             "`nodeuid` int(10) unsigned NOT NULL,"
             "`time` timestamp NOT NULL default CURRENT_TIMESTAMP,"
             "`dhtkeyuid` int(10) unsigned NOT NULL,"
             "`from_node` int(10) unsigned NOT NULL,"
             "`to_node` int(10) unsigned NOT NULL,"
             "PRIMARY KEY  (`queryuid`)"
             ") ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
    return GNUNET_SYSERR;

  if (MRUNS ("CREATE TABLE IF NOT EXISTS `trials` ("
             "`trialuid` int(10) unsigned NOT NULL auto_increment,"
             "`numnodes` int(10) unsigned NOT NULL,"
             "`topology` int(10) NOT NULL,"
             "`puts` int(10) unsigned NOT NULL,"
             "`gets` int(10) unsigned NOT NULL,"
             "`concurrent` int(10) unsigned NOT NULL,"
             "`starttime` datetime NOT NULL,"
             "`endtime` datetime NOT NULL,"
             "`settle_time` int(10) unsigned NOT NULL,"
             "`num_rounds` int(10) unsigned NOT NULL,"
             "`malicious_getters` int(10) unsigned NOT NULL,"
             "`malicious_putters` int(10) unsigned NOT NULL,"
             "`malicious_droppers` int(10) unsigned NOT NULL,"
             "`message` text NOT NULL,"
             "`totalMessagesDropped` int(10) unsigned NOT NULL,"
             "`totalBytesDropped` int(10) unsigned NOT NULL,"
             "`unknownPeers` int(10) unsigned NOT NULL,"
             "PRIMARY KEY  (`trialuid`),"
             "UNIQUE KEY `trialuid` (`trialuid`)"
             ") ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1"))
    return GNUNET_SYSERR;

  if (MRUNS ("SET AUTOCOMMIT = 1"))
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
      PINIT (insert_dhtkey, INSERT_DHTKEY_STMT) ||
      PINIT (update_trial, UPDATE_TRIALS_STMT) ||
      PINIT (get_dhtkeyuid, GET_DHTKEYUID_STMT) ||
      PINIT (get_nodeuid, GET_NODEUID_STMT) ||
      PINIT (update_connection, UPDATE_CONNECTIONS_STMT) ||
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
 * Inserts the specified trial into the dhttests.trials table
 */
int
add_trial (unsigned long long *trialuid, int num_nodes, int topology,
           float topology_modifier, float logNMultiplier,
           int puts, int gets, int concurrent, int settle_time,
           int num_rounds, int malicious_getters, int malicious_putters,
           int malicious_droppers, unsigned long long maxnetbps,
           char *message)
{
  int ret;
  unsigned long long m_len;
  m_len = strlen (message);
  if (GNUNET_OK !=
      (ret = GNUNET_MYSQL_prepared_statement_run (insert_trial,
                                                  trialuid,
                                                  MYSQL_TYPE_LONG,
                                                  &num_nodes,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &topology,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_FLOAT,
                                                  &topology_modifier,
                                                  MYSQL_TYPE_FLOAT,
                                                  &logNMultiplier,
                                                  MYSQL_TYPE_LONG,
                                                  &puts,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &gets,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &concurrent,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &settle_time,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &num_rounds,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &malicious_getters,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &malicious_putters,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &malicious_droppers,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &maxnetbps,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_BLOB,
                                                  message,
                                                  max_varchar_len +
                                                  max_varchar_len, &m_len,
                                                  -1)))
    {
      if (ret == GNUNET_SYSERR)
        {
          return GNUNET_SYSERR;
        }
    }

  get_current_trial (&current_trial);
#if DEBUG_DHTLOG
  fprintf (stderr, "Current trial is %llu\n", current_trial);
#endif
  return GNUNET_OK;
}


/*
 * Inserts the specified dhtkey into the dhttests.dhtkeys table,
 * stores return value of dhttests.dhtkeys.dhtkeyuid into dhtkeyuid
 */
int
add_dhtkey (unsigned long long *dhtkeyuid, const GNUNET_HashCode * dhtkey)
{

  int ret;
  GNUNET_EncName encKey;
  unsigned long long k_len;
  unsigned long long h_len;
  GNUNET_hash_to_enc (dhtkey, &encKey);
  k_len = strlen ((char *) &encKey);
  h_len = sizeof (GNUNET_HashCode);
  if (GNUNET_OK !=
      (ret = GNUNET_MYSQL_prepared_statement_run (insert_dhtkey,
                                                  dhtkeyuid,
                                                  MYSQL_TYPE_VAR_STRING,
                                                  &encKey,
                                                  max_varchar_len,
                                                  &k_len,
                                                  MYSQL_TYPE_LONG,
                                                  &current_trial,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_BLOB,
                                                  dhtkey,
                                                  sizeof (GNUNET_HashCode),
                                                  &h_len, -1)))
    {
      if (ret == GNUNET_SYSERR)
        {
          return GNUNET_SYSERR;
        }
    }

  return GNUNET_OK;
}


static int
get_dhtkey_uid (unsigned long long *dhtkeyuid, const GNUNET_HashCode * key)
{
  MYSQL_BIND rbind[1];
  GNUNET_EncName encKey;
  unsigned long long k_len;
  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_LONG;
  rbind[0].is_unsigned = 1;
  rbind[0].buffer = dhtkeyuid;
  GNUNET_hash_to_enc (key, &encKey);
  k_len = strlen ((char *) &encKey);

  if ((GNUNET_OK !=
       GNUNET_MYSQL_prepared_statement_run_select (get_dhtkeyuid,
                                                   1,
                                                   rbind,
                                                   return_ok, NULL,
                                                   MYSQL_TYPE_VAR_STRING,
                                                   &encKey,
                                                   max_varchar_len,
                                                   &k_len,
                                                   MYSQL_TYPE_LONGLONG,
                                                   &current_trial,
                                                   GNUNET_YES, -1)))
    {
      return GNUNET_SYSERR;
    }

  return GNUNET_OK;
}

static int
get_node_uid (unsigned long long *nodeuid, const GNUNET_HashCode * peerHash)
{
  MYSQL_BIND rbind[1];
  GNUNET_EncName encPeer;
  unsigned long long p_len;

  int ret;
  memset (rbind, 0, sizeof (rbind));
  rbind[0].buffer_type = MYSQL_TYPE_LONG;
  rbind[0].buffer = nodeuid;
  rbind[0].is_unsigned = GNUNET_YES;

  GNUNET_hash_to_enc (peerHash, &encPeer);
  p_len = strlen ((char *) &encPeer);

  if (1 != (ret = GNUNET_MYSQL_prepared_statement_run_select (get_nodeuid,
                                                              1,
                                                              rbind,
                                                              return_ok,
                                                              NULL,
                                                              MYSQL_TYPE_LONG,
                                                              &current_trial,
                                                              GNUNET_YES,
                                                              MYSQL_TYPE_VAR_STRING,
                                                              &encPeer,
                                                              max_varchar_len,
                                                              &p_len, -1)))
    {
#if DEBUG_DHTLOG
      fprintf (stderr, "FAILED\n");
#endif
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}


/*
 * Inserts the specified node into the dhttests.nodes table
 */
int
add_node (unsigned long long *nodeuid, GNUNET_PeerIdentity * node)
{
  GNUNET_EncName encPeer;
  unsigned long p_len;
  unsigned long h_len;
  int ret;

  if (node == NULL)
    return GNUNET_SYSERR;

  GNUNET_hash_to_enc (&node->hashPubKey, &encPeer);
  p_len = (unsigned long) strlen ((char *) &encPeer);
  h_len = sizeof (GNUNET_HashCode);
  if (GNUNET_OK !=
      (ret = GNUNET_MYSQL_prepared_statement_run (insert_node,
                                                  nodeuid,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &current_trial,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_VAR_STRING,
                                                  &encPeer,
                                                  max_varchar_len,
                                                  &p_len,
                                                  MYSQL_TYPE_BLOB,
                                                  &node->hashPubKey,
                                                  sizeof (GNUNET_HashCode),
                                                  &h_len, -1)))
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
int
update_trials (unsigned long long trialuid,
               unsigned long long totalMessagesDropped,
               unsigned long long totalBytesDropped,
               unsigned long long unknownPeers)
{
  int ret;
#if DEBUG_DHTLOG
  if (trialuid != current_trial)
    {
      fprintf (stderr,
               _("Trialuid to update is not equal to current_trial\n"));
    }
#endif
  if (GNUNET_OK !=
      (ret = GNUNET_MYSQL_prepared_statement_run (update_trial,
                                                  NULL,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &totalMessagesDropped,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &totalBytesDropped,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &unknownPeers,
                                                  GNUNET_YES,
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
 * Update dhttests.trials table with total connections information
 */
int
add_connections (unsigned long long trialuid, unsigned int totalConnections)
{
  int ret;
#if DEBUG_DHTLOG
  if (trialuid != current_trial)
    {
      fprintf (stderr,
               _("Trialuid to update is not equal to current_trial(!)(?)\n"));
    }
#endif
  if (GNUNET_OK !=
      (ret = GNUNET_MYSQL_prepared_statement_run (update_connection,
                                                  NULL,
                                                  MYSQL_TYPE_LONG,
                                                  &totalConnections,
                                                  GNUNET_YES,
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
int
add_query (unsigned long long *sqlqueryuid, unsigned long long queryid,
           unsigned int type, unsigned int hops, int succeeded,
           const GNUNET_PeerIdentity * node, const GNUNET_HashCode * key)
{
  int ret;
  unsigned long long peer_uid, key_uid;
  peer_uid = 0;
  key_uid = 0;

  if ((node != NULL)
      && (GNUNET_OK == get_node_uid (&peer_uid, &node->hashPubKey)))
    {

    }
  else
    {
      return GNUNET_SYSERR;
    }

  if ((key != NULL) && (GNUNET_OK == get_dhtkey_uid (&key_uid, key)))
    {

    }
  else if (key->bits[(512 / 8 / sizeof (unsigned int)) - 1] == 42)      /* Malicious marker */
    {
      key_uid = 0;
    }
  else
    {
      return GNUNET_SYSERR;
    }

  if (GNUNET_OK !=
      (ret = GNUNET_MYSQL_prepared_statement_run (insert_query,
                                                  sqlqueryuid,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &current_trial,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &type,
                                                  GNUNET_NO,
                                                  MYSQL_TYPE_LONG,
                                                  &hops,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &key_uid,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &queryid,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &succeeded,
                                                  GNUNET_NO,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &peer_uid, GNUNET_YES, -1)))
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
int
add_route (unsigned long long *sqlqueryuid, unsigned long long queryid,
           unsigned int type, unsigned int hops, unsigned int dvhops,
           int succeeded, const GNUNET_PeerIdentity * node,
           const GNUNET_HashCode * key, const GNUNET_PeerIdentity * from_node,
           const GNUNET_PeerIdentity * to_node)
{
  unsigned long long peer_uid = 0;
  unsigned long long key_uid = 0;
  unsigned long long from_uid = 0;
  unsigned long long to_uid = 0;
  int ret;

  if (from_node != NULL)
    get_node_uid (&from_uid, &from_node->hashPubKey);
  else
    from_uid = 0;

  if (to_node != NULL)
    get_node_uid (&to_uid, &to_node->hashPubKey);
  else
    to_uid = 0;

  if ((node != NULL))
    {
      if (1 != get_node_uid (&peer_uid, &node->hashPubKey))
        {
          return GNUNET_SYSERR;
        }
    }
  else
    return GNUNET_SYSERR;

  if ((key != NULL))
    {
      if (1 != get_dhtkey_uid (&key_uid, key))
        {
          return GNUNET_SYSERR;
        }
    }
  else
    return GNUNET_SYSERR;

  if (GNUNET_OK !=
      (ret = GNUNET_MYSQL_prepared_statement_run (insert_route,
                                                  sqlqueryuid,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &current_trial,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &type,
                                                  GNUNET_NO,
                                                  MYSQL_TYPE_LONG,
                                                  &hops,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &dvhops,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &key_uid,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &queryid,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONG,
                                                  &succeeded,
                                                  GNUNET_NO,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &peer_uid,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &from_uid,
                                                  GNUNET_YES,
                                                  MYSQL_TYPE_LONGLONG,
                                                  &to_uid, GNUNET_YES, -1)))
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
  char *mysql_server;
  char *mysql_user;
  char *mysql_db;
  char *mysql_password;
  unsigned long long mysql_port;

  dhtlog_cfg = GNUNET_GC_create ();
  coreAPI = capi;
  max_varchar_len = 255;
  blank = "";
#if DEBUG_DHTLOG
  GNUNET_GE_LOG (capi->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "MySQL DHT Logger: initializing database\n");
  fprintf (stderr, "MySQL DHT Logger: initializing database\n");
#endif

  GNUNET_GC_get_configuration_value_string (capi->cfg,
                                            "MULTIPLE_SERVER_TESTING",
                                            "MYSQL_SERVER", "localhost",
                                            &mysql_server);

  GNUNET_GC_get_configuration_value_string (capi->cfg,
                                            "MULTIPLE_SERVER_TESTING",
                                            "MYSQL_DB", "dhttests",
                                            &mysql_db);

  GNUNET_GC_get_configuration_value_string (capi->cfg,
                                            "MULTIPLE_SERVER_TESTING",
                                            "MYSQL_USER", "dht", &mysql_user);

  GNUNET_GC_get_configuration_value_string (capi->cfg,
                                            "MULTIPLE_SERVER_TESTING",
                                            "MYSQL_PASSWORD", "dht**",
                                            &mysql_password);

  GNUNET_GC_get_configuration_value_number (capi->cfg,
                                            "MULTIPLE_SERVER_TESTING",
                                            "MYSQL_PORT", 1, -1, 3306,
                                            &mysql_port);

  GNUNET_GC_set_configuration_value_string (dhtlog_cfg,
                                            NULL,
                                            "MYSQL", "DATABASE", mysql_db);

  GNUNET_GC_set_configuration_value_string (dhtlog_cfg,
                                            NULL,
                                            "MYSQL", "HOST", mysql_server);

  GNUNET_GC_set_configuration_value_string (dhtlog_cfg,
                                            NULL,
                                            "MYSQL", "USER", mysql_user);

  GNUNET_GC_set_configuration_value_string (dhtlog_cfg,
                                            NULL,
                                            "MYSQL", "PASSWORD",
                                            mysql_password);

  GNUNET_GC_set_configuration_value_number (dhtlog_cfg,
                                            NULL,
                                            "MYSQL", "PORT", mysql_port);

#if DEBUG_DHTLOG
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 _
                 ("pertinent mysql information: host %s, user %s, port %llu, pass %s, DB %s\n"),
                 mysql_server, mysql_user, mysql_port, mysql_password,
                 mysql_db);
#endif
  if (iopen () != GNUNET_OK)
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_IMMEDIATE | GNUNET_GE_USER,
                     _
                     ("Failed to initialize MySQL database connection for dhtlog.\n"));
      GNUNET_free (mysql_user);
      GNUNET_free (mysql_password);
      GNUNET_free (mysql_db);
      GNUNET_free (mysql_server);
      return NULL;
    }

  api.insert_trial = &add_trial;
  api.insert_query = &add_query;
  api.update_trial = &update_trials;
  api.insert_route = &add_route;
  api.insert_node = &add_node;
  api.insert_dhtkey = &add_dhtkey;
  api.update_connections = &add_connections;
  get_current_trial (&current_trial);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, _("current trial is %llu\n"), current_trial);
  GNUNET_free (mysql_user);
  GNUNET_free (mysql_password);
  GNUNET_free (mysql_db);
  GNUNET_free (mysql_server);
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
