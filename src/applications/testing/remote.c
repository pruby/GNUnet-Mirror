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
 * @file applications/testing/remote.c
 * @brief application to start remote gnunetd daemons
 * @author Nathan Evans
 */

#include "remote.h"
#include "remotetopologies.c"

#define GET_MASK 1
#define PUT_MASK 2
#define DROP_MASK 4
#define MAX_CONNECT_THREADS 10

struct ConnectedEntry
{
  struct ConnectedEntry *next;
  GNUNET_HashCode key;
};

static struct GNUNET_Mutex *connectMutex;
struct GNUNET_MultiHashMap *connected;

/* Yes this is ugly, but for now it is nice to
 * have a linked list and an array
 */
static struct GNUNET_REMOTE_host_list *head;
static struct GNUNET_REMOTE_host_list **list_as_array;

static int threadCount;
static int totalConnections;
static int connectFailures;

static FILE *globalDotFile;
/**
 * Starts a single gnunet daemon on a remote machine
 *
 * @param gnunetd_home directory where gnunetd is on remote machine
 * @param localConfigPath local configuration path for config file
 * @param configFileName  file to copy and use on remote machine
 * @param remote_config_path remote path to copy local config to
 * @param hostname hostname or ip address of remote machine
 * @param username username to use for ssh (assumed to be used with ssh-agent)
 * @param remote_friend_file_path path for friend file on remote machine
 * @param prepend_exec prepend gnunetd command with prepend_exec (such as valgrind)
 */
int
GNUNET_REMOTE_start_daemon (char *gnunetd_home,
                            char *localConfigPath, char *configFileName,
                            char *remote_config_path, char *hostname,
                            char *username, char *remote_friend_file_path,
                            char *prepend_exec)
{
  char *cmd;
  int length;
  unsigned int is_local = 0;
  int unused;

  if (strcmp (hostname, "localhost") == 0)
    {
      is_local = 1;
    }

  if (is_local)
    {
      length =
        snprintf (NULL, 0, "cp %s%s %s > /dev/null 2>&1", localConfigPath,
                  configFileName, remote_config_path);
      cmd = GNUNET_malloc (length + 1);
      GNUNET_snprintf (cmd, length + 1, "cp %s%s %s > /dev/null 2>&1",
                       localConfigPath, configFileName, remote_config_path);
    }
  else
    {
      length =
        snprintf (NULL, 0, "scp %s%s %s@%s:%s > /dev/null 2>&1",
                  localConfigPath, configFileName, username, hostname,
                  remote_config_path);
      cmd = GNUNET_malloc (length + 1);
      GNUNET_snprintf (cmd, length + 1, "scp %s%s %s@%s:%s > /dev/null 2>&1",
                       localConfigPath, configFileName, username, hostname,
                       remote_config_path);
    }

#if VERBOSE
  fprintf (stderr, _("cp command is : %s \n"), cmd);
#endif
  unused = system (cmd);

  GNUNET_free (cmd);

  if (is_local)
    {
      length =
        snprintf (NULL, 0, "%sgnunet-update -c %s%s > /dev/null 2>&1",
                  gnunetd_home, remote_config_path, configFileName);
      cmd = GNUNET_malloc (length + 1);
      snprintf (cmd, length + 1, "%sgnunet-update -c %s%s > /dev/null 2>&1",
                gnunetd_home, remote_config_path, configFileName);
    }
  else
    {
      length =
        snprintf (NULL, 0,
                  "ssh %s@%s %sgnunet-update -c %s%s > /dev/null 2>&1",
                  username, hostname, gnunetd_home, remote_config_path,
                  configFileName);
      cmd = GNUNET_malloc (length + 1);
      snprintf (cmd, length + 1,
                "ssh %s@%s %sgnunet-update -c %s%s > /dev/null 2>&1",
                username, hostname, gnunetd_home, remote_config_path,
                configFileName);
    }
#if VERBOSE
  fprintf (stderr, _("exec command is : %s \n"), cmd);
#endif

  unused = system (cmd);
  GNUNET_free (cmd);

  if (is_local)
    {
      length =
        snprintf (NULL, 0, "%s %sgnunetd -c %s%s > /dev/null 2>&1 &",
                  prepend_exec, gnunetd_home, remote_config_path,
                  configFileName);
      cmd = GNUNET_malloc (length + 1);
      snprintf (cmd, length + 1, "%s %sgnunetd -c %s%s 2>&1 > /dev/null &",
                prepend_exec, gnunetd_home, remote_config_path,
                configFileName);
    }
  else
    {
      length =
        snprintf (NULL, 0,
                  "ssh %s@%s %s %sgnunetd -c %s%s > /dev/null 2>&1 &",
                  username, hostname, prepend_exec, gnunetd_home,
                  remote_config_path, configFileName);
      cmd = GNUNET_malloc (length + 1);
      snprintf (cmd, length + 1,
                "ssh %s@%s %s %sgnunetd -c %s%s > /dev/null 2>&1 &", username,
                hostname, prepend_exec, gnunetd_home, remote_config_path,
                configFileName);

    }
#if VERBOSE
  fprintf (stderr, _("exec command is : %s \n"), cmd);
#endif

  unused = system (cmd);
  GNUNET_free (cmd);
  return GNUNET_OK;
}

int
GNUNET_REMOTE_kill_daemon (struct GNUNET_REMOTE_TESTING_DaemonContext *tokill)
{
  char *cmd;
  int length;
  unsigned int is_local = 0;
  int unused;
  FILE *output;
  pid_t pid;

  if (strcmp (tokill->hostname, "localhost") == 0)
    {
      is_local = 1;
    }

  if (is_local)
    {
      length = snprintf (NULL, 0, "cat %s", tokill->pid);
      cmd = GNUNET_malloc (length + 1);
      snprintf (cmd, length + 1, "cat %s", tokill->pid);
    }
  else
    {
      length =
        snprintf (NULL, 0, "ssh %s@%s cat %s", tokill->username,
                  tokill->hostname, tokill->pid);
      cmd = GNUNET_malloc (length + 1);
      snprintf (cmd, length + 1, "ssh %s@%s cat %s", tokill->username,
                tokill->hostname, tokill->pid);
    }
#if VERBOSE
  fprintf (stderr, _("exec command is : %s \n"), cmd);
#endif

  output = popen (cmd, "r");
  GNUNET_free (cmd);
  if (fscanf (output, "%d", &pid) == 1)
    {
#if VERBOSE
      fprintf (stderr, _("Got pid %d\n"), pid);
#endif
    }
  else
    {
      return -1;
    }

  if (is_local)
    {
      length = snprintf (NULL, 0, "kill %d", pid);
      cmd = GNUNET_malloc (length + 1);
      snprintf (cmd, length + 1, "kill %d", pid);
    }
  else
    {
      length =
        snprintf (NULL, 0, "ssh %s@%s kill %d", tokill->username,
                  tokill->hostname, pid);
      cmd = GNUNET_malloc (length + 1);
      snprintf (cmd, length + 1, "ssh %s@%s kill %d",
                tokill->username, tokill->hostname, pid);

    }
#if VERBOSE
  fprintf (stderr, _("exec command is : %s \n"), cmd);
#endif
  unused = system (cmd);
  GNUNET_free (cmd);
  GNUNET_thread_sleep(500 * GNUNET_CRON_MILLISECONDS);
  UNLINK (tokill->path);
  return GNUNET_OK;
}

static int
get_pid (struct GNUNET_REMOTE_TESTING_DaemonContext *daemon)
{
  char *tempcmd;
  int length;
  unsigned int is_local = 0;
  FILE *output;
  pid_t pid;
  output = NULL;
  if (strcmp (daemon->hostname, "localhost") == 0)
    {
      is_local = 1;
    }

  if (is_local)
    {
      length = snprintf (NULL, 0, "cat %s", daemon->pid);
      tempcmd = GNUNET_malloc (length + 1);
      if (tempcmd != NULL)
        snprintf (tempcmd, length + 1, "cat %s", daemon->pid);
    }
  else
    {
      length =
        snprintf (NULL, 0, "ssh %s@%s cat %s", daemon->username,
                  daemon->hostname, daemon->pid);
      tempcmd = GNUNET_malloc (length + 1);
      if (tempcmd != NULL)
        snprintf (tempcmd, length + 1, "ssh %s@%s cat %s", daemon->username,
                  daemon->hostname, daemon->pid);
    }
#if VERBOSE
  fprintf (stderr, _("exec command is : %s \n"), tempcmd);
#endif
  pid = -1;
  if ((tempcmd != NULL) && (strcmp (tempcmd, "") != 0))
    {
      output = popen (tempcmd, "r");
      if ((output != NULL) && (fscanf (output, "%d", &pid) == 1))
        {
#if VERBOSE
          fprintf (stderr, _("Got pid %d\n"), pid);
#endif
        }
      else
        {
          pid = -1;
        }
    }
  if (output != NULL)
    fclose (output);
  if (tempcmd != NULL)
    GNUNET_free (tempcmd);
  return pid;
}


int
GNUNET_REMOTE_start_daemons (struct GNUNET_REMOTE_TESTING_DaemonContext
                             **ret_peers,
                             struct GNUNET_GC_Configuration *newcfg,
                             unsigned long long number_of_daemons)
{
  struct GNUNET_GC_Configuration *basecfg;
  struct GNUNET_GC_Configuration *tempcfg;
  struct GNUNET_REMOTE_host_list *array_of_pointers[number_of_daemons];
  struct GNUNET_REMOTE_host_list *temp_pos;
  GNUNET_REMOTE_TOPOLOGIES type_of_topology;
  struct GNUNET_REMOTE_TESTING_DaemonContext *new_ret_peers;
  struct GNUNET_REMOTE_TESTING_DaemonContext *next_peer;

  new_ret_peers = NULL;
  list_as_array = &array_of_pointers[0];
  FILE *dotOutFile;

  char host[128];
  char *ssh_username;
  char *control_host;
  char *percentage_string;
  char *logNModifier_string;
  char *remote_config_path;
  char *remote_gnunetd_path;
  char *remote_pid_path;
  char *mysql_server;
  char *mysql_user;
  char *mysql_password;
  char *mysql_db;
  char *base_config;
  char *data_dir;
  char *hostnames;
  char *temp;
  char *temp_path;
  char *temp_pid_file;
  char *curr_host;
  char *temp_host_string;
  char *temp_remote_config_path;
  char *dotOutFileName;
  char *prepend_exec;

  unsigned long long starting_port;
  unsigned long long port_increment;
  unsigned long long mysql_port;
  unsigned long long daemons_per_machine;
  unsigned long long temp_port;
  unsigned long long topology;

  unsigned long long malicious_getters;
  unsigned long long malicious_get_frequency;
  unsigned long long malicious_putters;
  unsigned long long malicious_put_frequency;
  unsigned long long malicious_droppers;
  unsigned long long maxnetbps;

  unsigned long long extra_daemons;
  unsigned int count;
  unsigned int count_started;
  unsigned int length;
  unsigned int length_temp;
  unsigned long long num_machines;
  unsigned int i;
  unsigned int j;
  unsigned int modnum;
  unsigned int dotnum;
  unsigned int pos;
  unsigned short malicious_mask;
  int temp_remote_config_path_length;
  int temp_host_string_length;
  int friend_location_length;
  int ret;
  char *ipk_dir;
  double percentage;
  double logNModifier;

  int malicious_getter_num;
  int malicious_putter_num;
  int malicious_dropper_num;

  length = 0;
  ipk_dir = GNUNET_get_installation_path (GNUNET_IPK_DATADIR);
  if (ipk_dir == NULL)
    ipk_dir = GNUNET_strdup ("");
  length = snprintf (NULL, 0, "%s%s", ipk_dir, "gnunetd.conf.skel");
  data_dir = GNUNET_malloc (length + 1);
  snprintf (data_dir, length + 1, "%s%s", ipk_dir, "gnunetd.conf.skel");
  GNUNET_free (ipk_dir);
  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "SSH_USERNAME", "",
                                            &ssh_username);

  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "PREPEND_EXECUTABLE", "",
                                            &prepend_exec);

  GNUNET_GC_get_configuration_value_number (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "TOPOLOGY", 0, -1, 0, &topology);

  GNUNET_GC_get_configuration_value_number (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "MALICIOUS_GETTERS", 0,
                                            number_of_daemons, 0,
                                            &malicious_getters);

  if (malicious_getters > 0)
    malicious_getter_num = (int) (number_of_daemons / malicious_getters);
  else
    malicious_getter_num = 0;

  GNUNET_GC_get_configuration_value_number (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "MALICIOUS_PUTTERS", 0,
                                            number_of_daemons, 0,
                                            &malicious_putters);

  if (malicious_putters > 0)
    malicious_putter_num = (int) (number_of_daemons / malicious_putters);
  else
    malicious_putter_num = 0;

  GNUNET_GC_get_configuration_value_number (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "MALICIOUS_DROPPERS", 0,
                                            number_of_daemons, 0,
                                            &malicious_droppers);

  if (malicious_droppers > 0)
    malicious_dropper_num = (int) (number_of_daemons / malicious_droppers);
  else
    malicious_dropper_num = 0;

  type_of_topology = (unsigned int) topology;

  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "PERCENTAGE", "1.0",
                                            &percentage_string);
  percentage = atof (percentage_string);
  if (strcmp (percentage_string, "") != 0)
    percentage = atof (percentage_string);
  else
    percentage = 1.0;

  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "LOGNMODIFIER", "1.0",
                                            &logNModifier_string);

  if (strcmp (logNModifier_string, "") != 0)
    logNModifier = atof (logNModifier_string);
  else
    logNModifier = 1.0;

  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "CONTROL_HOST", "localhost",
                                            &control_host);

  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "HOSTNAMES", "localhost",
                                            &hostnames);

  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "DOT_OUTPUT", "",
                                            &dotOutFileName);
#if VERBOSE
  fprintf (stderr, "Hostnames is %s\n", hostnames);
#endif
  dotOutFile = NULL;
  if (strcmp (dotOutFileName, "") != 0)
    {
      dotOutFile = FOPEN (dotOutFileName, "w");
      if (dotOutFile != NULL)
        {
          fprintf (dotOutFile, "strict graph G {\n");
        }
    }

  GNUNET_GC_get_configuration_value_number (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "STARTING_PORT",
                                            1, -1, 1, &starting_port);

  GNUNET_GC_get_configuration_value_number (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "PORT_INCREMENT",
                                            1, -1, 2, &port_increment);

  GNUNET_GC_get_configuration_value_number (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "MAXNETBPS",
                                            1, -1, 50000000, &maxnetbps);

  GNUNET_GC_get_configuration_value_number (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "MYSQL_PORT",
                                            1, -1, 3306, &mysql_port);

  GNUNET_GC_get_configuration_value_number (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "MALICIOUS_GET_FREQUENCY",
                                            0, -1, 0,
                                            &malicious_get_frequency);

  GNUNET_GC_get_configuration_value_number (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "MALICIOUS_PUT_FREQUENCY",
                                            0, -1, 0,
                                            &malicious_put_frequency);

  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "REMOTE_CONFIG_PATH", "/tmp/",
                                            &remote_config_path);

  ipk_dir = GNUNET_get_installation_path (GNUNET_IPK_BINDIR);

  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "REMOTE_GNUNETD_PATH", ipk_dir,
                                            &remote_gnunetd_path);

  if (ipk_dir != NULL)
    GNUNET_free (ipk_dir);

  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "BASE_CONFIG",
                                            "gnunetd.conf.skel",
                                            &base_config);

  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "PID_PATH", "/tmp/",
                                            &remote_pid_path);

  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "MYSQL_SERVER", control_host,
                                            &mysql_server);

  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "MYSQL_DB", "dht", &mysql_db);

  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "MYSQL_USER", "dht", &mysql_user);

  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "MYSQL_PASSWORD", "dht**",
                                            &mysql_password);
  length = strlen (hostnames);
  num_machines = 1;
  for (count = 0; count < length; count++)
    if (hostnames[count] == ' ')
      ++num_machines;

  daemons_per_machine = number_of_daemons / num_machines;
  extra_daemons = number_of_daemons - (daemons_per_machine * num_machines);
#if VERBOSE
  fprintf (stdout, "Have %llu machines, need to start %llu daemons\n",
           num_machines, number_of_daemons);
  fprintf (stdout, "Total started without extra is %llu\n",
           daemons_per_machine * num_machines);
  fprintf (stdout, "Will start %llu per machine, and %llu extra\n",
           daemons_per_machine, extra_daemons);
#endif
  i = 0;
  count_started = 0;
  modnum = number_of_daemons / 4;
  dotnum = ceil(number_of_daemons / 50);
  if (dotnum == 0)
  	dotnum = 1;
  pos = length;
  fprintf (stdout, "Daemon start progress: [");
  fflush (stdout);
  while (i < num_machines)
    {
      basecfg = GNUNET_GC_create ();

      if (-1 == GNUNET_GC_parse_configuration (basecfg, base_config))
        {
          ret = GNUNET_SYSERR;
          break;
        }

      GNUNET_GC_set_configuration_value_string (basecfg, NULL, "NETWORK",
                                                "TRUSTED", control_host);
      GNUNET_GC_set_configuration_value_string (basecfg, NULL, "PATHS",
                                                "GNUNETD_HOME",
                                                remote_config_path);
      GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                "MULTIPLE_SERVER_TESTING",
                                                "MYSQL_SERVER", mysql_server);
      GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                "MULTIPLE_SERVER_TESTING",
                                                "MYSQL_DB", mysql_db);
      GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                "MULTIPLE_SERVER_TESTING",
                                                "MYSQL_USER", mysql_user);
      GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                "MULTIPLE_SERVER_TESTING",
                                                "MYSQL_PASSWORD",
                                                mysql_password);
      GNUNET_GC_set_configuration_value_number (basecfg, NULL,
                                                "MULTIPLE_SERVER_TESTING",
                                                "MYSQL_PORT", mysql_port);
      GNUNET_GC_set_configuration_value_number (basecfg, NULL,
                                                "LOAD",
                                                "MAXNETDOWNBPSTOTAL",
                                                maxnetbps);
      GNUNET_GC_set_configuration_value_number (basecfg, NULL, "LOAD",
                                                "MAXNETUPBPSTOTAL",
                                                maxnetbps);

      while (hostnames[pos] != ' ' && pos > 0)
        pos--;
      if (pos != 0)
        {
          hostnames[pos] = '\0';
          curr_host = &hostnames[pos + 1];
        }
      else
        {
          curr_host = &hostnames[pos];
        }

      for (j = 0; j < daemons_per_machine; ++j)
        {
          malicious_mask = 0;
          /*
           * Indicates that this node should be set as a malicious getter
           */
          if ((malicious_getters > 0)
              && ((((count_started + 1) % (int) malicious_getter_num) == 0)))
            {
              GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                        "DHT",
                                                        "MALICIOUS_GETTER",
                                                        "YES");

              if (malicious_get_frequency > 0)
                {
                  GNUNET_GC_set_configuration_value_number (basecfg, NULL,
                                                            "DHT",
                                                            "MALICIOUS_GET_FREQUENCY",
                                                            malicious_get_frequency);

                }
              malicious_mask |= GET_MASK;
            }
          else
            {
              GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                        "DHT",
                                                        "MALICIOUS_GETTER",
                                                        "NO");
            }

          /*
           * Indicates that this node should be set as a malicious putter
           */
          if ((malicious_putters > 0)
              && ((((count_started + 1) % (int) malicious_putter_num) == 0)))
            {
              GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                        "DHT",
                                                        "MALICIOUS_PUTTER",
                                                        "YES");
              if (malicious_put_frequency > 0)
                {
                  GNUNET_GC_set_configuration_value_number (basecfg, NULL,
                                                            "DHT",
                                                            "MALICIOUS_PUT_FREQUENCY",
                                                            malicious_put_frequency);

                }
              malicious_mask |= PUT_MASK;
            }
          else
            {
              GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                        "DHT",
                                                        "MALICIOUS_PUTTER",
                                                        "NO");
            }

          /*
           * Indicates that this node should be set as a malicious dropper
           */
          if ((malicious_droppers > 0)
              && ((((count_started + 1) % (int) malicious_dropper_num) == 0)))
            {
              GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                        "DHT",
                                                        "MALICIOUS_DROPPER",
                                                        "YES");
              malicious_mask |= DROP_MASK;
            }
          else
            {
              GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                        "DHT",
                                                        "MALICIOUS_DROPPER",
                                                        "NO");
            }

          length_temp =
            snprintf (NULL, 0, "%s%s%d", remote_pid_path, "pid", j);
          temp_pid_file = GNUNET_malloc (length_temp + 1);
          GNUNET_snprintf (temp_pid_file, length_temp + 1, "%s%s%d",
                           remote_pid_path, "pid", j);

          GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                    "GNUNETD", "PIDFILE",
                                                    temp_pid_file);



          temp_remote_config_path_length =
            snprintf (NULL, 0, "%s%d", remote_config_path, j);
          temp_remote_config_path =
            GNUNET_malloc (temp_remote_config_path_length + 1);
          snprintf (temp_remote_config_path,
                    temp_remote_config_path_length + 1, "%s%d",
                    remote_config_path, j);

          GNUNET_GC_set_configuration_value_string (basecfg, NULL, "PATHS",
                                                    "GNUNETD_HOME",
                                                    temp_remote_config_path);

          temp_host_string_length =
            snprintf (NULL, 0, "%s:%llu", curr_host,
                      starting_port +
                      ((unsigned long long) j * port_increment));
          temp_host_string = GNUNET_malloc (temp_host_string_length + 1);
          snprintf (temp_host_string,
                    temp_host_string_length + 1, "%s:%llu", curr_host,
                    starting_port +
                    ((unsigned long long) j * port_increment));

          GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                    "NETWORK",
                                                    "HOST", temp_host_string);

          GNUNET_GC_set_configuration_value_number (basecfg, NULL, "NETWORK",
                                                    "PORT",
                                                    starting_port +
                                                    (j * port_increment));
          GNUNET_GC_set_configuration_value_number (basecfg, NULL, "TCP",
                                                    "PORT",
                                                    starting_port +
                                                    (j * port_increment) + 1);
          GNUNET_GC_set_configuration_value_number (basecfg, NULL, "UDP",
                                                    "PORT",
                                                    starting_port +
                                                    (j * port_increment) + 1);

          temp_path = GNUNET_strdup ("/tmp/gnunetd.conf.XXXXXX");
          ret = mkstemp (temp_path);

          if (ret == -1)
            {
              GNUNET_GE_LOG_STRERROR_FILE (NULL,
                                           GNUNET_GE_ERROR |
                                           GNUNET_GE_USER |
                                           GNUNET_GE_BULK, "mkstemp",
                                           temp_path);
              GNUNET_free (temp_path);
              GNUNET_free (temp_remote_config_path);
              GNUNET_free (temp_host_string);
              GNUNET_free (temp_pid_file);
              break;
            }
          CLOSE (ret);
          if (0 != GNUNET_GC_write_configuration (basecfg, temp_path))
            {
              GNUNET_free (temp_path);
              GNUNET_free (temp_remote_config_path);
              GNUNET_free (temp_host_string);
              GNUNET_free (temp_pid_file);
              break;
            }

          temp = GNUNET_malloc (32);
          if (1 == sscanf (temp_path, "/tmp/%s", temp))
            {
              temp_pos =
                GNUNET_malloc (sizeof (struct GNUNET_REMOTE_host_list));
              temp_pos->hostname = GNUNET_strdup (curr_host);
              temp_pos->username = GNUNET_strdup (ssh_username);
              friend_location_length =
                snprintf (NULL, 0, "%s/friends", temp_remote_config_path);
              temp_pos->remote_friend_file_path =
                GNUNET_malloc (friend_location_length + 1);
              snprintf (temp_pos->remote_friend_file_path,
                        friend_location_length + 1, "%s/friends",
                        temp_remote_config_path);

              GNUNET_REMOTE_start_daemon (remote_gnunetd_path, "/tmp/",
                                          temp, remote_config_path,
                                          curr_host, ssh_username,
                                          temp_pos->remote_friend_file_path,
                                          prepend_exec);
              GNUNET_thread_sleep (500 * GNUNET_CRON_MILLISECONDS);
              next_peer =
                GNUNET_malloc (sizeof
                               (struct GNUNET_REMOTE_TESTING_DaemonContext));
              next_peer->next = new_ret_peers;
              next_peer->hostname = GNUNET_strdup (curr_host);
              next_peer->path = GNUNET_strdup (temp_path);
              next_peer->username = GNUNET_strdup (ssh_username);
              next_peer->port = starting_port + (j * port_increment);
              next_peer->pid = GNUNET_strdup (temp_pid_file);
              next_peer->malicious_val = malicious_mask;
              tempcfg = GNUNET_GC_create ();
              GNUNET_snprintf (host, 128, "%s:%u", next_peer->hostname,
                               next_peer->port);
              GNUNET_GC_set_configuration_value_string (tempcfg, NULL,
                                                        "NETWORK", "HOST",
                                                        host);
              next_peer->config = tempcfg;
              next_peer->peer =
                GNUNET_REMOTE_get_daemon_information (next_peer->hostname,
                                                      next_peer->port);

              new_ret_peers = next_peer;

              GNUNET_GC_get_configuration_value_number (basecfg,
                                                        "NETWORK",
                                                        "PORT",
                                                        0, 65535, 65535,
                                                        &temp_port);
              temp_pos->port = (unsigned short) temp_port;
              temp_pos->next = head;
              temp_pos->pid = get_pid (new_ret_peers);
              temp_pos->peer =
                GNUNET_REMOTE_get_daemon_information (next_peer->hostname,
                                                      next_peer->port);
              head = temp_pos;
              array_of_pointers[count_started] = temp_pos;
              if (count_started % modnum == 0)
                {
                  if (count_started == 0)
                    fprintf (stdout, "0%%");
                  else
                    fprintf (stdout, "%d%%",
                             (int) (((float) (count_started + 1) /
                                     number_of_daemons) * 100));

                }
              else if (count_started % dotnum == 0)
                {
                  fprintf (stdout, ".");
                }
              fflush (stdout);
              count_started++;
            }
          GNUNET_free (temp_pid_file);
          GNUNET_free (temp_remote_config_path);
          GNUNET_free (temp);
          GNUNET_free (temp_host_string);
          //UNLINK (temp_path);
          GNUNET_free (temp_path);

          if ((i < extra_daemons) && (j == daemons_per_machine - 1))
            {
              malicious_mask = 0;
              basecfg = GNUNET_GC_create ();

              if (-1 == GNUNET_GC_parse_configuration (basecfg, base_config))
                {
                  ret = GNUNET_SYSERR;
                  break;
                }

              /*
               * Indicates that this node should be set as a malicious getter
               */
              if ((malicious_getters > 0)
                  &&
                  ((((count_started + 1) % (int) malicious_getter_num) == 0)))
                {
                  GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                            "DHT",
                                                            "MALICIOUS_GETTER",
                                                            "YES");
                  if (malicious_get_frequency > 0)
                    {
                      GNUNET_GC_set_configuration_value_number (basecfg, NULL,
                                                                "DHT",
                                                                "MALICIOUS_GET_FREQUENCY",
                                                                malicious_get_frequency);

                    }
                  malicious_mask |= GET_MASK;
                }
              else
                {
                  GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                            "DHT",
                                                            "MALICIOUS_GETTER",
                                                            "NO");
                }

              /*
               * Indicates that this node should be set as a malicious putter
               */
              if ((malicious_putters > 0)
                  &&
                  ((((count_started + 1) % (int) malicious_putter_num) == 0)))
                {
                  GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                            "DHT",
                                                            "MALICIOUS_PUTTER",
                                                            "YES");
                  if (malicious_put_frequency > 0)
                    {
                      GNUNET_GC_set_configuration_value_number (basecfg, NULL,
                                                                "DHT",
                                                                "MALICIOUS_PUT_FREQUENCY",
                                                                malicious_put_frequency);

                    }
                  malicious_mask |= PUT_MASK;
                }
              else
                {
                  GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                            "DHT",
                                                            "MALICIOUS_PUTTER",
                                                            "NO");
                }

              /*
               * Indicates that this node should be set as a malicious dropper
               */
              if ((malicious_droppers > 0)
                  &&
                  ((((count_started + 1) % (int) malicious_dropper_num) ==
                    0)))
                {
                  GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                            "DHT",
                                                            "MALICIOUS_DROPPER",
                                                            "YES");
                  malicious_mask |= DROP_MASK;
                }
              else
                {
                  GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                            "DHT",
                                                            "MALICIOUS_DROPPER",
                                                            "NO");
                }

              GNUNET_GC_set_configuration_value_number (basecfg, NULL,
                                                        "NETWORK", "PORT",
                                                        starting_port);
              GNUNET_GC_set_configuration_value_number (basecfg, NULL, "TCP",
                                                        "PORT",
                                                        starting_port + 1);
              GNUNET_GC_set_configuration_value_number (basecfg, NULL, "UDP",
                                                        "PORT",
                                                        starting_port + 1);
              GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                        "NETWORK", "TRUSTED",
                                                        control_host);
              GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                        "PATHS",
                                                        "GNUNETD_HOME",
                                                        remote_config_path);

              GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                        "MULTIPLE_SERVER_TESTING",
                                                        "MYSQL_SERVER",
                                                        mysql_server);
              GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                        "MULTIPLE_SERVER_TESTING",
                                                        "MYSQL_DB", mysql_db);
              GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                        "MULTIPLE_SERVER_TESTING",
                                                        "MYSQL_USER",
                                                        mysql_user);
              GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                        "MULTIPLE_SERVER_TESTING",
                                                        "MYSQL_PASSWORD",
                                                        mysql_password);
              GNUNET_GC_set_configuration_value_number (basecfg, NULL,
                                                        "MULTIPLE_SERVER_TESTING",
                                                        "MYSQL_PORT",
                                                        mysql_port);
              GNUNET_GC_set_configuration_value_number (basecfg, NULL,
                                                        "LOAD",
                                                        "MAXNETDOWNBPSTOTAL",
                                                        maxnetbps);
              GNUNET_GC_set_configuration_value_number (basecfg, NULL, "LOAD",
                                                        "MAXNETUPBPSTOTAL",
                                                        maxnetbps);
              length_temp =
                snprintf (NULL, 0, "%s%s%d", remote_pid_path, "pid", j + 1);
              temp_pid_file = GNUNET_malloc (length_temp + 1);
              snprintf (temp_pid_file, length_temp + 1, "%s%s%d",
                        remote_pid_path, "pid", j + 1);

              GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                        "GNUNETD",
                                                        "PIDFILE",
                                                        temp_pid_file);

              temp_remote_config_path_length =
                snprintf (NULL, 0, "%s%d", remote_config_path, j + 1);
              temp_remote_config_path =
                GNUNET_malloc (temp_remote_config_path_length + 1);
              snprintf (temp_remote_config_path,
                        temp_remote_config_path_length + 1, "%s%d",
                        remote_config_path, j + 1);

              GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                        "PATHS",
                                                        "GNUNETD_HOME",
                                                        temp_remote_config_path);



              GNUNET_GC_set_configuration_value_number (basecfg, NULL,
                                                        "NETWORK", "PORT",
                                                        starting_port +
                                                        ((j +
                                                          1) *
                                                         port_increment));

              temp_host_string_length =
                snprintf (NULL, 0, "%s:%llu", curr_host,
                          starting_port +
                          ((unsigned long long) (j + 1) * port_increment));
              temp_host_string = GNUNET_malloc (temp_host_string_length + 1);
              snprintf (temp_host_string, temp_host_string_length + 1,
                        "%s:%llu", curr_host,
                        starting_port +
                        ((unsigned long long) (j + 1) * port_increment));

              GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                        "NETWORK",
                                                        "HOST",
                                                        temp_host_string);

              GNUNET_GC_set_configuration_value_number (basecfg, NULL, "TCP",
                                                        "PORT",
                                                        starting_port +
                                                        ((j +
                                                          1) *
                                                         port_increment) + 1);
              GNUNET_GC_set_configuration_value_number (basecfg, NULL, "UDP",
                                                        "PORT",
                                                        starting_port +
                                                        ((j +
                                                          1) *
                                                         port_increment) + 1);

              temp_path = GNUNET_strdup ("/tmp/gnunetd.conf.XXXXXX");
              ret = mkstemp (temp_path);

              if (ret == -1)
                {
                  GNUNET_GE_LOG_STRERROR_FILE (NULL,
                                               GNUNET_GE_ERROR |
                                               GNUNET_GE_USER |
                                               GNUNET_GE_BULK, "mkstemp",
                                               temp_path);
                  GNUNET_free (temp_pid_file);
                  GNUNET_free (temp_path);
                  GNUNET_free (temp_remote_config_path);
                  GNUNET_free (temp_host_string);
                  break;
                }
              CLOSE (ret);
              if (0 != GNUNET_GC_write_configuration (basecfg, temp_path))
                {
                  GNUNET_free (temp_pid_file);
                  GNUNET_free (temp_path);
                  GNUNET_free (temp_remote_config_path);
                  GNUNET_free (temp_host_string);
                  break;
                }

              temp = GNUNET_malloc (32);
              if (1 == sscanf (temp_path, "/tmp/%s", temp))
                {
                  temp_pos =
                    GNUNET_malloc (sizeof (struct GNUNET_REMOTE_host_list));
                  temp_pos->hostname = GNUNET_strdup (curr_host);
                  temp_pos->username = GNUNET_strdup (ssh_username);
                  friend_location_length =
                    snprintf (NULL, 0, "%s/friends", temp_remote_config_path);
                  temp_pos->remote_friend_file_path =
                    GNUNET_malloc (friend_location_length + 1);
                  GNUNET_snprintf (temp_pos->remote_friend_file_path,
                                   friend_location_length + 1,
                                   "%s/friends", temp_remote_config_path);
                  GNUNET_REMOTE_start_daemon (remote_gnunetd_path, "/tmp/",
                                              temp, remote_config_path,
                                              curr_host, ssh_username,
                                              temp_pos->
                                              remote_friend_file_path,
                                              prepend_exec);
                  GNUNET_thread_sleep (500 * GNUNET_CRON_MILLISECONDS);
                  next_peer =
                    GNUNET_malloc (sizeof
                                   (struct
                                    GNUNET_REMOTE_TESTING_DaemonContext));
                  next_peer->next = new_ret_peers;
                  next_peer->hostname = GNUNET_strdup (curr_host);
                  next_peer->port =
                    starting_port + ((j + 1) * port_increment);
                  next_peer->path = GNUNET_strdup (temp_path);
                  next_peer->username = GNUNET_strdup (ssh_username);
                  next_peer->pid = GNUNET_strdup (temp_pid_file);
                  next_peer->malicious_val = malicious_mask;
                  tempcfg = GNUNET_GC_create ();
                  GNUNET_snprintf (host, 128, "%s:%u", next_peer->hostname,
                                   next_peer->port);
                  GNUNET_GC_set_configuration_value_string (tempcfg, NULL,
                                                            "NETWORK", "HOST",
                                                            host);
                  next_peer->config = tempcfg;
                  next_peer->peer =
                    GNUNET_REMOTE_get_daemon_information (next_peer->hostname,
                                                          next_peer->port);
                  new_ret_peers = next_peer;

                  GNUNET_GC_get_configuration_value_number (basecfg,
                                                            "NETWORK",
                                                            "PORT",
                                                            0, 65535, 65535,
                                                            &temp_port);

                  temp_pos->port = (unsigned short) temp_port;
                  temp_pos->next = head;
                  temp_pos->pid = get_pid (new_ret_peers);
                  temp_pos->peer =
                    GNUNET_REMOTE_get_daemon_information (next_peer->hostname,
                                                          next_peer->port);
                  head = temp_pos;
                  array_of_pointers[count_started] = temp_pos;
                  if (count_started % modnum == 0)
                    {
                      if (count_started == 0)
                        fprintf (stdout, "0%%");
                      else
                        fprintf (stdout, "%d%%",
                                 (int) (((float) (count_started + 1) /
                                         number_of_daemons) * 100));

                    }
                  else if (count_started % dotnum == 0)
                    {
                      fprintf (stdout, ".");
                    }
                  fflush (stdout);
                  count_started++;
                }

              GNUNET_free (temp_pid_file);
              GNUNET_free (temp_remote_config_path);
              GNUNET_free (temp_host_string);
              //UNLINK (temp_path);
              GNUNET_free (temp_path);
              GNUNET_free (temp);
            }
        }
      GNUNET_GC_free (basecfg);
      ++i;
    }

  fprintf (stdout, "%d%%]\n",
           (int) (((float) count_started / number_of_daemons) * 100));
  ret =
    GNUNET_REMOTE_create_topology (type_of_topology, number_of_daemons,
                                   dotOutFile, percentage, logNModifier);
  if (dotOutFile != NULL)
    {
      fprintf (dotOutFile, "}\n");
      fclose (dotOutFile);
    }

  GNUNET_free (dotOutFileName);
  GNUNET_free (percentage_string);
  GNUNET_free (base_config);
  GNUNET_free (remote_pid_path);
  GNUNET_free (data_dir);
  GNUNET_free (ssh_username);
  GNUNET_free (control_host);
  GNUNET_free (hostnames);
  GNUNET_free (remote_config_path);
  GNUNET_free (remote_gnunetd_path);
  GNUNET_free (mysql_user);
  GNUNET_free (mysql_db);
  GNUNET_free (mysql_password);
  GNUNET_free (mysql_server);
  GNUNET_free (logNModifier_string);
  *ret_peers = new_ret_peers;
  return ret;
}

static void *
connect_peer_thread (void *cls)
{
  struct GNUNET_REMOTE_host_list *pos = cls;
  struct GNUNET_REMOTE_friends_list *friend_pos;
  struct ConnectedEntry *tempEntry;
  struct ConnectedEntry *tempFriendEntry;
  struct ConnectedEntry *tempEntryPos;

  int ret;
  int pid1;
  int pid2;
  int match;

  tempEntry = NULL;
  tempFriendEntry = NULL;
  pid1 = 0;
  pid2 = 0;
  GNUNET_mutex_lock (connectMutex);
#if VERBOSE
  fprintf (stdout, "Starting thread %d\n", threadCount);
#endif
  threadCount++;
  GNUNET_mutex_unlock (connectMutex);
  friend_pos = pos->friend_entries;
  while (friend_pos != NULL)
    {
      GNUNET_mutex_lock (connectMutex);
      match = GNUNET_NO;
      if (GNUNET_YES ==
          GNUNET_multi_hash_map_contains (connected, &pos->peer->hashPubKey))
        {
          tempEntryPos =
            GNUNET_multi_hash_map_get (connected, &pos->peer->hashPubKey);
          while (tempEntryPos != NULL)
            {
              if (memcmp
                  (&tempEntryPos->key,
                   &friend_pos->hostentry->peer->hashPubKey,
                   sizeof (GNUNET_HashCode)) == 0)
                match = GNUNET_YES;

              tempEntryPos = tempEntryPos->next;
            }
        }
      GNUNET_mutex_unlock (connectMutex);

      pid1 = pos->pid;
      pid2 = friend_pos->hostentry->pid;

      if (match == GNUNET_YES)
        {
#if VERBOSE
          fprintf (stderr,
                   _
                   ("NOT connecting peer %s:%d pid=%d to peer %s:%d pid=%d (already connected!)\n"),
                   pos->hostname, pos->port, pid1,
                   friend_pos->hostentry->hostname,
                   friend_pos->hostentry->port, pid2);
#endif
          friend_pos = friend_pos->next;
          continue;
        }

#if VERBOSE
      fprintf (stderr,
               _
               ("connecting peer %s:%d pid=%d to peer %s:%d pid=%d\n"),
               pos->hostname, pos->port, pid1,
               friend_pos->hostentry->hostname,
               friend_pos->hostentry->port, pid2);
#endif
      ret = GNUNET_REMOTE_connect_daemons (pos->hostname, pos->port,
                                           friend_pos->hostentry->
                                           hostname,
                                           friend_pos->hostentry->
                                           port, globalDotFile);
      if (ret != GNUNET_OK)
        {
          GNUNET_mutex_lock (connectMutex);
          connectFailures++;
          GNUNET_mutex_unlock (connectMutex);
        }
      if (connectFailures > totalConnections / 2)
        break;

      if (ret == GNUNET_OK)
        {
          GNUNET_mutex_lock (connectMutex);
          tempEntryPos = GNUNET_malloc (sizeof (struct ConnectedEntry));
          memcpy (&tempEntryPos->key,
                  &friend_pos->hostentry->peer->hashPubKey,
                  sizeof (GNUNET_HashCode));
          tempEntryPos->next = tempEntry;
          GNUNET_multi_hash_map_put (connected, &pos->peer->hashPubKey,
                                     tempEntryPos,
                                     GNUNET_MultiHashMapOption_REPLACE);

          tempFriendEntry =
            GNUNET_multi_hash_map_get (connected,
                                       &friend_pos->hostentry->peer->
                                       hashPubKey);
          tempEntryPos = GNUNET_malloc (sizeof (struct ConnectedEntry));
          memcpy (&tempEntryPos->key, &pos->peer->hashPubKey,
                  sizeof (GNUNET_HashCode));
          tempEntryPos->next = tempFriendEntry;
          GNUNET_multi_hash_map_put (connected,
                                     &friend_pos->hostentry->peer->hashPubKey,
                                     tempEntryPos,
                                     GNUNET_MultiHashMapOption_REPLACE);
          GNUNET_mutex_unlock (connectMutex);
        }

      friend_pos = friend_pos->next;
    }

  GNUNET_mutex_lock (connectMutex);
  threadCount--;
#if VERBOSE
  fprintf (stdout, "Exiting thread %d\n", threadCount);
#endif
  GNUNET_mutex_unlock (connectMutex);

  return NULL;
}

int
GNUNET_REMOTE_create_topology (GNUNET_REMOTE_TOPOLOGIES type,
                               int number_of_daemons, FILE * dotOutFile,
                               double percentage, double logNModifier)
{
  FILE *temp_friend_handle;
  int ret;
  struct GNUNET_REMOTE_host_list *pos;
  struct GNUNET_REMOTE_friends_list *friend_pos;
  struct GNUNET_ThreadHandle *threads[MAX_CONNECT_THREADS];
  int unused;
  char *cmd;
  int length;
  int tempThreadCount;
  int i;
  int j;
  unsigned int totalConnections;
  unsigned int totalConnectAttempts;
  unsigned int totalCreatedConnections;
  unsigned int *daemon_list;
  unsigned int modnum;
  unsigned int dotnum;
  void *unusedVoid;
  globalDotFile = dotOutFile;
  ret = GNUNET_OK;
  connected = GNUNET_multi_hash_map_create (number_of_daemons * 3);

  daemon_list =
    GNUNET_permute (GNUNET_RANDOM_QUALITY_WEAK, number_of_daemons);
  switch (type)
    {
    case GNUNET_REMOTE_CLIQUE:
      fprintf (stderr, _("Creating clique topology (may take a bit!)\n"));
      ret =
        GNUNET_REMOTE_connect_clique (&totalConnections, head, dotOutFile);
      break;
    case GNUNET_REMOTE_SMALL_WORLD:
      fprintf (stderr,
               _("Creating small world topology (may take a bit!)\n"));
      ret =
        GNUNET_REMOTE_connect_small_world_ring (&totalConnections,
                                                number_of_daemons,
                                                list_as_array, dotOutFile,
                                                percentage, logNModifier);
      break;
    case GNUNET_REMOTE_RING:
      fprintf (stderr, _("Creating ring topology (may take a bit!)\n"));
      ret = GNUNET_REMOTE_connect_ring (&totalConnections, head, dotOutFile);
      break;
    case GNUNET_REMOTE_2D_TORUS:
      fprintf (stderr, _("Creating 2d torus topology (may take a bit!)\n"));
      ret =
        GNUNET_REMOTE_connect_2d_torus (&totalConnections, number_of_daemons,
                                        list_as_array, dotOutFile);
      break;
    case GNUNET_REMOTE_ERDOS_RENYI:
      fprintf (stderr,
               _("Creating Erdos-Renyi topology (may take a bit!)\n"));
      ret =
        GNUNET_REMOTE_connect_erdos_renyi (&totalConnections, percentage,
                                           head, dotOutFile);
      break;
    case GNUNET_REMOTE_INTERNAT:
      fprintf (stderr, _("Creating InterNAT topology (may take a bit!)\n"));
      ret =
        GNUNET_REMOTE_connect_nated_internet (&totalConnections, percentage,
                                              number_of_daemons, head,
                                              dotOutFile);
      break;
    case GNUNET_REMOTE_NONE:
      GNUNET_free (daemon_list);
      return ret;
      break;
    default:
      ret = GNUNET_SYSERR;
      break;
    }
  totalCreatedConnections = 0;
  totalConnectAttempts = 0;
  if (totalConnections < 1)
    return 0;

  modnum = ceil(totalConnections / 4);
  dotnum = ceil(totalConnections / 50);
  if (dotnum == 0)
  	dotnum = 1;
  if (ret == GNUNET_OK)
    {
      pos = head;
      fprintf (stdout, "Friend file creation progress: \[");
      while (pos != NULL)
        {
          /* Printing out the friends isn't necessary, but it's nice */
#if VERBOSE
          fprintf (stderr, _("Friend list of %s:%d\n"), pos->hostname,
                   pos->port);
#endif
          temp_friend_handle = fopen ("friend.temp", "wt");
          friend_pos = pos->friend_entries;
          while (friend_pos != NULL)
            {
#if VERBOSE
              fprintf (stderr, "\t%s\n", (const char *) friend_pos->nodeid);
#endif
              fprintf (temp_friend_handle, "%s\n",
                       (const char *) friend_pos->nodeid);
              friend_pos = friend_pos->next;

              if (totalCreatedConnections % modnum == 0)
                {
                  if (totalCreatedConnections == 0)
                    fprintf (stdout, "0%%");
                  else
                    fprintf (stdout, "%d%%",
                             (int) (((float) totalCreatedConnections /
                                     totalConnections) * 100));

                }
              else if (totalCreatedConnections % dotnum == 0)
                {
                  fprintf (stdout, ".");
                }
              fflush (stdout);
              totalCreatedConnections++;
            }

          fclose (temp_friend_handle);
          if (strcmp (pos->hostname, "localhost") == 0)
            {
              length =
                snprintf (NULL, 0, "cp %s %s > /dev/null 2>&1", "friend.temp",
                          pos->remote_friend_file_path);
              cmd = GNUNET_malloc (length + 1);
              snprintf (cmd, length + 1, "cp %s %s > /dev/null 2>&1",
                        "friend.temp", pos->remote_friend_file_path);
            }
          else
            {
              length =
                snprintf (NULL, 0, "scp %s %s@%s:%s > /dev/null 2>&1",
                          "friend.temp", pos->username, pos->hostname,
                          pos->remote_friend_file_path);
              cmd = GNUNET_malloc (length + 1);
              snprintf (cmd, length + 1, "scp %s %s@%s:%s > /dev/null 2>&1",
                        "friend.temp", pos->username, pos->hostname,
                        pos->remote_friend_file_path);
            }
#if VERBOSE
          fprintf (stderr, _("scp command for friend file copy is : %s \n"),
                   cmd);
#endif
          unused = system (cmd);
          GNUNET_free (cmd);
          pos = pos->next;
        }
      fprintf (stdout, "%d%%]\n",
               (int) (((float) totalCreatedConnections / totalConnections) *
                      100));
      unused = system ("rm friend.temp");
      pos = head;

      connectMutex = GNUNET_mutex_create (GNUNET_YES);
      connectFailures = 0;
      tempThreadCount = 0;
      modnum = number_of_daemons / 4;
      dotnum = ceil(number_of_daemons / 50);
      if (dotnum == 0)
      	dotnum = 1;
      fprintf (stdout, "Friend connection progress: \[");
      for (j = 0; j < number_of_daemons; j++)
        {
          if (tempThreadCount >= MAX_CONNECT_THREADS)
            {
              for (i = 0; i < tempThreadCount; i++)
                {
#if VERBOSE
                  fprintf (stdout, "Joining thread %d...\n", i);
#endif
                  GNUNET_thread_join (threads[i], &unusedVoid);
                }
              tempThreadCount = 0;
            }
#if VERBOSE
          fprintf (stdout, "Creating real thread %d...\n", tempThreadCount);
#endif
          threads[tempThreadCount] =
            GNUNET_thread_create (&connect_peer_thread,
                                  list_as_array[daemon_list[j]], 1024 * 16);
          tempThreadCount++;
          if (totalConnectAttempts % modnum == 0)
            {
              if (totalConnectAttempts == 0)
                fprintf (stdout, "0%%");
              else
                fprintf (stdout, "%d%%",
                         (int) (((float) totalConnectAttempts /
                                 number_of_daemons) * 100));

            }
          else if (totalConnectAttempts % dotnum == 0)
            {
              fprintf (stdout, ".");
            }
          fflush (stdout);
          totalConnectAttempts++;
        }
      fprintf (stdout, "%d%%]\n",
               (int) (((float) totalConnectAttempts / number_of_daemons) *
                      100));
      GNUNET_thread_sleep (2000 * GNUNET_CRON_MILLISECONDS);
      for (i = 0; i < tempThreadCount; i++)
        {
#if VERBOSE
          fprintf (stdout, "Joining thread %d...\n", i);
#endif
          GNUNET_thread_stop_sleep (threads[i]);
          GNUNET_thread_join (threads[i], &unusedVoid);

        }
      GNUNET_mutex_destroy (connectMutex);
    }
  else
    {
#if VERBOSE
      fprintf (stderr, _("connect didn't return well!\n"));
#endif
    }

#if VERBOSE
  fprintf (stderr, _("Total connections: %d!\n"), totalCreatedConnections);
  fprintf (stderr, _("Total failed connections: %d!\n"), connectFailures);
#endif

  GNUNET_multi_hash_map_destroy (connected);
  if (ret != GNUNET_OK)
    return ret;
  else
    {
      GNUNET_free (daemon_list);
      return totalCreatedConnections;
    }
}

/* end of remote.c */
