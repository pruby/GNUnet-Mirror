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

#define VERBOSE GNUNET_NO

/* Yes this is ugly, but for now it is nice to
 * have a linked list and an array
 */
static struct GNUNET_REMOTE_host_list *head;
static struct GNUNET_REMOTE_host_list **list_as_array;

/**
 * Starts a single gnunet daemon on a remote machine
 *
 * @param gnunetd_home directory where gnunetd is on remote machine
 * @param localConfigPath local configuration path for config file
 * @param remote_config_path remote path to copy local config to
 * @param configFileName  file to copy and use on remote machine
 * @param ip_address ip address of remote machine
 * @param username username to use for ssh (assumed to be used with ssh-agent)
 */
int
GNUNET_REMOTE_start_daemon (char *gnunetd_home,
                            char *localConfigPath, char *configFileName,
                            char *remote_config_path, char *hostname,
                            char *username, char *remote_friend_file_path)
{
  char *cmd;
  int length;

  length =
    snprintf (NULL, 0, "scp %s%s %s@%s:%s", localConfigPath, configFileName,
              username, hostname, remote_config_path);
  cmd = GNUNET_malloc (length + 1);
  snprintf (cmd, length + 1, "scp %s%s %s@%s:%s", localConfigPath,
            configFileName, username, hostname, remote_config_path);

  /* To me this seems like information that will always be appreciated by the user
   * if this is contested by anyone, please mark it here as well as how it should be
   * done, and I can change it everywhere else by example! NE
   */
  fprintf (stderr, _("scp command is : %s \n"), cmd);
  system (cmd);

  GNUNET_free (cmd);

  length =
    snprintf (NULL, 0, "ssh %s@%s %sgnunetd -c %s%s", username, hostname,
              gnunetd_home, remote_config_path, configFileName);
  cmd = GNUNET_malloc (length + 1);
  snprintf (cmd, length + 1, "ssh %s@%s %sgnunetd -c %s%s", username,
            hostname, gnunetd_home, remote_config_path, configFileName);

  fprintf (stderr, "ssh command is : %s \n", cmd);

  system (cmd);

  GNUNET_free (cmd);


  return GNUNET_OK;
}

int
GNUNET_REMOTE_start_daemons (struct GNUNET_GC_Configuration *newcfg,
                             unsigned long long number_of_daemons)
{
  struct GNUNET_GC_Configuration *basecfg;
  struct GNUNET_REMOTE_host_list *array_of_pointers[number_of_daemons];
  struct GNUNET_REMOTE_host_list *temp_pos;
  GNUNET_REMOTE_TOPOLOGIES type_of_topology;
  list_as_array = &array_of_pointers[0];


  char *ssh_username;
  char *control_host;
  char *remote_config_path;
  char *remote_gnunetd_path;
  char *remote_pid_path;
  char *base_config;
  char *data_dir;
  char *hostnames;
  char *temp;
  char *temp_path;
  char *temp_pid_file;
  char *curr_host;
  char *temp_remote_config_path;

  unsigned long long starting_port;
  unsigned long long port_increment;
  unsigned long long daemons_per_machine;
  unsigned long long temp_port;
  unsigned long long topology;



  unsigned int extra_daemons;
  unsigned int count;
  unsigned int count_started;
  unsigned int length;
  unsigned int length_temp;
  unsigned int num_machines;
  unsigned int i;
  unsigned int j;
  unsigned int pos;
  int temp_remote_config_path_length;
  int friend_location_length;
  int ret;
  char *ipk_dir;

  length = 0;
  ipk_dir = GNUNET_get_installation_path (GNUNET_IPK_DATADIR);
  if (ipk_dir == NULL)
    {
      ipk_dir = GNUNET_malloc (1);
      strcpy (ipk_dir, "");
    }
  length = snprintf (NULL, 0, "%s%s", ipk_dir, "gnunetd.conf.skel");
  data_dir = GNUNET_malloc (length + 1);
  snprintf (data_dir, length + 1, "%s%s", ipk_dir, "gnunetd.conf.skel");
  GNUNET_free (ipk_dir);
  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "SSH_USERNAME", "",
                                            &ssh_username);
  GNUNET_GC_get_configuration_value_number (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "TOPOLOGY", 0, -1, 0, &topology);
  type_of_topology = (unsigned int) topology;
  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "CONTROL_HOST", "localhost",
                                            &control_host);
  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "HOSTNAMES", "localhost",
                                            &hostnames);
  GNUNET_GC_get_configuration_value_number (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "STARTING_PORT",
                                            1, -1, 1, &starting_port);
  GNUNET_GC_get_configuration_value_number (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "PORT_INCREMENT",
                                            1, -1, 2, &port_increment);
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

  length = strlen (hostnames);
  num_machines = 1;
  for (count = 0; count < length; count++)
    if (hostnames[count] == ' ')
      ++num_machines;

  daemons_per_machine = number_of_daemons / num_machines;
  extra_daemons = number_of_daemons - (daemons_per_machine * num_machines);

  i = 0;
  count_started = 0;
  pos = length;
  while (i < num_machines)
    {
      basecfg = GNUNET_GC_create ();

      if (-1 == GNUNET_GC_parse_configuration (basecfg, base_config))
        {
          ret = GNUNET_SYSERR;
          break;
        }

      GNUNET_GC_set_configuration_value_number (basecfg, NULL, "NETWORK",
                                                "PORT", starting_port);
      GNUNET_GC_set_configuration_value_number (basecfg, NULL, "TCP",
                                                "PORT", starting_port + 1);
      GNUNET_GC_set_configuration_value_number (basecfg, NULL, "UDP",
                                                "PORT", starting_port + 1);
      GNUNET_GC_set_configuration_value_string (basecfg, NULL, "NETWORK",
                                                "TRUSTED", control_host);
      GNUNET_GC_set_configuration_value_string (basecfg, NULL, "PATHS",
                                                "GNUNETD_HOME",
                                                remote_config_path);

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
          length_temp =
            snprintf (NULL, 0, "%s%s%d", remote_pid_path, "pid", j);
          temp_pid_file = GNUNET_malloc (length_temp + 1);
          snprintf (temp_pid_file, length_temp + 1, "%s%s%d", remote_pid_path,
                    "pid", j);

          GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                    "GNUNETD", "PIDFILE",
                                                    temp_pid_file);

          GNUNET_free (temp_pid_file);

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
              break;
            }
          CLOSE (ret);
          if (0 != GNUNET_GC_write_configuration (basecfg, temp_path))
            {
              GNUNET_free (temp_path);
              GNUNET_free (temp_remote_config_path);
              break;
            }

          temp = GNUNET_malloc (32);
          if (1 == sscanf (temp_path, "/tmp/%s", temp))
            {
              temp_pos =
                GNUNET_malloc (sizeof (struct GNUNET_REMOTE_host_list));
              temp_pos->hostname = GNUNET_malloc (strlen (curr_host) + 1);
              strcpy (temp_pos->hostname, curr_host);

              temp_pos->username = GNUNET_malloc (strlen (ssh_username) + 1);
              strcpy (temp_pos->username, ssh_username);

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
                                          temp_pos->remote_friend_file_path);

              GNUNET_GC_get_configuration_value_number (basecfg,
                                                        "NETWORK",
                                                        "PORT",
                                                        0, 65535, 65535,
                                                        &temp_port);
              temp_pos->port = (unsigned short) temp_port;
              temp_pos->next = head;
              head = temp_pos;
              array_of_pointers[count_started] = temp_pos;
              count_started++;
            }

          GNUNET_free (temp_remote_config_path);
          GNUNET_free (temp);
          UNLINK (temp_path);
          GNUNET_free (temp_path);

          if ((i < extra_daemons) && (j == daemons_per_machine - 1))
            {
              length_temp =
                snprintf (NULL, 0, "%s%s%d", remote_pid_path, "pid", j + 1);
              temp_pid_file = GNUNET_malloc (length_temp + 1);
              snprintf (temp_pid_file, length_temp + 1, "%s%s%d",
                        remote_pid_path, "pid", j + 1);

              GNUNET_GC_set_configuration_value_string (basecfg, NULL,
                                                        "GNUNETD",
                                                        "PIDFILE",
                                                        temp_pid_file);
              GNUNET_free (temp_pid_file);

              temp_remote_config_path_length =
                snprintf (NULL, 0, "%s%d", remote_config_path, j);
              temp_remote_config_path =
                GNUNET_malloc (temp_remote_config_path_length + 1);
              snprintf (temp_remote_config_path,
                        temp_remote_config_path_length + 1, "%s%d",
                        remote_config_path, j);

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
                  GNUNET_GC_free (basecfg);
                  GNUNET_free (temp_path);
                  break;
                }
              CLOSE (ret);
              if (0 != GNUNET_GC_write_configuration (basecfg, temp_path))
                {
                  /* I guess an error would be logged by GNUNET_GC_write_configuration */
                  GNUNET_GC_free (basecfg);
                  GNUNET_free (temp_path);
                  break;
                }

              temp = GNUNET_malloc (32);
              if (1 == sscanf (temp_path, "/tmp/%s", temp))
                {
                  temp_pos =
                    GNUNET_malloc (sizeof (struct GNUNET_REMOTE_host_list));
                  temp_pos->hostname = GNUNET_malloc (strlen (curr_host));
                  strcpy (temp_pos->hostname, curr_host);

                  temp_pos->username = GNUNET_malloc (strlen (ssh_username));
                  strcpy (temp_pos->username, ssh_username);

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
                                              temp_pos->remote_friend_file_path);

                  GNUNET_GC_get_configuration_value_number (basecfg,
                                                            "NETWORK",
                                                            "PORT",
                                                            0, 65535, 65535,
                                                            &temp_port);

                  temp_pos->port = (unsigned short) temp_port;
                  temp_pos->next = head;
                  head = temp_pos;
                  array_of_pointers[count_started] = temp_pos;
                  count_started++;
                }
              GNUNET_free (temp_remote_config_path);
              UNLINK (temp_path);
              GNUNET_free (temp_path);
              GNUNET_free (temp);
            }
        }

      GNUNET_GC_free (basecfg);
      ++i;
    }
  ret = GNUNET_REMOTE_create_topology (type_of_topology, number_of_daemons);

  GNUNET_free (base_config);
  GNUNET_free (remote_pid_path);
  GNUNET_free (data_dir);
  GNUNET_free (ssh_username);
  GNUNET_free (control_host);
  GNUNET_free (hostnames);
  GNUNET_free (remote_config_path);
  GNUNET_free (remote_gnunetd_path);

  return ret;
}

int
GNUNET_REMOTE_create_topology (GNUNET_REMOTE_TOPOLOGIES t,
                               int number_of_daemons)
{
  FILE *temp_friend_handle;
  int ret;
  struct GNUNET_REMOTE_host_list *pos;
  struct GNUNET_REMOTE_friends_list *friend_pos;

  char *cmd;
  int length;

  ret = GNUNET_OK;
  switch (t)
    {
    case GNUNET_REMOTE_CLIQUE:
      fprintf (stderr, "Creating clique topology\n");
      ret = GNUNET_REMOTE_connect_clique (head);
      break;
    case GNUNET_REMOTE_SMALL_WORLD:
      fprintf (stderr, "Creating small world topology\n");
      ret = GNUNET_SYSERR;
      break;
    case GNUNET_REMOTE_RING:
      fprintf (stderr, "Creating ring topology\n");
      ret = GNUNET_SYSERR;
      break;
    case GNUNET_REMOTE_2D_TORUS:
      fprintf (stderr, "Creating 2d torus topology\n");
      ret = GNUNET_REMOTE_connect_2d_torus (number_of_daemons, list_as_array);
      break;
    default:
      ret = GNUNET_SYSERR;
      break;
    }

  if (ret == GNUNET_OK)
    {
      pos = head;
      while (pos != NULL)
        {
          /* Printing out the friends isn't necessary, but it's nice */
          fprintf (stderr, _("Friend list of %s:%d\n"), pos->hostname,
                   pos->port);
          temp_friend_handle = fopen ("friend.temp", "wt");
          friend_pos = pos->friend_entries;
          while (friend_pos != NULL)
            {
              fprintf (stderr, "\t%s\n", (const char *) friend_pos->nodeid);
              fprintf (temp_friend_handle, "%s\n",
                       (const char *) friend_pos->nodeid);
              friend_pos = friend_pos->next;
            }

          fclose (temp_friend_handle);
          length =
            snprintf (NULL, 0, "scp %s %s@%s:%s", "friend.temp",
                      pos->username, pos->hostname,
                      pos->remote_friend_file_path);
          cmd = GNUNET_malloc (length + 1);
          snprintf (cmd, length + 1, "scp %s %s@%s:%s", "friend.temp",
                    pos->username, pos->hostname,
                    pos->remote_friend_file_path);

          fprintf (stderr, _("scp command for friend file copy is : %s \n"),
                   cmd);
          system (cmd);
          GNUNET_free (cmd);
          pos = pos->next;
        }

      system ("rm friend.temp");

      pos = head;

      /* This loop goes over the friend entries of each peer and connects that
       * peer to each friend in the list.  Note this is redundant, i.e. once
       * the two are connected, the second doesn't really need to try to connect
       * to the first later, but this IS simple.  If performance becomes a problem
       * with MANY conns, we'll see...
       */
      while (pos != NULL)
        {
          friend_pos = pos->friend_entries;
          while (friend_pos != NULL)
            {
              fprintf (stderr, _("connecting peer %s:%d to peer %s:%d\n"),
                       pos->hostname, pos->port,
                       friend_pos->hostentry->hostname,
                       friend_pos->hostentry->port);
              GNUNET_REMOTE_connect_daemons (pos->hostname, pos->port,
                                             friend_pos->hostentry->hostname,
                                             friend_pos->hostentry->port);
              friend_pos = friend_pos->next;
            }
          pos = pos->next;
        }

    }
  else
    {
      fprintf (stderr, "connect didn't return well!\n");
    }


  return ret;
}

/* end of remote.c */
