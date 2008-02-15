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

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_identity_lib.h"
#include "gnunet_util.h"
#include "gnunet_testing_lib.h"

#define VERBOSE GNUNET_NO

const unsigned long long MIN_STARTING_PORT = 1;
const unsigned long long MAX_STARTING_PORT = -1;
const unsigned long long MIN_PORT_INCREMENT = 1;
const unsigned long long MAX_PORT_INCREMENT = -1;
const unsigned long long MIN_NUMBER_DAEMONS = 1;
const unsigned long long MAX_NUMBER_DAEMONS = -1;

static void
updatePort (struct GNUNET_GC_Configuration *cfg,
            const char *section, unsigned short offset)
{
  unsigned long long old;

  if ((GNUNET_YES == GNUNET_GC_have_configuration_value (cfg,
                                                         section,
                                                         "PORT")) &&
      (0 == GNUNET_GC_get_configuration_value_number (cfg,
                                                      section,
                                                      "PORT",
                                                      0, 65535, 65535, &old)))
    {
      old += offset;
      GNUNET_GE_ASSERT (NULL,
                        0 == GNUNET_GC_set_configuration_value_number (cfg,
                                                                       NULL,
                                                                       section,
                                                                       "PORT",
                                                                       old));
    }
}


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
                            char *username)
{
  char *cmd;
  int length;

  length =
    snprintf (NULL, 0, "scp %s%s %s@%s:%s", localConfigPath, configFileName,
              username, hostname, remote_config_path);
  cmd = GNUNET_malloc (length + 1);
  snprintf (cmd, length + 1, "scp %s%s %s@%s:%s", localConfigPath,
            configFileName, username, hostname, remote_config_path);

  printf ("scp command is : %s \n", cmd);
  system (cmd);

  GNUNET_free (cmd);
  length =
    snprintf (NULL, 0, "ssh %s@%s %sgnunetd -c %s%s", username, hostname,
              gnunetd_home, remote_config_path, configFileName);
  cmd = GNUNET_malloc (length + 1);
  snprintf (cmd, length + 1, "ssh %s@%s %sgnunetd -c %s%s", username,
            hostname, gnunetd_home, remote_config_path, configFileName);

  printf ("ssh command is : %s \n", cmd);

  system (cmd);

  GNUNET_free (cmd);
  return GNUNET_OK;
}

int
GNUNET_REMOTE_start_daemons (struct GNUNET_GC_Configuration *newcfg,
                             unsigned int number_of_daemons)
{
  struct GNUNET_GC_Configuration *basecfg;

  char *ssh_username;
  char *control_host;
  char *remote_config_path;
  char *remote_gnunetd_path;
  char *remote_pid_path;
  char *base_config;
  char *data_dir;
  unsigned long long starting_port;
  unsigned long long port_increment;
  unsigned long long daemons_per_machine;

  char *hostnames;
  char *temp;
  char *temp_path;
  char *temp_pid_file;
  char *curr_host;

  unsigned int extra_daemons;
  unsigned int count;
  unsigned int length;
  unsigned int length_temp;
  unsigned int num_machines;
  unsigned int i;
  unsigned int j;
  unsigned int pos;
  int ret;
  char *ipk_dir;

  length = 0;
  ipk_dir = GNUNET_get_installation_path (GNUNET_IPK_DATADIR);
  length = snprintf (NULL, 0, "%s%s", ipk_dir, "gnunetd.conf.skel");
  data_dir = GNUNET_malloc (length + 1);
  snprintf (data_dir, length + 1, "%s%s", ipk_dir, "gnunetd.conf.skel");
  GNUNET_free (ipk_dir);
  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "SSH_USERNAME", "",
                                            &ssh_username);
  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "CONTROL_HOST", "localhost",
                                            &control_host);
  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "HOSTNAMES", "localhost",
                                            &hostnames);
  GNUNET_GC_get_configuration_value_number (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "STARTING_PORT",
                                            MIN_STARTING_PORT,
                                            MAX_STARTING_PORT, 1,
                                            &starting_port);
  GNUNET_GC_get_configuration_value_number (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "PORT_INCREMENT",
                                            MIN_PORT_INCREMENT,
                                            MAX_PORT_INCREMENT, 2,
                                            &port_increment);
  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "REMOTE_CONFIG_PATH", "/tmp/",
                                            &remote_config_path);
  ipk_dir = GNUNET_get_installation_path (GNUNET_IPK_BINDIR);
  GNUNET_GC_get_configuration_value_string (newcfg, "MULTIPLE_SERVER_TESTING",
                                            "REMOTE_GNUNETD_PATH", ipk_dir,
                                            &remote_gnunetd_path);
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
      printf ("curr_host is %s\n", curr_host);

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

          updatePort (basecfg, "NETWORK", j + port_increment);
          updatePort (basecfg, "TCP", j + port_increment);
          updatePort (basecfg, "UDP", j + port_increment);

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
              break;
            }
          CLOSE (ret);
          if (0 != GNUNET_GC_write_configuration (basecfg, temp_path))
            {
              fprintf (stderr,
                       "Failed to write peer configuration file `%s'\n",
                       temp_path);
              GNUNET_free (temp_path);
              break;
            }

          temp = GNUNET_malloc (32);
          if (1 == sscanf (temp_path, "/tmp/%s", temp))
            {
              GNUNET_REMOTE_start_daemon (remote_gnunetd_path, "/tmp/",
                                          temp, remote_config_path,
                                          curr_host, ssh_username);
            }
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

              updatePort (basecfg, "NETWORK", (j + 1) + port_increment);
              updatePort (basecfg, "TCP", (j + 1) + port_increment);
              updatePort (basecfg, "UDP", (j + 1) + port_increment);
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
                  fprintf (stderr,
                           "Failed to write peer configuration file `%s'\n",
                           temp_path);
                  GNUNET_GC_free (basecfg);
                  GNUNET_free (temp_path);
                  break;
                }

              temp = GNUNET_malloc (32);
              if (1 == sscanf (temp_path, "/tmp/%s", temp))
                {
                  printf ("calling start on %s\n", curr_host);
                  GNUNET_REMOTE_start_daemon (remote_gnunetd_path,
                                              "/tmp/", temp,
                                              remote_config_path,
                                              curr_host, ssh_username);
                }
              UNLINK (temp_path);
              GNUNET_free (temp_path);
              GNUNET_free (temp);
            }
        }

      GNUNET_GC_free (basecfg);
      ++i;
    }

  GNUNET_free (base_config);
  GNUNET_free (remote_pid_path);
  GNUNET_free (data_dir);
  GNUNET_free (ssh_username);
  GNUNET_free (control_host);
  GNUNET_free (hostnames);
  GNUNET_free (remote_config_path);
  GNUNET_free (remote_gnunetd_path);

  return GNUNET_OK;
}

/* end of remote.c */
