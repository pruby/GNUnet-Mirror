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
                             char *localConfigPath,char *configFileName,char *remote_config_path,char *ip_address,
                             char *username)
{
	char *cmd;
	char *newcmd;
	
	cmd = "scp ";
	newcmd = GNUNET_malloc (strlen (cmd) + strlen(localConfigPath) + 1 + strlen(configFileName));
	strcpy(newcmd,cmd);
	//strcat(newcmd,(localConfigFile) " " (username) "@" (ip_address) ":" (remote_config_path));
	strcat(newcmd,localConfigPath);
	strcat(newcmd,configFileName);
	strcat(newcmd," ");
	strcat(newcmd,username);
	strcat(newcmd,"@");
	strcat(newcmd,ip_address);
	strcat(newcmd,":");
	strcat(newcmd,remote_config_path);
	
	//printf("scp command is : %s \n",newcmd);
	//system(newcmd);
	
	cmd = "ssh ";
	GNUNET_free(newcmd);
	newcmd = GNUNET_malloc (strlen (cmd) + 128);
	strcpy(newcmd,cmd);
	strcat(newcmd,username);
	strcat(newcmd,"@");
	strcat(newcmd,ip_address);
	strcat(newcmd," ");
	strcat(newcmd,gnunetd_home);
	strcat(newcmd, DIR_SEPARATOR_STR "gnunetd -c ");
	strcat(newcmd, remote_config_path);
	strcat(newcmd, configFileName);
	
	//printf("ssh command is : %s \n",newcmd);
	
	//system(newcmd);
		
	return GNUNET_OK;
}

int
GNUNET_REMOTE_start_daemons(struct GNUNET_GC_Configuration **newcfg)
{
	
	
	char *ssh_username;
	char *control_host;
	char *remote_config_path;
	char *remote_gnunetd_path;
	unsigned long long starting_port;
	unsigned long long port_increment;
	unsigned long long number_of_daemons;
	char *client_ips;
	
	unsigned int count = 0;
	unsigned int length;
	unsigned int temp[4];
	unsigned int num_machines = 0;
	unsigned int i;
	unsigned int j;
	unsigned int pos;
	unsigned int cnt;
	
	GNUNET_GC_get_configuration_value_string(*newcfg,"MULTIPLE_SERVER_TESTING","SSH_USERNAME",NULL,&ssh_username);
	GNUNET_GC_get_configuration_value_string(*newcfg,"MULTIPLE_SERVER_TESTING","CONTROL_HOST",NULL,&control_host);
	GNUNET_GC_get_configuration_value_string(*newcfg,"MULTIPLE_SERVER_TESTING","CLIENT_IPS",NULL,&client_ips);
	GNUNET_GC_get_configuration_value_number(*newcfg,"MULTIPLE_SERVER_TESTING","STARTING_PORT",MIN_STARTING_PORT,MAX_STARTING_PORT,0,&starting_port);
	GNUNET_GC_get_configuration_value_number(*newcfg,"MULTIPLE_SERVER_TESTING","PORT_INCREMENT",MIN_PORT_INCREMENT,MAX_PORT_INCREMENT,0,&port_increment);
	GNUNET_GC_get_configuration_value_number(*newcfg,"MULTIPLE_SERVER_TESTING","NUMBER_OF_DAEMONS",MIN_NUMBER_DAEMONS,MAX_NUMBER_DAEMONS,0,&number_of_daemons);
	GNUNET_GC_get_configuration_value_string(*newcfg,"MULTIPLE_SERVER_TESTING","REMOTE_CONFIG_PATH",NULL,&remote_config_path);
	GNUNET_GC_get_configuration_value_string(*newcfg,"MULTIPLE_SERVER_TESTING","REMOTE_GNUNETD_PATH",NULL,&remote_gnunetd_path);
	
	
	//printf("username : %s\n", ssh_username);
	//printf("control host : %s\n", control_host);
	//printf("client ip string : %s\n", client_ips);
	//printf("remote config path : %s\n", remote_config_path);
	//printf("remote gnunetd path : %s\n", remote_gnunetd_path);

	//printf("starting port : %lld\n", starting_port);
	//printf("port increment : %lld\n", port_increment);
	//printf("# of daemons : %lld\n", number_of_daemons);
	
	if (client_ips == NULL)
		return GNUNET_SYSERR;
		
	length = strlen(client_ips);
	
	while(count < length)
	{
		if (client_ips[count] == ';')
			++num_machines;
		++count;		
	}
	
	i = 0;
    pos = 0;
    
  	while (i < num_machines)
    {
		cnt = sscanf (&client_ips[pos],
	                    "%u.%u.%u.%u;",
	                    &temp[0], &temp[1], &temp[2], &temp[3]);
	      if (cnt == 4)
	        {
	          for (j = 0; j < 4; j++)
	            if (temp[j] > 0xFF)
	              {
	                printf("Error with ip address in config file...\n");
	                return NULL;
	              }
	
	        }
	        
	        while(client_ips[pos] != ';' && pos<length-1)
	        	pos++;
        	pos++;
        	i++;
        	
        printf("ip address is %u.%u.%u.%u\n",temp[0],temp[1],temp[2],temp[3]);
    }
	
		
}

int GNUNET_REMOTE_read_config(const char *config_file,struct GNUNET_GC_Configuration **newcfg)
{
	struct GNUNET_GC_Configuration *cfg;
		
	if (config_file == NULL) 
		return GNUNET_SYSERR;
	
	cfg = GNUNET_GC_create ();
	if (-1 == GNUNET_GC_parse_configuration (cfg, config_file))
	{
	  fprintf (stderr,
	          "Failed to read configuration file `%s'\n", config_file);
	  GNUNET_GC_free (cfg);
	  return GNUNET_SYSERR;
	}
	
	*newcfg = cfg;
	
	return GNUNET_OK;	
}
/* end of remote.c */
