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
 * @file applications/testing/remotetopologies.c
 * @brief helper to set up topologies for testing
 * @author Nathan Evans
 */
#include "remote.h"

static int
printInfo (void *data,
           const GNUNET_PeerIdentity *
           identity,
           const void *address,
           unsigned int addr_len,
           GNUNET_CronTime last_message,
           unsigned int trust, unsigned int bpmFromPeer)
{
  GNUNET_EncName oth;
  GNUNET_hash_to_enc (&identity->hashPubKey, &oth);
  fprintf (stderr,
           "%s: %llu - %u\n", (const char *) &oth, last_message, bpmFromPeer);
  return GNUNET_OK;
}

int
GNUNET_REMOTE_connect_clique (struct GNUNET_REMOTE_host_list *main_list)
{
  struct GNUNET_REMOTE_host_list *pos = main_list;
  struct GNUNET_REMOTE_host_list *iter_pos = main_list;
  GNUNET_EncName *node1;
  GNUNET_EncName *node2;
  struct GNUNET_REMOTE_friends_list *node1temp;
  struct GNUNET_REMOTE_friends_list *node2temp;

	node1 = GNUNET_malloc(sizeof(GNUNET_EncName));
	node2 = GNUNET_malloc(sizeof(GNUNET_EncName));

  while ((pos != NULL) && (pos->next != NULL))
    {
      iter_pos = pos->next;
      while (iter_pos != NULL)
        {
        	
        	fprintf(stderr,"connecting %s:%lld to %s:%lld\n",pos->hostname,pos->port,iter_pos->hostname,iter_pos->port);
          if(GNUNET_OK == GNUNET_REMOTE_get_daemons_information (pos->hostname, pos->port,
                                         iter_pos->hostname, iter_pos->port,&node1,&node2))
          	{
          		node1temp = GNUNET_malloc(sizeof(struct GNUNET_REMOTE_friends_list));
          		node2temp = GNUNET_malloc(sizeof(struct GNUNET_REMOTE_friends_list));
          		
          		node1temp->nodeid = GNUNET_malloc(sizeof(GNUNET_EncName));
          		node2temp->nodeid = GNUNET_malloc(sizeof(GNUNET_EncName));
          		
          		memcpy(node1temp->nodeid,node2,sizeof(GNUNET_EncName));
          		memcpy(node2temp->nodeid,node1,sizeof(GNUNET_EncName)); 
          		
          		node1temp->next = pos->friend_entries;
          		node2temp->next = iter_pos->friend_entries;
          		
          		pos->friend_entries = node1temp;
          		iter_pos->friend_entries = node2temp;         
          	}
          iter_pos = iter_pos->next;
        }
      pos = pos->next;
    }
    
  GNUNET_free(node1);
	GNUNET_free(node2);
	
  return GNUNET_OK;
}

int
GNUNET_REMOTE_connect_2d_torus (int number_of_daemons,
                                struct GNUNET_REMOTE_host_list
                                **list_as_array)
{

  return GNUNET_SYSERR;
}

/**
* Establish a connection between two GNUnet daemons
*
* @param port1 client port of the first daemon
* @param port2 client port of the second daemon
* @param ip1 client ip or hostname for the first daemon
* @param ip2 client ip or hostname for the second daemon
* @return GNUNET_OK on success, GNUNET_SYSERR on failure
*/

int
GNUNET_REMOTE_connect_daemons (char *hostname1, unsigned short port1,
                               char *hostname2, unsigned short port2)
{
  char host[128];
  struct GNUNET_GC_Configuration *cfg1 = GNUNET_GC_create ();
  struct GNUNET_GC_Configuration *cfg2 = GNUNET_GC_create ();
  struct GNUNET_ClientServerConnection *sock1;
  struct GNUNET_ClientServerConnection *sock2;
  int ret;
  
  GNUNET_EncName *host1entry;
  GNUNET_EncName *host2entry;
  host1entry = GNUNET_malloc(sizeof(GNUNET_EncName));
  host2entry = GNUNET_malloc(sizeof(GNUNET_EncName));
  
  GNUNET_MessageHello *h1;
  GNUNET_MessageHello *h2;

  ret = GNUNET_SYSERR;
  GNUNET_snprintf (host, 128, "%s:%u", hostname1, port1);
  GNUNET_GC_set_configuration_value_string (cfg1, NULL, "NETWORK", "HOST",
                                            host);

  GNUNET_snprintf (host, 128, "%s:%u", hostname2, port2);
  GNUNET_GC_set_configuration_value_string (cfg2, NULL, "NETWORK", "HOST",
                                            host);

  if ((GNUNET_OK ==
       GNUNET_wait_for_daemon_running (NULL, cfg1, 300 * GNUNET_CRON_SECONDS))
      && (GNUNET_OK ==
          GNUNET_wait_for_daemon_running (NULL, cfg2,
                                          300 * GNUNET_CRON_SECONDS)))
    {
      sock1 = GNUNET_client_connection_create (NULL, cfg1);
      sock2 = GNUNET_client_connection_create (NULL, cfg2);
      ret = -20;
      fprintf (stderr, _("Waiting for peers to connect"));
      while ((ret++ < -1) && (GNUNET_shutdown_test () == GNUNET_NO))
        {
          h1 = NULL;
          h2 = NULL;
          if ((GNUNET_OK == GNUNET_IDENTITY_get_self (sock1,
                                                      &h1)) &&
              (GNUNET_OK == GNUNET_IDENTITY_get_self (sock2,
                                                      &h2)) &&
              (GNUNET_OK == GNUNET_IDENTITY_peer_add (sock1,
                                                      h2)) &&
              (GNUNET_OK == GNUNET_IDENTITY_peer_add (sock2, h1)))
            {
              fprintf (stderr, ".");
              if (GNUNET_YES == GNUNET_IDENTITY_request_connect (sock1,
                                                                 &h2->
                                                                 senderIdentity))
                {
                  ret = GNUNET_OK;
                  GNUNET_free_non_null (h1);
                  GNUNET_free_non_null (h2);
                  break;
                }
              if (GNUNET_YES == GNUNET_IDENTITY_request_connect (sock2,
                                                                 &h1->
                                                                 senderIdentity))
                {
                  ret = GNUNET_OK;
                  GNUNET_free_non_null (h1);
                  GNUNET_free_non_null (h2);
                  break;
                }
              GNUNET_thread_sleep (100 * GNUNET_CRON_MILLISECONDS);
            }
          GNUNET_free_non_null (h1);
          GNUNET_free_non_null (h2);
        }

    	GNUNET_hash_to_enc (&h1->senderIdentity.hashPubKey, host1entry);
      GNUNET_hash_to_enc (&h2->senderIdentity.hashPubKey, host2entry);
      
      if (ret != GNUNET_OK)
        {
          fprintf (stderr,
                   "\nFailed to connect `%s' and `%s'\n",
                   (const char *) &host1entry, (const char *) &host2entry);
          fprintf (stderr, "Connections of `%s':\n", (const char *) &host1entry);
          GNUNET_IDENTITY_request_peer_infos (sock1, &printInfo, NULL);
          fprintf (stderr, "Connections of `%s':\n", (const char *) &host2entry);
          GNUNET_IDENTITY_request_peer_infos (sock2, &printInfo, NULL);

        }
      fprintf (stderr, "%s\n", ret == GNUNET_OK ? "Connected nodes." : "?");
      GNUNET_client_connection_destroy (sock1);
      GNUNET_client_connection_destroy (sock2);
    }
  else
    {
      fprintf (stderr, "Failed to establish connection with peers.\n");
    }
  GNUNET_GC_free (cfg1);
  GNUNET_GC_free (cfg2);
  return ret;
}

int
GNUNET_REMOTE_get_daemons_information (char *hostname1, unsigned short port1,
                               char *hostname2, unsigned short port2, GNUNET_EncName **host1entry, GNUNET_EncName **host2entry)
{
	char host[128];
  struct GNUNET_GC_Configuration *cfg1 = GNUNET_GC_create ();
  struct GNUNET_GC_Configuration *cfg2 = GNUNET_GC_create ();
  struct GNUNET_ClientServerConnection *sock1;
  struct GNUNET_ClientServerConnection *sock2;
  int ret;
  GNUNET_MessageHello *h1;
  GNUNET_MessageHello *h2;

  ret = GNUNET_SYSERR;
  GNUNET_snprintf (host, 128, "%s:%u", hostname1, port1);
  GNUNET_GC_set_configuration_value_string (cfg1, NULL, "NETWORK", "HOST",
                                            host);

  GNUNET_snprintf (host, 128, "%s:%u", hostname2, port2);
  GNUNET_GC_set_configuration_value_string (cfg2, NULL, "NETWORK", "HOST",
                                            host);

  if ((GNUNET_OK ==
       GNUNET_wait_for_daemon_running (NULL, cfg1, 300 * GNUNET_CRON_SECONDS))
      && (GNUNET_OK ==
          GNUNET_wait_for_daemon_running (NULL, cfg2,
                                          300 * GNUNET_CRON_SECONDS)))
    {
      sock1 = GNUNET_client_connection_create (NULL, cfg1);
      sock2 = GNUNET_client_connection_create (NULL, cfg2);
      ret = -20;
      fprintf (stderr, _("Waiting for peers to connect"));
      while ((ret++ < -1) && (GNUNET_shutdown_test () == GNUNET_NO))
        {
          h1 = NULL;
          h2 = NULL;
          GNUNET_IDENTITY_get_self (sock1,&h1);
          GNUNET_IDENTITY_get_self (sock2,&h2);
                        
          GNUNET_thread_sleep (100 * GNUNET_CRON_MILLISECONDS);
         }

    	GNUNET_hash_to_enc (&h1->senderIdentity.hashPubKey, *host1entry);
      GNUNET_hash_to_enc (&h2->senderIdentity.hashPubKey, *host2entry);
      
      GNUNET_free_non_null (h1);
      GNUNET_free_non_null (h2);

      fprintf (stderr, "%s\n", ret == GNUNET_OK ? "Connected nodes." : "?");
      GNUNET_client_connection_destroy (sock1);
      GNUNET_client_connection_destroy (sock2);
    }
  else
    {
      fprintf (stderr, "Failed to establish connection with peers.\n");
    }
  GNUNET_GC_free (cfg1);
  GNUNET_GC_free (cfg2);
  return ret;
}

/* end of remotetopologies.c */
