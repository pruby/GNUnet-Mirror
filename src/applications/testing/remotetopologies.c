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

#define DEBUG GNUNET_YES

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
GNUNET_REMOTE_connect_erdos_renyi (double probability,
                                   struct GNUNET_REMOTE_host_list *main_list,
                                   FILE * dotOutFile)
{
  double temp_rand;
  struct GNUNET_REMOTE_host_list *pos = main_list;
  struct GNUNET_REMOTE_host_list *iter_pos = main_list;
  GNUNET_EncName *node1;
  GNUNET_EncName *node2;
  struct GNUNET_REMOTE_friends_list *node1temp;
  struct GNUNET_REMOTE_friends_list *node2temp;

  node1 = GNUNET_malloc (sizeof (GNUNET_EncName));
  node2 = GNUNET_malloc (sizeof (GNUNET_EncName));


  while ((pos != NULL) && (pos->next != NULL))
    {
      iter_pos = pos->next;
      while (iter_pos != NULL)
        {
          if (GNUNET_OK ==
              GNUNET_REMOTE_get_daemons_information (pos->hostname, pos->port,
                                                     iter_pos->hostname,
                                                     iter_pos->port, &node1,
                                                     &node2))
            {
              temp_rand = ((double) RANDOM () / RAND_MAX);
              fprintf(stderr, "rand is %f probability is %f\n",temp_rand,probability);
              if (temp_rand < probability)
                {
                  node1temp =
                    GNUNET_malloc (sizeof
                                   (struct GNUNET_REMOTE_friends_list));
                  node2temp =
                    GNUNET_malloc (sizeof
                                   (struct GNUNET_REMOTE_friends_list));

                  node2temp->hostentry = pos;
                  node1temp->hostentry = iter_pos;

                  node1temp->nodeid = GNUNET_malloc (sizeof (GNUNET_EncName));
                  node2temp->nodeid = GNUNET_malloc (sizeof (GNUNET_EncName));

                  memcpy (node1temp->nodeid, node2, sizeof (GNUNET_EncName));
                  memcpy (node2temp->nodeid, node1, sizeof (GNUNET_EncName));

                  node1temp->next = pos->friend_entries;
                  node2temp->next = iter_pos->friend_entries;

                  pos->friend_entries = node1temp;
                  iter_pos->friend_entries = node2temp;
                }
            }
          iter_pos = iter_pos->next;
        }
      pos = pos->next;
    }

  GNUNET_free (node1);
  GNUNET_free (node2);

  return GNUNET_OK;
}

int
GNUNET_REMOTE_connect_clique (struct GNUNET_REMOTE_host_list *main_list,
                              FILE * dotOutFile)
{
  struct GNUNET_REMOTE_host_list *pos = main_list;
  struct GNUNET_REMOTE_host_list *iter_pos = main_list;
  GNUNET_EncName *node1;
  GNUNET_EncName *node2;
  struct GNUNET_REMOTE_friends_list *node1temp;
  struct GNUNET_REMOTE_friends_list *node2temp;

  node1 = GNUNET_malloc (sizeof (GNUNET_EncName));
  node2 = GNUNET_malloc (sizeof (GNUNET_EncName));

  while ((pos != NULL) && (pos->next != NULL))
    {
      iter_pos = pos->next;
      while (iter_pos != NULL)
        {
          if (GNUNET_OK ==
              GNUNET_REMOTE_get_daemons_information (pos->hostname, pos->port,
                                                     iter_pos->hostname,
                                                     iter_pos->port, &node1,
                                                     &node2))
            {
              node1temp =
                GNUNET_malloc (sizeof (struct GNUNET_REMOTE_friends_list));
              node2temp =
                GNUNET_malloc (sizeof (struct GNUNET_REMOTE_friends_list));

              node2temp->hostentry = pos;
              node1temp->hostentry = iter_pos;

              node1temp->nodeid = GNUNET_malloc (sizeof (GNUNET_EncName));
              node2temp->nodeid = GNUNET_malloc (sizeof (GNUNET_EncName));

              memcpy (node1temp->nodeid, node2, sizeof (GNUNET_EncName));
              memcpy (node2temp->nodeid, node1, sizeof (GNUNET_EncName));

              node1temp->next = pos->friend_entries;
              node2temp->next = iter_pos->friend_entries;

              pos->friend_entries = node1temp;
              iter_pos->friend_entries = node2temp;
            }
          iter_pos = iter_pos->next;
        }
      pos = pos->next;
    }

  GNUNET_free (node1);
  GNUNET_free (node2);

  return GNUNET_OK;
}

int
GNUNET_REMOTE_connect_ring (struct GNUNET_REMOTE_host_list *main_list,
                            FILE * dotOutFile)
{
  struct GNUNET_REMOTE_host_list *pos = main_list;
  struct GNUNET_REMOTE_host_list *iter_pos = main_list;
  GNUNET_EncName *node1;
  GNUNET_EncName *node2;
  struct GNUNET_REMOTE_friends_list *node1temp;
  struct GNUNET_REMOTE_friends_list *node2temp;

  node1 = GNUNET_malloc (sizeof (GNUNET_EncName));
  node2 = GNUNET_malloc (sizeof (GNUNET_EncName));

  while (pos->next != NULL)
    {
      iter_pos = pos->next;
      if (GNUNET_OK ==
          GNUNET_REMOTE_get_daemons_information (pos->hostname, pos->port,
                                                 iter_pos->hostname,
                                                 iter_pos->port, &node1,
                                                 &node2))
        {
          node1temp =
            GNUNET_malloc (sizeof (struct GNUNET_REMOTE_friends_list));
          node2temp =
            GNUNET_malloc (sizeof (struct GNUNET_REMOTE_friends_list));

          node2temp->hostentry = pos;
          node1temp->hostentry = iter_pos;

          node1temp->nodeid = GNUNET_malloc (sizeof (GNUNET_EncName));
          node2temp->nodeid = GNUNET_malloc (sizeof (GNUNET_EncName));

          memcpy (node1temp->nodeid, node2, sizeof (GNUNET_EncName));
          memcpy (node2temp->nodeid, node1, sizeof (GNUNET_EncName));

          node1temp->next = pos->friend_entries;
          node2temp->next = iter_pos->friend_entries;

          pos->friend_entries = node1temp;
          iter_pos->friend_entries = node2temp;
        }
      pos = pos->next;
    }
  iter_pos = main_list;
  if (GNUNET_OK ==
      GNUNET_REMOTE_get_daemons_information (pos->hostname, pos->port,
                                             iter_pos->hostname,
                                             iter_pos->port, &node1, &node2))
    {
      node1temp = GNUNET_malloc (sizeof (struct GNUNET_REMOTE_friends_list));
      node2temp = GNUNET_malloc (sizeof (struct GNUNET_REMOTE_friends_list));

      node2temp->hostentry = pos;
      node1temp->hostentry = iter_pos;

      node1temp->nodeid = GNUNET_malloc (sizeof (GNUNET_EncName));
      node2temp->nodeid = GNUNET_malloc (sizeof (GNUNET_EncName));

      memcpy (node1temp->nodeid, node2, sizeof (GNUNET_EncName));
      memcpy (node2temp->nodeid, node1, sizeof (GNUNET_EncName));

      node1temp->next = pos->friend_entries;
      node2temp->next = iter_pos->friend_entries;

      pos->friend_entries = node1temp;
      iter_pos->friend_entries = node2temp;
    }

  GNUNET_free (node1);
  GNUNET_free (node2);

  return GNUNET_OK;
}

int
GNUNET_REMOTE_connect_2d_torus (unsigned int number_of_daemons,
                                struct GNUNET_REMOTE_host_list
                                **list_as_array, FILE * dotOutFile)
{
  unsigned int i;
  unsigned int square;
  unsigned int rows;
  unsigned int cols;
  unsigned int toggle = 1;
  unsigned int nodeToConnect;

  GNUNET_EncName *node1;
  GNUNET_EncName *node2;
  struct GNUNET_REMOTE_friends_list *node1temp;
  struct GNUNET_REMOTE_friends_list *node2temp;

  node1 = GNUNET_malloc (sizeof (GNUNET_EncName));
  node2 = GNUNET_malloc (sizeof (GNUNET_EncName));

  square = floor (sqrt (number_of_daemons));
  rows = square;
  cols = square;

  if (square * square != number_of_daemons)
    {
      while (rows * cols < number_of_daemons)
        {
          if (toggle % 2 == 0)
            rows++;
          else
            cols++;

          toggle++;
        }
    }
  fprintf (stderr,
           _("Connecting nodes in 2d torus topology: %u rows %u columns\n"),
           rows, cols);
  /* Rows and columns are all sorted out, now iterate over all nodes and connect each
   * to the node to its right and above.  Once this is over, we'll have our torus!
   * Special case for the last node (if the rows and columns are not equal), connect
   * to the first in the row to maintain topology.
   */
  for (i = 0; i < number_of_daemons; i++)
    {
      /* First connect to the node to the right */
      if (((i + 1) % cols != 0) && (i + 1 != number_of_daemons))
        nodeToConnect = i + 1;
      else if (i + 1 == number_of_daemons)
        nodeToConnect = rows * cols - cols;
      else
        nodeToConnect = i - cols + 1;

      fprintf (stderr, "connecting node %u to %u\n", i, nodeToConnect);
      GNUNET_REMOTE_get_daemons_information (list_as_array[i]->hostname,
                                             list_as_array[i]->port,
                                             list_as_array
                                             [nodeToConnect]->hostname,
                                             list_as_array
                                             [nodeToConnect]->port, &node1,
                                             &node2);

      node1temp = GNUNET_malloc (sizeof (struct GNUNET_REMOTE_friends_list));
      node2temp = GNUNET_malloc (sizeof (struct GNUNET_REMOTE_friends_list));

      node2temp->hostentry = list_as_array[i];
      node1temp->hostentry = list_as_array[nodeToConnect];

      node1temp->nodeid = GNUNET_malloc (sizeof (GNUNET_EncName));
      node2temp->nodeid = GNUNET_malloc (sizeof (GNUNET_EncName));

      memcpy (node1temp->nodeid, node2, sizeof (GNUNET_EncName));
      memcpy (node2temp->nodeid, node1, sizeof (GNUNET_EncName));

      node1temp->next = list_as_array[i]->friend_entries;
      node2temp->next = list_as_array[nodeToConnect]->friend_entries;

      list_as_array[i]->friend_entries = node1temp;
      list_as_array[nodeToConnect]->friend_entries = node2temp;


      /* Second connect to the node immediately above */
      if (i < cols)
        nodeToConnect = (rows * cols) - cols + i;
      else
        nodeToConnect = i - cols;

      if (nodeToConnect < number_of_daemons)
        {
          fprintf (stderr, "connecting node %u to %u\n", i, nodeToConnect);
          GNUNET_REMOTE_get_daemons_information (list_as_array[i]->hostname,
                                                 list_as_array[i]->port,
                                                 list_as_array
                                                 [nodeToConnect]->hostname,
                                                 list_as_array
                                                 [nodeToConnect]->port,
                                                 &node1, &node2);

          node1temp =
            GNUNET_malloc (sizeof (struct GNUNET_REMOTE_friends_list));
          node2temp =
            GNUNET_malloc (sizeof (struct GNUNET_REMOTE_friends_list));

          node2temp->hostentry = list_as_array[i];
          node1temp->hostentry = list_as_array[nodeToConnect];

          node1temp->nodeid = GNUNET_malloc (sizeof (GNUNET_EncName));
          node2temp->nodeid = GNUNET_malloc (sizeof (GNUNET_EncName));

          memcpy (node1temp->nodeid, node2, sizeof (GNUNET_EncName));
          memcpy (node2temp->nodeid, node1, sizeof (GNUNET_EncName));

          node1temp->next = list_as_array[i]->friend_entries;
          node2temp->next = list_as_array[nodeToConnect]->friend_entries;

          list_as_array[i]->friend_entries = node1temp;
          list_as_array[nodeToConnect]->friend_entries = node2temp;
        }

    }

  GNUNET_free (node1);
  GNUNET_free (node2);
  return GNUNET_OK;
}

int
GNUNET_REMOTE_connect_small_world (int number_of_daemons,
                                   struct GNUNET_REMOTE_host_list
                                   **list_as_array, FILE * dotOutFile)
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
                               char *hostname2, unsigned short port2,
                               FILE * dotOutFile)
{
  char host[128];
  char *buf;
  struct GNUNET_GC_Configuration *cfg1 = GNUNET_GC_create ();
  struct GNUNET_GC_Configuration *cfg2 = GNUNET_GC_create ();
  struct GNUNET_ClientServerConnection *sock1;
  struct GNUNET_ClientServerConnection *sock2;
  int ret;

  GNUNET_EncName *host1entry;
  GNUNET_EncName *host2entry;
  host1entry = GNUNET_malloc (sizeof (GNUNET_EncName));
  host2entry = GNUNET_malloc (sizeof (GNUNET_EncName));

  GNUNET_MessageHello *h1;
  GNUNET_MessageHello *h2;

  ret = GNUNET_SYSERR;
  GNUNET_snprintf (host, 128, "%s:%u", hostname1, port1);
  GNUNET_GC_set_configuration_value_string (cfg1, NULL, "NETWORK", "HOST",
                                            host);
  if (DEBUG == GNUNET_YES)
    {
      fprintf (stderr, "Setting config 1 to host %s\n", host);
    }
  GNUNET_snprintf (host, 128, "%s:%u", hostname2, port2);
  GNUNET_GC_set_configuration_value_string (cfg2, NULL, "NETWORK", "HOST",
                                            host);

  if (DEBUG == GNUNET_YES)
    {
      fprintf (stderr, "Setting config 2 to host %s\n", host);
    }

  if ((GNUNET_OK ==
       GNUNET_wait_for_daemon_running (NULL, cfg1, 30 * GNUNET_CRON_SECONDS))
      && (GNUNET_OK ==
          GNUNET_wait_for_daemon_running (NULL, cfg2,
                                          30 * GNUNET_CRON_SECONDS)))
    {
      sock1 = GNUNET_client_connection_create (NULL, cfg1);
      sock2 = GNUNET_client_connection_create (NULL, cfg2);
      ret = -20;
      fprintf (stderr, _("Waiting for peers to connect"));
      h1 = NULL;
      h2 = NULL;
      while ((ret++ < -1) && (GNUNET_shutdown_test () == GNUNET_NO))
        {

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
                  break;
                }
              if (GNUNET_YES == GNUNET_IDENTITY_request_connect (sock2,
                                                                 &h1->
                                                                 senderIdentity))
                {
                  ret = GNUNET_OK;
                  break;
                }
              GNUNET_thread_sleep (100 * GNUNET_CRON_MILLISECONDS);
            }

        }

      GNUNET_hash_to_enc (&h1->senderIdentity.hashPubKey, host1entry);
      GNUNET_hash_to_enc (&h2->senderIdentity.hashPubKey, host2entry);

      GNUNET_free_non_null (h1);
      GNUNET_free_non_null (h2);

      if (ret != GNUNET_OK)
        {
          fprintf (stderr,
                   "\nFailed to connect `%s' and `%s'\n",
                   (const char *) host1entry, (const char *) host2entry);
          fprintf (stderr, "Connections of `%s':\n",
                   (const char *) host1entry);
          GNUNET_IDENTITY_request_peer_infos (sock1, &printInfo, NULL);
          fprintf (stderr, "Connections of `%s':\n",
                   (const char *) host2entry);
          GNUNET_IDENTITY_request_peer_infos (sock2, &printInfo, NULL);

        }
      if (dotOutFile != NULL)
        {
          buf = GNUNET_malloc (18);
          snprintf (buf, 7, "\tn%s", (char *) host1entry);
          snprintf (&buf[6], 5, " -- ");
          snprintf (&buf[10], 6, "n%s", (char *) host2entry);
          fprintf (dotOutFile, "%s;\n", buf);
          GNUNET_free (buf);
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
  GNUNET_free (host1entry);
  GNUNET_free (host2entry);
  return ret;
}

int
GNUNET_REMOTE_get_daemons_information (char *hostname1, unsigned short port1,
                                       char *hostname2, unsigned short port2,
                                       GNUNET_EncName ** host1entry,
                                       GNUNET_EncName ** host2entry)
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
       GNUNET_wait_for_daemon_running (NULL, cfg1, 30 * GNUNET_CRON_SECONDS))
      && (GNUNET_OK ==
          GNUNET_wait_for_daemon_running (NULL, cfg2,
                                          30 * GNUNET_CRON_SECONDS)))
    {
      sock1 = GNUNET_client_connection_create (NULL, cfg1);
      sock2 = GNUNET_client_connection_create (NULL, cfg2);
      ret = -20;
      while ((ret++ < -1) && (GNUNET_shutdown_test () == GNUNET_NO))
        {
          h1 = NULL;
          h2 = NULL;
          if ((GNUNET_OK == GNUNET_IDENTITY_get_self (sock1, &h1))
              && (GNUNET_OK == GNUNET_IDENTITY_get_self (sock2, &h2)))
            {
              ret = GNUNET_OK;
              break;
            }

          GNUNET_thread_sleep (100 * GNUNET_CRON_MILLISECONDS);
        }

      GNUNET_hash_to_enc (&h1->senderIdentity.hashPubKey, *host1entry);
      GNUNET_hash_to_enc (&h2->senderIdentity.hashPubKey, *host2entry);

      GNUNET_free_non_null (h1);
      GNUNET_free_non_null (h2);

      GNUNET_client_connection_destroy (sock1);
      GNUNET_client_connection_destroy (sock2);
    }
  else
    {
      fprintf (stderr, _("Failed to establish connection with peers.\n"));
    }
  GNUNET_GC_free (cfg1);
  GNUNET_GC_free (cfg2);
  return ret;
}



/* end of remotetopologies.c */
