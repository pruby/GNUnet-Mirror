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

#if VERBOSE
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
#endif

static int
addNodeRefs (struct GNUNET_REMOTE_host_list *node1pos,
             struct GNUNET_REMOTE_host_list *node2pos)
{
  struct GNUNET_REMOTE_friends_list *node1temp;
  struct GNUNET_REMOTE_friends_list *node2temp;

  GNUNET_EncName node1enc;
  GNUNET_EncName node2enc;

  struct GNUNET_REMOTE_friends_list *node1iter;
  struct GNUNET_REMOTE_friends_list *node2iter;
  int added;
  int addNode1 = 1;
  int addNode2 = 1;

  node1iter = node1pos->friend_entries;
  node2iter = node2pos->friend_entries;

  GNUNET_hash_to_enc (&node1pos->peer->hashPubKey, &node1enc);
  GNUNET_hash_to_enc (&node2pos->peer->hashPubKey, &node2enc);

  while (node2iter != NULL)
    {
      if (memcmp (node2iter->nodeid, &node1enc, sizeof (GNUNET_EncName)) == 0)
        addNode2 = 0;
      node2iter = node2iter->next;
    }

  while (node1iter != NULL)
    {
      if (memcmp (node1iter->nodeid, &node2enc, sizeof (GNUNET_EncName)) == 0)
        addNode1 = 0;
      node1iter = node1iter->next;
    }
  added = 0;
  if (addNode1)
    {
      node1temp = GNUNET_malloc (sizeof (struct GNUNET_REMOTE_friends_list));
      node1temp->nodeid = GNUNET_malloc (sizeof (GNUNET_EncName));
      memcpy (node1temp->nodeid, &node2enc, sizeof (GNUNET_EncName));
      node1temp->next = node1pos->friend_entries;
      node1temp->hostentry = node2pos;
      node1pos->friend_entries = node1temp;
      added++;
    }

  if (addNode2)
    {
      node2temp = GNUNET_malloc (sizeof (struct GNUNET_REMOTE_friends_list));
      node2temp->hostentry = node1pos;
      node2temp->nodeid = GNUNET_malloc (sizeof (GNUNET_EncName));
      memcpy (node2temp->nodeid, &node1enc, sizeof (GNUNET_EncName));
      node2temp->next = node2pos->friend_entries;
      node2pos->friend_entries = node2temp;
      added++;
    }

  return added;
}

int
GNUNET_REMOTE_connect_nated_internet (double nat_percentage,
                                      int number_of_daemons,
                                      struct GNUNET_REMOTE_host_list
                                      *main_list, FILE * dotOutFile)
{
  unsigned int count, inner_count;
  int is_nat, inner_is_nat, can_connect;
  unsigned int cutoff;
  struct GNUNET_REMOTE_host_list *pos = main_list;
  struct GNUNET_REMOTE_host_list *iter_pos = main_list;

  cutoff = (unsigned int) (nat_percentage * number_of_daemons);

  count = 0;
  while ((pos != NULL) && (pos->next != NULL))
    {
      if (count < cutoff)
        is_nat = GNUNET_YES;
      else
        is_nat = GNUNET_NO;
      inner_count = count + 1;
      iter_pos = pos->next;
      while (iter_pos != NULL)
        {
          if (inner_count < cutoff)
            inner_is_nat = GNUNET_YES;
          else
            inner_is_nat = GNUNET_NO;
          can_connect = GNUNET_YES;

          if ((is_nat == GNUNET_YES) && (inner_is_nat == GNUNET_YES))
            {
              can_connect = GNUNET_NO;
            }

          if (GNUNET_YES == can_connect)
            {
              addNodeRefs (pos, iter_pos);
            }
          iter_pos = iter_pos->next;
          inner_count++;
        }
      pos = pos->next;
      count++;
    }

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

  while ((pos != NULL) && (pos->next != NULL))
    {
      iter_pos = pos->next;
      while (iter_pos != NULL)
        {
          temp_rand = ((double) RANDOM () / RAND_MAX);
#if VERBOSE
          fprintf (stderr, _("rand is %f probability is %f\n"), temp_rand,
                   probability);
#endif
          if (temp_rand < probability)
            {
              addNodeRefs (pos, iter_pos);
            }

          iter_pos = iter_pos->next;
        }
      pos = pos->next;
    }

  return GNUNET_OK;
}

int
GNUNET_REMOTE_connect_clique (struct GNUNET_REMOTE_host_list *main_list,
                              FILE * dotOutFile)
{
  struct GNUNET_REMOTE_host_list *pos = main_list;
  struct GNUNET_REMOTE_host_list *iter_pos = main_list;

  while ((pos != NULL) && (pos->next != NULL))
    {
      iter_pos = pos->next;
      while (iter_pos != NULL)
        {
          addNodeRefs (pos, iter_pos);
          iter_pos = iter_pos->next;
        }
      pos = pos->next;
    }

  return GNUNET_OK;
}

int
GNUNET_REMOTE_connect_ring (struct GNUNET_REMOTE_host_list *main_list,
                            FILE * dotOutFile)
{
  struct GNUNET_REMOTE_host_list *pos = main_list;
  struct GNUNET_REMOTE_host_list *iter_pos = main_list;

  while (pos->next != NULL)
    {
      iter_pos = pos->next;
      addNodeRefs (pos, iter_pos);
      pos = pos->next;
    }
  iter_pos = main_list;
  addNodeRefs (pos, iter_pos);

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
#if VERBOSE
  fprintf (stderr,
           _("Connecting nodes in 2d torus topology: %u rows %u columns\n"),
           rows, cols);
#endif
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
#if VERBOSE
      fprintf (stderr, _("connecting node %u to %u\n"), i, nodeToConnect);
#endif

      addNodeRefs (list_as_array[i], list_as_array[nodeToConnect]);

      /* Second connect to the node immediately above */
      if (i < cols)
        nodeToConnect = (rows * cols) - cols + i;
      else
        nodeToConnect = i - cols;

      if (nodeToConnect < number_of_daemons)
        {
#if VERBOSE
          fprintf (stderr, _("connecting node %u to %u\n"), i, nodeToConnect);
#endif
          addNodeRefs (list_as_array[i], list_as_array[nodeToConnect]);
        }

    }

  return GNUNET_OK;
}

int
GNUNET_REMOTE_connect_small_world (unsigned int number_of_daemons,
                                   struct GNUNET_REMOTE_host_list
                                   **list_as_array, FILE * dotOutFile,
                                   double percentage)
{
  unsigned int i, j, k;
  unsigned int square;
  unsigned int rows;
  unsigned int cols;
  unsigned int toggle = 1;
  unsigned int nodeToConnect;
  unsigned int natLog;
  unsigned int node1Row;
  unsigned int node1Col;
  unsigned int node2Row;
  unsigned int node2Col;
  unsigned int distance;
  double probability, random;
  unsigned int totalConnections, smallWorldConnections;

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
#if VERBOSE
  fprintf (stderr,
           _("Connecting nodes in 2d torus topology: %u rows %u columns\n"),
           rows, cols);
#endif

  totalConnections = 0;
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
#if VERBOSE
      fprintf (stderr, _("connecting node %u to %u\n"), i, nodeToConnect);
#endif
      totalConnections += addNodeRefs (list_as_array[i],
                                       list_as_array[nodeToConnect]);

      if (i < cols)
        nodeToConnect = (rows * cols) - cols + i;
      else
        nodeToConnect = i - cols;

      if (nodeToConnect < number_of_daemons)
        {
#if VERBOSE
          fprintf (stderr, _("connecting node %u to %u\n"), i, nodeToConnect);
#endif
          totalConnections += addNodeRefs (list_as_array[i],
                                           list_as_array[nodeToConnect]);
        }

    }

  natLog = log (number_of_daemons);
#if VERBOSE
  fprintf (stderr, _("natural log of %d is %d, will run %d iterations\n"),
           number_of_daemons, natLog, (int) (natLog * percentage));
  fprintf (stderr, _("Total connections added thus far: %d!\n"),
           totalConnections);
#endif
  smallWorldConnections = 0;
  for (i = 0; i < (int) (natLog * percentage); i++)
    {
      for (j = 0; j < number_of_daemons; j++)
        {
          /* Determine the row and column of node at position j on the 2d torus */
          node1Row = j / cols;
          node1Col = j - (node1Row * cols);
          for (k = 0; k < number_of_daemons; k++)
            {
              /* Determine the row and column of node at position k on the 2d torus */
              node2Row = k / cols;
              node2Col = k - (node2Row * cols);
              /* Simple Cartesian distance */
              distance =
                abs (node1Row - node2Row) + abs (node1Col - node2Col);
              if (distance > 1)
                {
                  /* Calculate probability as 1 over the square of the distance */
                  probability = 1.0 / (distance * distance);
                  /* Choose a random, divide by RAND_MAX to get a number between 0 and 1 */
                  random = ((double) rand () / RAND_MAX);
                  /* If random < probability, then connect the two nodes */
                  if (random < probability)
                    {
                      smallWorldConnections +=
                        addNodeRefs (list_as_array[j], list_as_array[k]);
                    }
                }
            }
        }
    }
  totalConnections += smallWorldConnections;
#if VERBOSE
  fprintf (stderr, _("Total connections added for small world: %d!\n"),
           smallWorldConnections);
#endif

  return GNUNET_OK;
}

int
GNUNET_REMOTE_connect_small_world_ring (unsigned int number_of_daemons,
                                        struct GNUNET_REMOTE_host_list
                                        **list_as_array, FILE * dotOutFile,
                                        double percentage,
                                        double logNModifier)
{
  unsigned int i, j;
  int nodeToConnect;
  unsigned int natLog;
  unsigned int randomPeer;
  double random;
  unsigned int totalConnections, smallWorldConnections;
  int connsPerPeer;
  natLog = log (number_of_daemons);
  connsPerPeer = ceil (natLog * logNModifier);
  int max;
  int min;
  unsigned int useAnd;

  if (connsPerPeer % 2 == 1)
    connsPerPeer += 1;

  srand ((unsigned int) GNUNET_get_time ());
  smallWorldConnections = 0;
  totalConnections = 0;
  for (i = 0; i < number_of_daemons; i++)
    {
      useAnd = 0;
      max = i + connsPerPeer / 2;
      min = i - connsPerPeer / 2;

      if (max > number_of_daemons - 1)
        {
          max = max - number_of_daemons;
          useAnd = 1;
        }

      if (min < 0)
        {
          min = number_of_daemons - 1 + min;
          useAnd = 1;
        }
#if VERBOSE
      fprintf (stderr,
               _
               ("For peer %d, number must be less than %d or greater than %d (%d)\n"),
               i, min, max, useAnd);
#endif
      for (j = 0; j < connsPerPeer / 2; j++)
        {
          random = ((double) rand () / RAND_MAX);
          if (random < percentage)
            {
              /* Connect to uniformly selected random peer */
              randomPeer =
                GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                                   number_of_daemons);
              while ((((randomPeer < max) && (randomPeer > min))
                      && (useAnd == 0)) || (((randomPeer > min)
                                             || (randomPeer < max))
                                            && (useAnd == 1)))
                {
#if VERBOSE
                  fprintf (stderr,
                           _
                           ("NOT connecting node %u to %u (already existing connection!)\n"),
                           i, randomPeer);
#endif
                  randomPeer =
                    GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                                       number_of_daemons);
                }
#if VERBOSE
              fprintf (stderr, _("connecting node (rewire) %u to %u\n"), i,
                       randomPeer);
#endif
              smallWorldConnections +=
                addNodeRefs (list_as_array[i], list_as_array[randomPeer]);
            }
          else
            {
              nodeToConnect = i + j + 1;
              if (nodeToConnect > number_of_daemons - 1)
                {
                  nodeToConnect = nodeToConnect - number_of_daemons;
                }
#if VERBOSE
              fprintf (stderr, _("connecting node %u to %u\n"), i,
                       nodeToConnect);
#endif
              totalConnections +=
                addNodeRefs (list_as_array[i], list_as_array[nodeToConnect]);
            }
        }

    }

  totalConnections += smallWorldConnections;
#if VERBOSE
  fprintf (stderr, _("Total connections added for small world: %d!\n"),
           smallWorldConnections);
  fprintf (stderr, _("Total connections: %d!\n"), totalConnections);
#endif

  return GNUNET_OK;
}

/**
* Establish a connection between two GNUnet daemons
*
* @param port1 client port of the first daemon
* @param port2 client port of the second daemon
* @param ip1 client ip or hostname for the first daemon
* @param ip2 client ip or hostname for the second daemon
* @param dotOutFile file to write dot style graph info to
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
#if VERBOSE
  fprintf (stderr, _("Setting config 1 to host %s\n"), host);
#endif
  GNUNET_snprintf (host, 128, "%s:%u", hostname2, port2);
  GNUNET_GC_set_configuration_value_string (cfg2, NULL, "NETWORK", "HOST",
                                            host);

#if VERBOSE
  fprintf (stderr, _("Setting config 2 to host %s\n"), host);
#endif

  if ((GNUNET_OK ==
       GNUNET_wait_for_daemon_running (NULL, cfg1, 30 * GNUNET_CRON_SECONDS))
      && (GNUNET_OK ==
          GNUNET_wait_for_daemon_running (NULL, cfg2,
                                          30 * GNUNET_CRON_SECONDS)))
    {
      sock1 = GNUNET_client_connection_create (NULL, cfg1);
      sock2 = GNUNET_client_connection_create (NULL, cfg2);
      ret = -20;
#if VERBOSE
      fprintf (stderr, _("Waiting for peers to connect"));
#endif
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

      if (ret == GNUNET_OK)
        {
          GNUNET_hash_to_enc (&h1->senderIdentity.hashPubKey, host1entry);
          GNUNET_hash_to_enc (&h2->senderIdentity.hashPubKey, host2entry);
        }

      GNUNET_free_non_null (h1);
      GNUNET_free_non_null (h2);

      if (ret != GNUNET_OK)
        {
#if VERBOSE
          fprintf (stderr,
                   _("\nFailed to connect `%s' and `%s'\n"),
                   (const char *) host1entry, (const char *) host2entry);
          fprintf (stderr, _("Connections of `%s':\n"),
                   (const char *) host1entry);
          GNUNET_IDENTITY_request_peer_infos (sock1, &printInfo, NULL);
          fprintf (stderr, _("Connections of `%s':\n"),
                   (const char *) host2entry);
          GNUNET_IDENTITY_request_peer_infos (sock2, &printInfo, NULL);
#endif
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
#if VERBOSE
      fprintf (stderr, "%s\n", ret == GNUNET_OK ? "Connected nodes." : "?");
#endif
      GNUNET_client_connection_destroy (sock1);
      GNUNET_client_connection_destroy (sock2);
    }
  else
    {
#if VERBOSE
      fprintf (stderr, _("Failed to establish connection with peers.\n"));
#endif
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
#if VERBOSE
      fprintf (stderr, _("Failed to establish connection with peers.\n"));
#endif
    }
  GNUNET_GC_free (cfg1);
  GNUNET_GC_free (cfg2);
  return ret;
}

GNUNET_PeerIdentity *
GNUNET_REMOTE_get_daemon_information (char *hostname, unsigned short port)
{
  char host[128];
  struct GNUNET_GC_Configuration *cfg1 = GNUNET_GC_create ();
  struct GNUNET_ClientServerConnection *sock1;
  GNUNET_PeerIdentity *retval;
  int ret;
  GNUNET_MessageHello *h1;

  ret = GNUNET_SYSERR;
  GNUNET_snprintf (host, 128, "%s:%u", hostname, port);
  GNUNET_GC_set_configuration_value_string (cfg1, NULL, "NETWORK", "HOST",
                                            host);

  retval = NULL;
  if (GNUNET_OK ==
      GNUNET_wait_for_daemon_running (NULL, cfg1, 30 * GNUNET_CRON_SECONDS))
    {
      sock1 = GNUNET_client_connection_create (NULL, cfg1);

      ret = -20;
      while ((ret++ < -1) && (GNUNET_shutdown_test () == GNUNET_NO))
        {
          h1 = NULL;

          if (GNUNET_OK == GNUNET_IDENTITY_get_self (sock1, &h1))
            {
              ret = GNUNET_OK;
              break;
            }

          GNUNET_thread_sleep (100 * GNUNET_CRON_MILLISECONDS);
        }
      if (ret == GNUNET_OK)
        {
          retval = GNUNET_malloc (sizeof (GNUNET_PeerIdentity));
          memcpy (retval, &h1->senderIdentity, sizeof (GNUNET_PeerIdentity));
        }

      GNUNET_free_non_null (h1);

      GNUNET_client_connection_destroy (sock1);
    }
  else
    {
#if VERBOSE
      fprintf (stderr, _("Failed to establish connection with peers.\n"));
#endif
    }
  GNUNET_GC_free (cfg1);
  if (ret != GNUNET_SYSERR)
    return retval;
  else
    return NULL;
}


/* end of remotetopologies.c */
