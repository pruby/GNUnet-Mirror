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
 * @author Nathan Evans
 * @file applications/dv/module/dv_heaptest.c
 * @brief Test of heap operations in dv like conditions (churny)...
 */

#include "gnunet_util.h"
#include "gnunet_util_crypto.h"
#include "platform.h"
#include "heap.h"
#include "dv.h"
#include "../../../util/crypto/hostkey_gcrypt.c"

#define MAX_SIZE 100
#define TESTS 10
static int tempmaxsize;
static int tempminsize;
static int heapverify;

static int
count_max_callback (struct GNUNET_dv_neighbor *neighbor,
                    struct GNUNET_dv_heap *root, void *cls)
{
  tempmaxsize++;
  return 1;
}

static int
count_min_callback (struct GNUNET_dv_neighbor *neighbor,
                    struct GNUNET_dv_heap *root, void *cls)
{
  tempminsize++;
  return 1;
}

static int
heap_verify_callback (struct GNUNET_dv_neighbor *neighbor,
                      struct GNUNET_dv_heap *root, void *cls)
{
  int ret;
  ret = heapverify;
  if (root->type == GNUNET_CONTAINER_MAX_HEAP)
    {
      if ((neighbor->max_loc->left_child != NULL)
          && (neighbor->cost < neighbor->max_loc->left_child->neighbor->cost))
        {
          ret = GNUNET_SYSERR;
        }

      if ((neighbor->max_loc->right_child != NULL)
          && (neighbor->cost <
              neighbor->max_loc->right_child->neighbor->cost))
        {
          ret = GNUNET_SYSERR;
        }
    }
  else if (root->type == GNUNET_CONTAINER_MIN_HEAP)
    {
      if ((neighbor->min_loc->left_child != NULL)
          && (neighbor->cost > neighbor->min_loc->left_child->neighbor->cost))
        {
          ret = GNUNET_SYSERR;
        }

      if ((neighbor->min_loc->right_child != NULL)
          && (neighbor->cost >
              neighbor->min_loc->right_child->neighbor->cost))
        {
          ret = GNUNET_SYSERR;
        }
    }

  heapverify = ret;
  return ret;
}


static int
iterator_callback (struct GNUNET_dv_neighbor *neighbor,
                   struct GNUNET_dv_heap *root, void *cls)
{
  fprintf (stdout, "%d\n", neighbor->cost);

  return GNUNET_OK;
}

static int
check_node (struct GNUNET_dv_neighbor *neighbor)
{
  if ((neighbor->max_loc->neighbor == neighbor)
      && (neighbor->min_loc->neighbor == neighbor))
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
}


int
main (int argc, char **argv)
{
  struct GNUNET_RSA_PrivateKey *hostkey;
  GNUNET_RSA_PublicKey pubkey;

  struct GNUNET_dv_heap *minHeap;
  struct GNUNET_dv_heap *maxHeap;
  int i;
  int j;
  int ret;
  int cur_pos = 0;
  unsigned int temp_rand;
  unsigned int temp_node;
  //int seq[6] = {0, 0, 0, 3, 3, 0};
  //int vals[6] = {70, 26, 53, 100, 35, 95};
  struct GNUNET_dv_neighbor *neighbors[TESTS];
  ret = GNUNET_OK;
  maxHeap = GNUNET_CONTAINER_heap_create(GNUNET_MAX_HEAP);
  minHeap = GNUNET_CONTAINER_heap_create(GNUNET_MIN_HEAP);

  for (i = 0; i < TESTS; i++)
    {
      neighbors[i] = NULL;
    }

  for (i = 0; i < TESTS; i++)
    //for (i = 0;i<6;i++)
    {
      temp_rand = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 5);
      while ((cur_pos <= 1) && (temp_rand != 0))
        temp_rand = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 5);
      //temp_rand = seq[i];
      switch (temp_rand)
        {
        case 0:
        case 1:
          temp_rand = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 100) + 1;
          fprintf (stderr, "Adding node with cost %d\n", temp_rand);
          neighbors[cur_pos] = malloc (sizeof (struct GNUNET_dv_neighbor));
          neighbors[cur_pos]->neighbor =
            malloc (sizeof (GNUNET_PeerIdentity));
          hostkey = GNUNET_RSA_create_key ();
          GNUNET_RSA_get_public_key (hostkey, &pubkey);
          GNUNET_hash (&pubkey, sizeof (GNUNET_RSA_PublicKey),
                       &neighbors[cur_pos]->neighbor->hashPubKey);
          //neighbors[cur_pos]->cost = temp_rand;
          neighbors[cur_pos]->cost = temp_rand;
          GNUNET_CONTAINER_heap_insert (maxHeap, neighbors[cur_pos]);
          GNUNET_CONTAINER_heap_insert (minHeap, neighbors[cur_pos]);
          cur_pos++;
          break;

        case 2:
          temp_node = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, cur_pos);
          temp_rand = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 100) + 1;
          fprintf (stderr, "Updating node %d (cost %d) with new cost %d\n",
                   temp_node + 1, neighbors[temp_node]->cost, temp_rand);
          GNUNET_CONTAINER_heap_update_cost (maxHeap, neighbors[temp_node],
                                     temp_rand);
          GNUNET_CONTAINER_heap_update_Cost (minHeap, neighbors[temp_node],
                                     temp_rand);
          break;
        case 3:
          fprintf (stderr, "Removing node %d with cost %d\n", cur_pos,
                   neighbors[cur_pos - 1]->cost);
          GNUNET_CONTAINER_heap_remove_node (maxHeap, neighbors[cur_pos - 1]);
          GNUNET_CONTAINER_heap_remove_node (minHeap, neighbors[cur_pos - 1]);
          GNUNET_free (neighbors[cur_pos - 1]->neighbor);
          GNUNET_free (neighbors[cur_pos - 1]);
          neighbors[cur_pos - 1] = NULL;
          cur_pos--;
          break;
        case 4:
          //fprintf(stderr, "Removing matching nodes\n");
          break;
        }

      if (ret != GNUNET_OK)
        return GNUNET_SYSERR;

    }

  return 0;
}

/* end of heaptest.c */
