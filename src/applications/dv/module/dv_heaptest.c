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
#include "dv.h"
#include "../../../util/crypto/hostkey_gcrypt.c"

#define MAX_SIZE 100
#define TESTS 75


int
main (int argc, char **argv)
{
  struct GNUNET_RSA_PrivateKey *hostkey;
  GNUNET_RSA_PublicKey pubkey;

  struct GNUNET_CONTAINER_Heap *minHeap;
  struct GNUNET_CONTAINER_Heap *maxHeap;
  int i;
  int ret;
  int cur_pos = 0;
  unsigned int temp_rand;
  unsigned int temp_node;

  struct GNUNET_dv_neighbor *neighbors[TESTS];
  ret = GNUNET_OK;
  maxHeap = GNUNET_CONTAINER_heap_create (GNUNET_MAX_HEAP);
  minHeap = GNUNET_CONTAINER_heap_create (GNUNET_MIN_HEAP);

  for (i = 0; i < TESTS; i++)
    {
      neighbors[i] = NULL;
    }

  for (i = 0; i < TESTS; i++)
    {
      temp_rand = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 5);
      while ((cur_pos <= 1) && (temp_rand != 0))
        temp_rand = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 5);
      fprintf(stderr, "size is %d\n", GNUNET_CONTAINER_heap_get_size(minHeap));
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
          neighbors[cur_pos]->cost = temp_rand;
          GNUNET_CONTAINER_heap_insert (maxHeap, neighbors[cur_pos],
                                        temp_rand);
          GNUNET_CONTAINER_heap_insert (minHeap, neighbors[cur_pos],
                                        temp_rand);
          cur_pos++;
          break;

        case 2:
          temp_node = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, cur_pos);
          temp_rand = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 100) + 1;
          fprintf (stderr, "Updating node %d (cost %d) with new cost %d\n",
                   temp_node + 1, neighbors[temp_node]->cost, temp_rand);
          GNUNET_CONTAINER_heap_update_cost (maxHeap, neighbors[temp_node],
                                             temp_rand);
          GNUNET_CONTAINER_heap_update_cost (minHeap, neighbors[temp_node],
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
          break;
        }

      if (ret != GNUNET_OK)
        return GNUNET_SYSERR;

    }
  GNUNET_CONTAINER_heap_destroy (minHeap);
  return 0;
}

/* end of heaptest.c */
