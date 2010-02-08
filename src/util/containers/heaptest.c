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
 * @file util/containers/heaptest.c
 * @brief Test of heap operations in churny like conditions...
 */

#include "gnunet_util.h"
#include "gnunet_util_crypto.h"
#include "platform.h"

#define MAX_SIZE 100
#define TESTS 75
#define DEBUG GNUNET_NO

/* Test struct so we have something to actually
 * put into the heap */

struct GNUNET_neighbor
{

  /**
   * Identity of neighbor.
   */
  unsigned int neighbor;

  /**
   * Cost to neighbor
   */
  unsigned int cost;
};

static struct GNUNET_CONTAINER_Heap *minHeap;
static struct GNUNET_CONTAINER_Heap *maxHeap;
static int cur_pos = 0;
struct GNUNET_neighbor *neighbors[TESTS];

static int
iterator_callback (void *cls,
                   struct GNUNET_CONTAINER_HeapNode * node,
                   void *element,
                   GNUNET_CONTAINER_HeapCostType cost)
{
  struct GNUNET_neighbor *neighbor = element;
  struct GNUNET_neighbor *to_remove = cls;

  if (to_remove == neighbor)
  {
#if DEBUG
  fprintf(stderr, "Iterating, removing: neighbor %u with cost %u\n", neighbor->neighbor, neighbor->cost);
#endif
    GNUNET_CONTAINER_heap_remove_node (maxHeap, node);
    GNUNET_free (neighbors[cur_pos - 1]);
    neighbors[cur_pos - 1] = NULL;
    cur_pos--;
  }
  return GNUNET_YES;

}

int
main (int argc, char **argv)
{
  int i;
  int ret;

  unsigned int temp_rand;
  unsigned int temp_node;
  unsigned int temp_id;

  struct GNUNET_CONTAINER_HeapNode *min_nodes[TESTS];
  struct GNUNET_CONTAINER_HeapNode *max_nodes[TESTS];

  ret = GNUNET_OK;
  maxHeap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MAX);
  minHeap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);

  for (i = 0; i < TESTS; i++)
    {
      neighbors[i] = NULL;
    }

  for (i = 0; i < TESTS; i++)
    {
      temp_rand = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 5);
      while ((cur_pos <= 1) && (temp_rand != 0))
        temp_rand = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 5);

      switch (temp_rand)
        {
        case 0:
        case 1:
          temp_rand = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 100) + 1;
          temp_id =
            GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 100000) + 1;
#if DEBUG
          fprintf (stderr, "Adding node with cost %d\n", temp_rand);
#endif
          neighbors[cur_pos] =
            GNUNET_malloc (sizeof (struct GNUNET_neighbor));
          neighbors[cur_pos]->neighbor = temp_id;
          neighbors[cur_pos]->cost = temp_rand;
          max_nodes[cur_pos] =
            GNUNET_CONTAINER_heap_insert (maxHeap, neighbors[cur_pos],
                                          temp_rand);
          min_nodes[cur_pos] =
            GNUNET_CONTAINER_heap_insert (minHeap, neighbors[cur_pos],
                                          temp_rand);
          cur_pos++;
          break;

        case 2:
          temp_node = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, cur_pos);
          temp_rand = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 100) + 1;
#if DEBUG
          fprintf (stderr, "Updating node %d (cost %d) with new cost %d\n",
                   temp_node + 1, neighbors[temp_node]->cost, temp_rand);
#endif
          GNUNET_CONTAINER_heap_update_cost (maxHeap, max_nodes[temp_node],
                                             temp_rand);
          GNUNET_CONTAINER_heap_update_cost (minHeap, min_nodes[temp_node],
                                             temp_rand);
          neighbors[temp_node]->cost = temp_rand;
          break;
        case 3:
#if DEBUG
          fprintf (stderr, "Removing node %d with cost %d\n", cur_pos,
                   neighbors[cur_pos - 1]->cost);
#endif
          GNUNET_CONTAINER_heap_remove_node (maxHeap, max_nodes[cur_pos - 1]);
          GNUNET_CONTAINER_heap_remove_node (minHeap, min_nodes[cur_pos - 1]);
          GNUNET_free (neighbors[cur_pos - 1]);
          neighbors[cur_pos - 1] = NULL;
          cur_pos--;
          break;
        case 4:
#if DEBUG
          fprintf (stderr, "First removing from minheap, pre removal size is %d\n", GNUNET_CONTAINER_heap_get_size(minHeap));
#endif
          GNUNET_CONTAINER_heap_remove_node (minHeap, min_nodes[cur_pos - 1]);
#if DEBUG
          fprintf (stderr, "removal from minheap, post removal size is %d\n", GNUNET_CONTAINER_heap_get_size(minHeap));
          fprintf (stderr, "Iterating over heap, pre removal size is %d\n", GNUNET_CONTAINER_heap_get_size(maxHeap));
#endif
          GNUNET_CONTAINER_heap_iterate(maxHeap, &iterator_callback, neighbors[cur_pos - 1]);
#if DEBUG
          fprintf (stderr, "post removal size is %d\n", GNUNET_CONTAINER_heap_get_size(maxHeap));
#endif

          break;
        }

      if (ret != GNUNET_OK)
        return GNUNET_SYSERR;

    }



  while (GNUNET_CONTAINER_heap_get_size (maxHeap) > 0)
    {
      GNUNET_CONTAINER_heap_remove_root (maxHeap);
    }

  while (GNUNET_CONTAINER_heap_get_size (minHeap) > 0)
    {
      GNUNET_CONTAINER_heap_remove_root (minHeap);
    }

  GNUNET_CONTAINER_heap_destroy (maxHeap);
  GNUNET_CONTAINER_heap_destroy (minHeap);
  return 0;
}

/* end of heaptest.c */
