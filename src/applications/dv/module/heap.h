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
 * @file applications/dv/module/heap.h
 * @brief Definitions of heap operations
 */
#include "gnunet_core.h"
#include "dv.h"

#ifndef HEAP_H_
#define HEAP_H_

/*
 * Heap type, either max or min.  Hopefully makes the
 * implementation more useful.
 */
typedef enum
{
  GNUNET_DV_MAX_HEAP = 0,
  GNUNET_DV_MIN_HEAP = 1,
} GNUNET_DV_HeapType;

/*
 * Struct that is stored in hashmap, pointers to
 * locations in min_heap and max_heap.
 */
struct GNUNET_dv_heap_info
{
  struct GNUNET_dv_heap_node *min_loc;

  struct GNUNET_dv_heap_node *max_loc;

};

/*
 * Heap base structure, contains current size,
 * maximum allowed size, pointer to the root,
 * and the heap type (max or min)
 */
struct GNUNET_dv_heap
{
  unsigned int size;

  unsigned int max_size;

  GNUNET_DV_HeapType type;

  struct GNUNET_dv_heap_node *root;

  struct GNUNET_dv_heap_node *traversal_pos;

};

/*
 * Generic heap node structure, contains pointer to parent
 * left child, right child, and actual neighbor.
 */
struct GNUNET_dv_heap_node
{
  struct GNUNET_dv_heap_node *parent;

  struct GNUNET_dv_heap_node *left_child;

  struct GNUNET_dv_heap_node *right_child;

  struct GNUNET_dv_neighbor *neighbor;

};

/** FIXME:
 * Smart heap iterator and iterate functions are literal
 * prototypes, they are not yet implemented!!!  Heap needs
 * to be de-DV-ified.  Just here to remind me (nate) that
 * it still needs done!!!!!!!!!!!!!!
 */

/**
 * Iterator for heap
 *
 * @param value - obj stored in heap
 * @param cls - client arg passed through
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
typedef int (*GNUNET_HeapIterator) (void *value, void *cls);

/**
 * Iterate over all entries in the map.
 *
 * @param heap - the heap
 * @param iterator - function to call on each entry
 * @param cls - client argument (closure)
 * @return - number of items handled
 *         GNUNET_SYSERR if there's a problem
 */
int GNUNET_DV_heap_iterate (const struct GNUNET_dv_heap *heap,
                            GNUNET_HeapIterator iterator, void *cls);

/**
 * Simple stupid tree print.  Prints in depth first order.
 */
void printTree (struct GNUNET_dv_heap_node *root);

/**
 * Inserts a new item into the heap, item is always neighbor now.
 */
int
GNUNET_DV_Heap_insert (struct GNUNET_dv_heap *root,
                       struct GNUNET_dv_neighbor *neighbor);

/**
 * Removes root of the tree, is remove max if a max heap and remove min
 * if a min heap, returns the data stored at the node.
 */
struct GNUNET_dv_neighbor *GNUNET_DV_Heap_removeRoot (struct GNUNET_dv_heap
                                                      *root);

/**
 * Returns data stored at root of tree, doesn't affect anything
 */
struct GNUNET_dv_neighbor *GNUNET_DV_Heap_peekRoot (struct GNUNET_dv_heap
                                                    *root);

/**
 * Removes any node from the tree based on the neighbor given, does
 * not traverse the tree (backpointers) but may take more time due to
 * percolation of nodes.
 */
struct GNUNET_dv_neighbor *GNUNET_DV_Heap_removeNode (struct GNUNET_dv_heap
                                                      *root,
                                                      struct
                                                      GNUNET_dv_neighbor
                                                      *neighbor);

/**
 * Updates the cost of any node in the tree
 */
int
GNUNET_DV_Heap_updateCost (struct GNUNET_dv_heap *root,
                           struct GNUNET_dv_neighbor *neighbor,
                           unsigned int new_cost);

/**
 * Fixes the tree after a node's cost was externally modified
 */
int
GNUNET_DV_Heap_updatedCost (struct GNUNET_dv_heap *root,
                            struct GNUNET_dv_neighbor *neighbor);

/**
 * Iterator to go over all nodes in the tree... Goes from the bottom up
 */
void
GNUNET_DV_Heap_Iterator (void (*callee)
                         (struct GNUNET_dv_neighbor * neighbor,
                          struct GNUNET_dv_heap * root,
                          GNUNET_PeerIdentity * toMatch),
                         struct GNUNET_dv_heap *root,
                         struct GNUNET_dv_heap_node *node,
                         const GNUNET_PeerIdentity * toMatch);


/**
 * Random walk of the tree, returns the data stored at the next random node
 * in the walk.  Calls callee with the data, or NULL if the tree is empty
 * or some other problem crops up.
 */
struct GNUNET_dv_neighbor *GNUNET_DV_Heap_Walk_getNext (struct GNUNET_dv_heap
                                                        *root);


#endif /* HEAP_H_ */

/* end of heap.h */
