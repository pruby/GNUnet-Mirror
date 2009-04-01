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

#ifndef HEAP_H_
#define HEAP_H_

typedef unsigned int GNUNET_CostType;

/*
 * Heap type, either max or min.  Hopefully makes the
 * implementation more useful.
 */
typedef enum
{
  GNUNET_MAX_HEAP = 0,
  GNUNET_MIN_HEAP = 1,
} GNUNET_CONTAINER_HeapType;

/*
 * Struct that is stored in hashmap, pointers to
 * locations in min_heap and max_heap.
 */
struct GNUNET_CONTAINER_Heap;

/** FIXME:
 * Heap needs to be de-DV-ified.  Just here to remind me
 * (nate) that it still needs done!!!!!!!!!!!!!!
 */

struct GNUNET_CONTAINER_Heap *
GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HeapType type);

void
GNUNET_CONTAINER_heap_destroy (struct GNUNET_CONTAINER_Heap * h);


/** FIXME:
 * Heap needs to be de-DV-ified.  Just here to remind me
 * (nate) that it still needs done!!!!!!!!!!!!!!
 */

/**
 * Iterator for heap
 *
 * @param value - obj stored in heap
 * @param root - root of heap in which obj is stored
 * @param cls - client arg passed through
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
typedef int (*GNUNET_CONTAINER_HeapIterator) (void * element,
                GNUNET_CostType cost,
                struct GNUNET_CONTAINER_Heap * root,
                void *cls);

/**
 * Iterate over all entries in the map.
 *
 * @param heap - the heap
 * @param iterator - function to call on each entry
 * @param cls - client argument (closure)
 * @return - number of items handled
 *         GNUNET_SYSERR if there's a problem
 */
int GNUNET_CONTAINER_heap_iterate (struct GNUNET_CONTAINER_Heap *heap,
                            GNUNET_CONTAINER_HeapIterator iterator, void *cls);


/**
 * Inserts a new item into the heap, item is always neighbor now.
 */
int
GNUNET_CONTAINER_heap_insert (struct GNUNET_CONTAINER_Heap *root,
                       void * element, GNUNET_CostType cost);

/**
 * Removes root of the tree, is remove max if a max heap and remove min
 * if a min heap, returns the data stored at the node.
 */
void *GNUNET_CONTAINER_heap_remove_root (struct GNUNET_CONTAINER_Heap *root);

/**
 * Returns data stored at root of tree, doesn't effect anything
 */
void *GNUNET_CONTAINER_heap_peek (struct GNUNET_CONTAINER_Heap *root);

/**
 * Removes any node from the tree based on the neighbor given, does
 * not traverse the tree (backpointers) but may take more time due to
 * percolation of nodes.
 */
void *GNUNET_CONTAINER_heap_remove_node (struct GNUNET_CONTAINER_Heap *root,
                                 void *element);

/**
 * Updates the cost of any node in the tree
 */
int
GNUNET_CONTAINER_heap_update_cost (struct GNUNET_CONTAINER_Heap *root,
                           void * element,
                           GNUNET_CostType new_cost);

/**
 * Random walk of the tree, returns the data stored at the next random node
 * in the walk.  Calls callee with the data, or NULL if the tree is empty
 * or some other problem crops up.
 */
void *GNUNET_CONTAINER_heap_walk_get_next (struct GNUNET_CONTAINER_Heap
                                                        *root);

void
printTree (struct GNUNET_CONTAINER_Heap *root);

/*
 * Returns the current size of the heap
 *
 * @param heap the heap to get the size of
 */
unsigned int
GNUNET_CONTAINER_heap_get_size(struct GNUNET_CONTAINER_Heap *heap);
#endif /* HEAP_H_ */

/* end of heap.h */
