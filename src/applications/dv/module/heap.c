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
 * @file applications/dv/module/heap.c
 * @brief Implementation of heap operations
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_util.h"
#include "dv.h"
#include "heap.h"

void
printTree (struct GNUNET_dv_heap_node *root)
{
  if (root->neighbor != NULL)
    {
      fprintf (stdout, "%d\n", root->neighbor->cost);
      if (root->left_child != NULL)
        {
          fprintf (stdout, "LEFT of %d\n", root->neighbor->cost);
          printTree (root->left_child);
        }
      if (root->right_child != NULL)
        {
          fprintf (stdout, "RIGHT of %d\n", root->neighbor->cost);
          printTree (root->right_child);
        }
    }
}

static struct GNUNET_dv_heap_node *
getNextPos (struct GNUNET_dv_heap *root)
{
  struct GNUNET_dv_heap_node *ret;
  struct GNUNET_dv_heap_node *parent;
  int pos;
  int depth;
  int i;

  ret = GNUNET_malloc (sizeof (struct GNUNET_dv_heap_node));
  pos = root->size + 1;
  depth = (int) log2 (pos);
  ret->left_child = NULL;
  ret->right_child = NULL;

  if (depth == 0)
    {
      ret->parent = NULL;
      root->root = ret;
    }
  else
    {
      parent = root->root;
      for (i = depth; i > 1; i--)
        {
          if (((pos / (1 << (i - 1))) % 2) == 0)
            parent = parent->left_child;
          else
            parent = parent->right_child;
        }

      ret->parent = parent;
      if ((pos % 2) == 0)
        parent->left_child = ret;
      else
        parent->right_child = ret;

    }

  return ret;

}

static struct GNUNET_dv_heap_node *
getPos (struct GNUNET_dv_heap *root, unsigned int pos)
{
  struct GNUNET_dv_heap_node *ret;

  int depth;
  int i;

  depth = (int) log2 (pos);
  ret = NULL;
  if (pos > root->size)
    {
      return ret;
    }
  else
    {
      ret = root->root;
      for (i = depth; i > 0; i--)
        {
          if (((pos / (1 << (i - 1))) % 2) == 0)
            ret = ret->left_child;
          else
            ret = ret->right_child;
        }
    }

  return ret;

}

void
swapNodes (struct GNUNET_dv_heap_node *first,
           struct GNUNET_dv_heap_node *second, struct GNUNET_dv_heap *root)
{
  struct GNUNET_dv_neighbor *tempNeighbor;

  tempNeighbor = first->neighbor;
  first->neighbor = second->neighbor;
  second->neighbor = tempNeighbor;

  if ((root->type == GNUNET_DV_MAX_HEAP))
    {
      first->neighbor->max_loc = first;
      second->neighbor->max_loc = second;
    }
  else if ((root->type == GNUNET_DV_MIN_HEAP))
    {
      first->neighbor->min_loc = first;
      second->neighbor->min_loc = second;
    }

  return;
}

void
percolateHeap (struct GNUNET_dv_heap_node *pos, struct GNUNET_dv_heap *root)
{

  while ((pos->parent != NULL) &&
         (((root->type == GNUNET_DV_MAX_HEAP)
           && (pos->parent->neighbor->cost < pos->neighbor->cost))
          || ((root->type == GNUNET_DV_MIN_HEAP)
              && (pos->parent->neighbor->cost > pos->neighbor->cost))))
    {
      swapNodes (pos, pos->parent, root);
      pos = pos->parent;
    }

  return;
}



void
percolateDownHeap (struct GNUNET_dv_heap_node *pos,
                   struct GNUNET_dv_heap *root)
{
  struct GNUNET_dv_heap_node *switchNeighbor;

  switchNeighbor = pos;

  if ((root->type == GNUNET_DV_MAX_HEAP))
    {
      if ((pos->left_child != NULL)
          && (pos->left_child->neighbor->cost >
              switchNeighbor->neighbor->cost))
        {
          switchNeighbor = pos->left_child;
        }

      if ((pos->right_child != NULL)
          && (pos->right_child->neighbor->cost >
              switchNeighbor->neighbor->cost))
        {
          switchNeighbor = pos->right_child;
        }
    }
  else if ((root->type == GNUNET_DV_MIN_HEAP))
    {
      if ((pos->left_child != NULL)
          && (pos->left_child->neighbor->cost <
              switchNeighbor->neighbor->cost))
        {
          switchNeighbor = pos->left_child;
        }

      if ((pos->right_child != NULL)
          && (pos->right_child->neighbor->cost <
              switchNeighbor->neighbor->cost))
        {
          switchNeighbor = pos->right_child;
        }
    }

  if (switchNeighbor != pos)
    {
      swapNodes (switchNeighbor, pos, root);
      percolateDownHeap (switchNeighbor, root);
    }

  return;
}

struct GNUNET_dv_neighbor *
GNUNET_DV_Heap_removeNode (struct GNUNET_dv_heap *root,
                           struct GNUNET_dv_neighbor *neighbor)
{
  struct GNUNET_dv_neighbor *ret;
  struct GNUNET_dv_heap_node *del_node;
  struct GNUNET_dv_heap_node *last;

  del_node = NULL;
  if (root->type == GNUNET_DV_MAX_HEAP)
    del_node = neighbor->max_loc;
  else if (root->type == GNUNET_DV_MIN_HEAP)
    del_node = neighbor->min_loc;

  if (del_node == NULL)
    return NULL;

  ret = del_node->neighbor;
  last = getPos (root, root->size);
  if (root->type == GNUNET_DV_MAX_HEAP)
    last->neighbor->max_loc = del_node->neighbor->max_loc;
  else if (root->type == GNUNET_DV_MIN_HEAP)
    last->neighbor->min_loc = del_node->neighbor->min_loc;

  del_node->neighbor = last->neighbor;

  if (last->parent->left_child == last)
    last->parent->left_child = NULL;
  if (last->parent->right_child == last)
    last->parent->right_child = NULL;

  if (root->traversal_pos == last)
    {
      root->traversal_pos = root->root;
    }
  GNUNET_free (last);
  root->size--;

  if (del_node->neighbor->cost > ret->cost)
    {
      if (root->type == GNUNET_DV_MAX_HEAP)
        percolateHeap (del_node, root);
      else if (root->type == GNUNET_DV_MIN_HEAP)
        percolateDownHeap (del_node, root);
    }
  else if (del_node->neighbor->cost < ret->cost)
    {
      if (root->type == GNUNET_DV_MAX_HEAP)
        percolateDownHeap (del_node, root);
      else if (root->type == GNUNET_DV_MIN_HEAP)
        percolateHeap (del_node, root);
    }

  return ret;
}

int
GNUNET_DV_Heap_insert (struct GNUNET_dv_heap *root,
                       struct GNUNET_dv_neighbor *neighbor)
{
  struct GNUNET_dv_heap_node *new_pos;
  int ret;
  ret = GNUNET_YES;

  if (root->max_size > root->size)
    {
      new_pos = getNextPos (root);
      new_pos->neighbor = neighbor;
      root->size++;
      if (root->type == GNUNET_DV_MIN_HEAP)
        new_pos->neighbor->min_loc = new_pos;
      else if (root->type == GNUNET_DV_MAX_HEAP)
        new_pos->neighbor->max_loc = new_pos;
      percolateHeap (new_pos, root);
    }
  else
    {
      ret = GNUNET_NO;
    }

  return ret;
}

struct GNUNET_dv_neighbor *
GNUNET_DV_Heap_removeRoot (struct GNUNET_dv_heap *root)
{
  struct GNUNET_dv_neighbor *ret;
  struct GNUNET_dv_heap_node *root_node;
  struct GNUNET_dv_heap_node *last;

  root_node = root->root;
  ret = root_node->neighbor;
  last = getPos (root, root->size);

  if (last->parent->left_child == last)
    last->parent->left_child = NULL;
  else if (last->parent->right_child == last)
    last->parent->right_child = NULL;

  root_node->neighbor = last->neighbor;

  if (root->traversal_pos == last)
    {
      root->traversal_pos = root->root;
    }

  GNUNET_free (last);
  root->size--;
  percolateDownHeap (root->root, root);
  return ret;
}

int
GNUNET_DV_Heap_updateCost (struct GNUNET_dv_heap *root,
                           struct GNUNET_dv_neighbor *neighbor,
                           unsigned int new_cost)
{
  int ret = GNUNET_YES;
  neighbor->cost = new_cost;

  ret = GNUNET_DV_Heap_updatedCost (root, neighbor);
  return ret;
}

int
GNUNET_DV_Heap_updatedCost (struct GNUNET_dv_heap *root,
                            struct GNUNET_dv_neighbor *neighbor)
{
  struct GNUNET_dv_heap_node *node;
  struct GNUNET_dv_heap_node *parent;

  if (neighbor == NULL)
    return GNUNET_SYSERR;

  if ((root->type == GNUNET_DV_MAX_HEAP) && (neighbor->max_loc != NULL))
    {
      node = neighbor->max_loc;
    }
  else if ((root->type == GNUNET_DV_MIN_HEAP) && (neighbor->min_loc != NULL))
    {
      node = neighbor->min_loc;
    }
  else
    return GNUNET_SYSERR;

  parent = node->parent;

  if ((root->type == GNUNET_DV_MAX_HEAP) && (parent != NULL)
      && (node->neighbor->cost > parent->neighbor->cost))
    percolateHeap (neighbor->max_loc, root);
  else if ((root->type == GNUNET_DV_MIN_HEAP) && (parent != NULL)
           && (node->neighbor->cost < parent->neighbor->cost))
    percolateHeap (neighbor->min_loc, root);
  else if (root->type == GNUNET_DV_MAX_HEAP)
    percolateDownHeap (neighbor->max_loc, root);
  else if (root->type == GNUNET_DV_MIN_HEAP)
    percolateDownHeap (neighbor->min_loc, root);

  return GNUNET_YES;
}

int
GNUNET_DV_Heap_delete_matching_referrers (struct GNUNET_dv_heap *root,
                                          struct GNUNET_dv_heap_node *node,
                                          GNUNET_PeerIdentity * toMatch)
{
  int count = 0;
  if (node->left_child != NULL)
    {
      count +=
        GNUNET_DV_Heap_delete_matching_referrers (root, node->left_child,
                                                  toMatch);
    }
  if (node->right_child != NULL)
    {
      count +=
        GNUNET_DV_Heap_delete_matching_referrers (root, node->right_child,
                                                  toMatch);
    }
  if ((node->neighbor != NULL)
      &&
      (memcmp (node->neighbor, toMatch, sizeof (GNUNET_PeerIdentity)) == 0))
    {
      GNUNET_DV_Heap_removeNode (root, node->neighbor);
      count++;
    }

  return count;

}

void
GNUNET_DV_Heap_Iterator (struct GNUNET_dv_heap *root,
                         struct GNUNET_dv_heap_node *node,
                         GNUNET_HeapIterator iterator, void *cls)
{

  if (node->left_child != NULL)
    {
      GNUNET_DV_Heap_Iterator (root, node->left_child, iterator, cls);
    }

  if (node->right_child != NULL)
    {
      GNUNET_DV_Heap_Iterator (root, node->right_child, iterator, cls);
    }

  if (node->neighbor != NULL)
    {
      iterator (node->neighbor, root, cls);
    }
}

struct GNUNET_dv_neighbor *
GNUNET_DV_Heap_Walk_getNext (struct GNUNET_dv_heap *root)
{
  unsigned int choice;
  struct GNUNET_dv_neighbor *neighbor;

  if ((root->traversal_pos == NULL) && (root->root != NULL))
    {
      root->traversal_pos = root->root;
    }

  if (root->traversal_pos == NULL)
    return NULL;

  neighbor = root->traversal_pos->neighbor;

  choice = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 2);

  switch (choice)
    {
    case 1:
      root->traversal_pos = root->traversal_pos->right_child;
      break;
    case 0:
      root->traversal_pos = root->traversal_pos->left_child;
      break;
    }

  return neighbor;

}

/* end of heap.h */
