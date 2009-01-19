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
 * @file applications/dv/module/heaptest.c
 * @brief Test of heap operations
 */

#include "heap.h"
#include "dv.h"


static int
iterator_callback (struct GNUNET_dv_neighbor *neighbor,
                   struct GNUNET_dv_heap *root, void *cls)
{
  fprintf (stdout, "%d\n", neighbor->cost);

  return GNUNET_OK;
}


int
main (int argc, char **argv)
{
  struct GNUNET_dv_heap *myHeap;
  struct GNUNET_dv_neighbor *neighbor1;
  struct GNUNET_dv_neighbor *neighbor2;
  struct GNUNET_dv_neighbor *neighbor3;
  struct GNUNET_dv_neighbor *neighbor4;
  struct GNUNET_dv_neighbor *neighbor5;
  struct GNUNET_dv_neighbor *neighbor6;

  myHeap = malloc (sizeof (struct GNUNET_dv_heap));
  myHeap->type = GNUNET_DV_MAX_HEAP;
  myHeap->max_size = 10;
  myHeap->size = 0;

  neighbor1 = malloc (sizeof (struct GNUNET_dv_neighbor));
  neighbor2 = malloc (sizeof (struct GNUNET_dv_neighbor));
  neighbor3 = malloc (sizeof (struct GNUNET_dv_neighbor));
  neighbor4 = malloc (sizeof (struct GNUNET_dv_neighbor));
  neighbor5 = malloc (sizeof (struct GNUNET_dv_neighbor));
  neighbor6 = malloc (sizeof (struct GNUNET_dv_neighbor));

  neighbor1->cost = 60;
  neighbor2->cost = 50;
  neighbor3->cost = 70;
  neighbor4->cost = 120;
  neighbor5->cost = 100;
  neighbor6->cost = 30;

  GNUNET_DV_Heap_insert (myHeap, neighbor1);
  fprintf (stdout, "\n");
  printTree (myHeap->root);

  GNUNET_DV_Heap_insert (myHeap, neighbor2);
  fprintf (stdout, "\n");
  printTree (myHeap->root);

  GNUNET_DV_Heap_insert (myHeap, neighbor3);
  fprintf (stdout, "\n");
  printTree (myHeap->root);

  GNUNET_DV_Heap_insert (myHeap, neighbor4);
  fprintf (stdout, "\n");
  printTree (myHeap->root);

  GNUNET_DV_Heap_insert (myHeap, neighbor5);
  fprintf (stdout, "\n");
  printTree (myHeap->root);

  GNUNET_DV_Heap_insert (myHeap, neighbor6);
  fprintf (stdout, "\n");
  printTree (myHeap->root);

  GNUNET_DV_Heap_removeNode (myHeap, neighbor5);
  fprintf (stdout, "\n");
  printTree (myHeap->root);

  GNUNET_DV_Heap_removeRoot (myHeap);
  fprintf (stdout, "\n");
  printTree (myHeap->root);

  GNUNET_DV_Heap_updateCost (myHeap, neighbor6, 200);
  fprintf (stdout, "\n");
  printTree (myHeap->root);

  GNUNET_DV_Heap_Iterator (myHeap, myHeap->root, iterator_callback, NULL);
  return 0;
}

/* end of heaptest.c */
