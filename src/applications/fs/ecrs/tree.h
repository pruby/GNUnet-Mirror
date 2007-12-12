/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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

#ifndef TREE_H
#define TREE_H

#include "ecrs_core.h"

/**
 * Size of a DBlock.  Should be a multiple of 8 and larger than
 * sizeof(CHK).
 */
#define DBLOCK_SIZE 32768

/**
 * Pick a multiple of 2 here to achive 8-byte alignment!
 * We also probably want DBlocks to have (roughly) the
 * same size as IBlocks.  With SHA-512, the optimal
 * value is 32768 byte / 128 byte = 256
 * (128 byte = 2 * 512 bits).
 */
#define CHK_PER_INODE 256

/**
 * You cannot change this one (directly).  Ideally
 * CHK_PER_INODE is chosen such that
 * IBLOCK_SIZE == DBLOCK_SIZE.
 */
#define IBLOCK_SIZE (CHK_PER_INODE * sizeof(CHK))

/**
 * Compute the depth of the tree.
 * @param flen file length for which to compute the depth
 * @return depth of the tree
 */
unsigned int GNUNET_ECRS_compute_depth (unsigned long long flen);

#endif
