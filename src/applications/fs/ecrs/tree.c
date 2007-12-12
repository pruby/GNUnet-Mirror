/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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

#include "platform.h"
#include "gnunet_util.h"
#include "tree.h"

/**
 * Compute the depth of the tree.
 * @param flen file length for which to compute the depth
 * @return depth of the tree
 */
unsigned int
GNUNET_ECRS_compute_depth (unsigned long long flen)
{
  unsigned int treeDepth;
  unsigned long long fl;

  GNUNET_GE_ASSERT (NULL, DBLOCK_SIZE < GNUNET_MAX_BUFFER_SIZE);
  GNUNET_GE_ASSERT (NULL, IBLOCK_SIZE < GNUNET_MAX_BUFFER_SIZE);
  treeDepth = 0;
  fl = DBLOCK_SIZE;
  while (fl < flen)
    {
      treeDepth++;
      if (fl * CHK_PER_INODE < fl)
        {
          /* integer overflow, this is a HUGE file... */
          return treeDepth;
        }
      fl = fl * CHK_PER_INODE;
    }
  return treeDepth;
}
