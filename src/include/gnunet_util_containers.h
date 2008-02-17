/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_util_containers.h
 * @brief container classes for GNUnet
 *
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author Gerd Knorr <kraxel@bytesex.org>
 * @author Ioana Patrascu
 * @author Tzvetan Horozov
 * @author Nils Durner
 */

#ifndef GNUNET_UTIL_CONTAINERS_H
#define GNUNET_UTIL_CONTAINERS_H

/* add error and config prototypes */
#include "gnunet_util.h"
#include "gnunet_util_crypto.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * @brief bloomfilter representation (opaque)
 */
struct GNUNET_BloomFilter;

/**
 * Iterator over HashCodes.
 *
 * @return GNUNET_YES if next was updated
 *         GNUNET_NO if there are no more entries
 */
typedef int (*GNUNET_HashCodeIterator) (GNUNET_HashCode * next, void *arg);

/**
 * Load a bloom-filter from a file.
 * @param filename the name of the file (or the prefix)
 * @param size the size of the bloom-filter (number of
 *        bytes of storage space to use)
 * @param k the number of GNUNET_hash-functions to apply per
 *        element (number of bits set per element in the set)
 * @return the bloomfilter
 */
struct GNUNET_BloomFilter *GNUNET_bloomfilter_load (struct GNUNET_GE_Context
                                                    *ectx,
                                                    const char *filename,
                                                    unsigned int size,
                                                    unsigned int k);

/**
 * Create a bloom filter from raw bits.
 *
 * @param data the raw bits in memory (maybe NULL,
 *        in which case all bits should be considered
 *        to be zero).
 * @param size the size of the bloom-filter (number of
 *        bytes of storage space to use); also size of data
 *        -- unless data is NULL.  Must be a power of 2.
 * @param k the number of GNUNET_hash-functions to apply per
 *        element (number of bits set per element in the set)
 * @return the bloomfilter
 */
struct GNUNET_BloomFilter *GNUNET_bloomfilter_init (struct GNUNET_GE_Context
                                                    *ectx,
                                                    const char *data,
                                                    unsigned int size,
                                                    unsigned int k);

/**
 * Copy the raw data of this bloomfilter into
 * the given data array.
 *
 * @param data where to write the data
 * @param size the size of the given data array
 * @return GNUNET_SYSERR if the data array of the wrong size
 */
int GNUNET_bloomfilter_get_raw_data (struct GNUNET_BloomFilter *bf,
                                     char *data, unsigned int size);

/**
 * Test if an element is in the filter.
 * @param e the element
 * @param bf the filter
 * @return GNUNET_YES if the element is in the filter, GNUNET_NO if not
 */
int GNUNET_bloomfilter_test (struct GNUNET_BloomFilter *bf,
                             const GNUNET_HashCode * e);

/**
 * Add an element to the filter
 * @param bf the filter
 * @param e the element
 */
void GNUNET_bloomfilter_add (struct GNUNET_BloomFilter *bf,
                             const GNUNET_HashCode * e);

/**
 * Remove an element from the filter.
 * @param bf the filter
 * @param e the element to remove
 */
void GNUNET_bloomfilter_remove (struct GNUNET_BloomFilter *bf,
                                const GNUNET_HashCode * e);

/**
 * Free the space associcated with a filter
 * in memory, flush to drive if needed (do not
 * free the space on the drive)
 * @param bf the filter
 */
void GNUNET_bloomfilter_free (struct GNUNET_BloomFilter *bf);

/**
 * Reset a bloom filter to empty.
 * @param bf the filter
 */
void GNUNET_bloomfilter_clear (struct GNUNET_BloomFilter *bf);

/**
 * Or the entries of the given raw data array with the
 * data of the given bloom filter.  Assumes that
 * the size of the data array and the current filter
 * match.
 * @param bf the filter
 */
int GNUNET_bloomfilter_or (struct GNUNET_BloomFilter *bf,
                           const char *data, unsigned int size);

/**
 * Resize a bloom filter.  Note that this operation
 * is pretty costly.  Essentially, the bloom filter
 * needs to be completely re-build.
 *
 * @param bf the filter
 * @param iterator an iterator over all elements stored in the BF
 * @param iterator_arg argument to the iterator function
 * @param size the new size for the filter
 * @param k the new number of GNUNET_hash-function to apply per element
 */
void GNUNET_bloomfilter_resize (struct GNUNET_BloomFilter *bf,
                                GNUNET_HashCodeIterator iterator,
                                void *iterator_arg,
                                unsigned int size, unsigned int k);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_UTIL_CONTAINERS_H */
#endif
/* end of gnunet_util_containers.h */
