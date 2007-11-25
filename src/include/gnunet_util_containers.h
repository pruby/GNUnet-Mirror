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
 */
typedef GNUNET_HashCode *(*GNUNET_HashCodeIterator) (void *arg);

/**
 * @brief a GNUNET_Vector (ordered variable size set of elements), opaque
 */
struct GNUNET_Vector;

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

/**
 * A debug function that dumps the vector to stderr.
 */
void GNUNET_vector_dump (struct GNUNET_Vector *v);

/**
 * @param vss Size of the VectorSegment data area. The "correct" value for this
 * is a bit of a gamble, as it depends on both the operations you
 * perform on the vectors and how much data is stored in them. In
 * general, the more data you store the bigger the segments should be,
 * or otherwise the increased length of the linked list will become a
 * bottleneck for operations that are performed on arbitrary indexes.
 */
struct GNUNET_Vector *GNUNET_vector_create (unsigned int vss);

/**
 * Free vector structure including its data segments, but _not_ including the
 * stored void pointers. It is the user's responsibility to empty the vector
 * when necessary to avoid memory leakage.
 */
void GNUNET_vector_destroy (struct GNUNET_Vector *v);

size_t GNUNET_vector_get_size (struct GNUNET_Vector *v);

/**
 * Insert a new element in the vector at given index.
 * @return GNUNET_OK on success, GNUNET_SYSERR if the index is out of bounds.
 */
int GNUNET_vector_insert_at (struct GNUNET_Vector *v, void *object,
                             unsigned int index);

/**
 * Insert a new element at the end of the vector.
 */
void GNUNET_vector_insert_last (struct GNUNET_Vector *v, void *object);

/**
 * Return the element at given index in the vector or NULL if the index is out
 * of bounds. The iterator is set to point to the returned element.
 */
void *GNUNET_vector_get (struct GNUNET_Vector *v, unsigned int index);

/**
 * Return the first element in the vector, whose index is 0, or NULL if the
 * vector is empty. The iterator of the vector is set to point to the first
 * element.
 */
void *GNUNET_vector_get_first (struct GNUNET_Vector *v);

/**
 * Return the last element in the vector or NULL if the vector is empty. The
 * iterator of the vector is set to point to the last element.
 */
void *GNUNET_vector_get_last (struct GNUNET_Vector *v);

/**
 * Return the next element in the vector, as called after vector_get_at() or
 * vector_get_first(). The return value is NULL if there are no more elements
 * in the vector or if the iterator has not been set.
 */
void *GNUNET_vector_get_next (struct GNUNET_Vector *v);

/**
 * Return the previous element in the vector, as called after vector_get_at()
 * or vector_get_last(). The return value is NULL if there are no more
 * elements in the vector or if the iterator has not been set.
 */
void *GNUNET_vector_get_prev (struct GNUNET_Vector *v);

/**
 * Delete and return the element at given index. NULL is returned if index is
 * out of bounds.
 */
void *GNUNET_vector_delete_at (struct GNUNET_Vector *v, unsigned int index);

/**
 * Delete and return the last element in the vector, or NULL if the vector
 * is empty.
 */
void *GNUNET_vector_delete_last (struct GNUNET_Vector *v);

/**
 * Delete and return given object from the vector, or return NULL if the object
 * is not found.
 */
void *GNUNET_vector_delete (struct GNUNET_Vector *v, void *object);

/**
 * Set the given index in the vector. The old value of the index is
 * returned, or NULL if the index is out of bounds.
 */
void *GNUNET_vector_update_at (struct GNUNET_Vector *v, void *object,
                               unsigned int index);

/**
 * Set the index occupied by the given object to point to the new object.
 * The old object is returned, or NULL if it's not found.
 */
void *GNUNET_vector_update (struct GNUNET_Vector *v, void *object,
                            void *old_object);

/**
 * Swaps the contents of index1 and index2. Return value is GNUNET_OK
 * on success, GNUNET_SYSERR if either index is out of bounds.
 */
int GNUNET_vector_swap_elements (struct GNUNET_Vector *v, unsigned int index1,
                                 unsigned int index2);

/**
 * Return the index of given element or -1 if the element is not found.
 */
unsigned int GNUNET_vector_index_of (struct GNUNET_Vector *v, void *object);

/**
 * Return the data stored in the vector as a single dynamically
 * allocated array of (void *), which must be GNUNET_freeed by the caller.
 * Use the functions get_{at,first,last,next,previous} instead, unless
 * you really need to access everything in the vector as fast as
 * possible.
 */
void **GNUNET_vector_to_array (struct GNUNET_Vector *v);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_UTIL_CONTAINERS_H */
#endif
/* end of gnunet_util_containers.h */
