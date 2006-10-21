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
 *
 * TODO: refactor APIs (more consistent naming conventions, etc.)
 */

#ifndef GNUNET_UTIL_CONTAINERS_H
#define GNUNET_UTIL_CONTAINERS_H

/* add error and config prototypes */
#include "gnunet_util.h"
#include "gnunet_util_crypto.h"

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * @brief bloomfilter representation (opaque)
 */
struct Bloomfilter;

/**
 * Iterator over all HashCodes stored in a Bloomfilter.
 */
typedef HashCode512 * (*ElementIterator)(void * arg);

/**
 * @brief a Vector (ordered variable size set of elements), opaque
 */
struct Vector;

/**
 * @brief a hash table, opaque
 */
struct HashTable;

/**
 * Load a bloom-filter from a file.
 * @param filename the name of the file (or the prefix)
 * @param size the size of the bloom-filter (number of
 *        bytes of storage space to use)
 * @param k the number of hash-functions to apply per
 *        element (number of bits set per element in the set)
 * @return the bloomfilter
 */
struct Bloomfilter * loadBloomfilter(struct GE_Context * ectx,
				     const char * filename,
				     unsigned int size,
				     unsigned int k);

/**
 * Test if an element is in the filter.
 * @param e the element
 * @param bf the filter
 * @return YES if the element is in the filter, NO if not
 */
int testBloomfilter(struct Bloomfilter * bf,
		    const HashCode512 * e);

/**
 * Add an element to the filter
 * @param bf the filter
 * @param e the element
 */
void addToBloomfilter(struct Bloomfilter * bf,
		      const HashCode512 * e);

/**
 * Remove an element from the filter.
 * @param bf the filter
 * @param e the element to remove
 */
void delFromBloomfilter(struct Bloomfilter * bf,
			const HashCode512 * e);

/**
 * Free the space associcated with a filter
 * in memory, flush to drive if needed (do not
 * free the space on the drive)
 * @param bf the filter
 */
void freeBloomfilter(struct Bloomfilter * bf);

/**
 * Reset a bloom filter to empty.
 * @param bf the filter
 */
void resetBloomfilter(struct Bloomfilter * bf);

/**
 * Resize a bloom filter.  Note that this operation
 * is pretty costly.  Essentially, the bloom filter
 * needs to be completely re-build.
 *
 * @param bf the filter
 * @param iterator an iterator over all elements stored in the BF
 * @param iterator_arg argument to the iterator function
 * @param size the new size for the filter
 * @param k the new number of hash-function to apply per element
 */
void resizeBloomfilter(struct Bloomfilter * bf,
		       ElementIterator iterator,
		       void * iterator_arg,
		       unsigned int size,
		       unsigned int k);

/**
 * A debug function that dumps the vector to stderr.
 */
void vectorDump(struct Vector *v);

/**
 * @param vss Size of the VectorSegment data area. The "correct" value for this
 * is a bit of a gamble, as it depends on both the operations you
 * perform on the vectors and how much data is stored in them. In
 * general, the more data you store the bigger the segments should be,
 * or otherwise the increased length of the linked list will become a
 * bottleneck for operations that are performed on arbitrary indexes.
 */
struct Vector * vectorNew(unsigned int vss);

/**
 * Free vector structure including its data segments, but _not_ including the
 * stored void pointers. It is the user's responsibility to empty the vector
 * when necessary to avoid memory leakage.
 */
void vectorFree(struct Vector * v);

size_t vectorSize(struct Vector * v);

/**
 * Insert a new element in the vector at given index.
 * @return OK on success, SYSERR if the index is out of bounds.
 */
int vectorInsertAt(struct Vector * v,
		   void * object,
		   unsigned int index);

/**
 * Insert a new element at the end of the vector.
 */
void vectorInsertLast(struct Vector * v, void * object);

/**
 * Return the element at given index in the vector or NULL if the index is out
 * of bounds. The iterator is set to point to the returned element.
 */
void * vectorGetAt(struct Vector * v,
		   unsigned int index);

/**
 * Return the first element in the vector, whose index is 0, or NULL if the
 * vector is empty. The iterator of the vector is set to point to the first
 * element.
 */
void * vectorGetFirst(struct Vector * v);

/**
 * Return the last element in the vector or NULL if the vector is empty. The
 * iterator of the vector is set to point to the last element.
 */
void * vectorGetLast(struct Vector * v);

/**
 * Return the next element in the vector, as called after vector_get_at() or
 * vector_get_first(). The return value is NULL if there are no more elements
 * in the vector or if the iterator has not been set.
 */
void * vectorGetNext(struct Vector * v);

/**
 * Return the previous element in the vector, as called after vector_get_at()
 * or vector_get_last(). The return value is NULL if there are no more
 * elements in the vector or if the iterator has not been set.
 */
void * vectorGetPrevious(struct Vector * v);

/**
 * Delete and return the element at given index. NULL is returned if index is
 * out of bounds.
 */
void * vectorRemoveAt(struct Vector * v,
		      unsigned int index);

/**
 * Delete and return the last element in the vector, or NULL if the vector
 * is empty.
 */
void * vectorRemoveLast(struct Vector * v);

/**
 * Delete and return given object from the vector, or return NULL if the object
 * is not found.
 */
void * vectorRemoveObject(struct Vector * v, void * object);

/**
 * Set the given index in the vector. The old value of the index is
 * returned, or NULL if the index is out of bounds.
 */
void * vectorSetAt(struct Vector * v,
		   void * object,
		   unsigned int index);

/**
 * Set the index occupied by the given object to point to the new object.
 * The old object is returned, or NULL if it's not found.
 */
void * vectorSetObject(struct Vector * v,
		       void * object,
		       void * old_object);

/**
 * Swaps the contents of index1 and index2. Return value is OK
 * on success, SYSERR if either index is out of bounds.
 */
int vectorSwap(struct Vector * v,
	       unsigned int index1,
	       unsigned int index2);

/**
 * Return the index of given element or -1 if the element is not found.
 */
unsigned int vectorIndexOf(struct Vector * v,
			   void * object);

/**
 * Return the data stored in the vector as a single dynamically
 * allocated array of (void *), which must be FREEed by the caller.
 * Use the functions get_{at,first,last,next,previous} instead, unless
 * you really need to access everything in the vector as fast as
 * possible.
 */
void ** vectorElements(struct Vector * v);

/**
 * @brief creates a new HashTable
 * @param numOfBuckets the number of buckets to start the HashTable out with.
 *                     Must be greater than zero, and should be prime.
 *                     Ideally, the number of buckets should between 1/5
 *                     and 1 times the expected number of elements in the
 *                     HashTable.  Values much more or less than this will
 *                     result in wasted memory or decreased performance
 *                     respectively.  The number of buckets in a HashTable
 *                     can be re-calculated to an appropriate number by
 *                     calling the HashTableRehash() function once the
 *                     HashTable has been populated.  The number of buckets
 *                     in a HashTable may also be re-calculated
 *                     automatically if the ratio of elements to buckets
 *                     passes the thresholds set by ht_setIdealRatio().
 * @return a new Hashtable, or NULL on error
 */
struct HashTable *ht_create(long numOfBuckets);

/**
 * @brief destroys an existing HashTable
 * @param hashTable the HashTable to destroy
 */
void ht_destroy(struct HashTable *hashTable);

/**
 * @brief checks the existence of a key in a HashTable
 * @param hashTable the HashTable to search
 * @param key the key to search for
 * @return whether or not the specified HashTable contains the
 *         specified key
 */
int ht_containsKey(const struct HashTable *hashTable, const void *key, const unsigned int keylen);

/**
 * @brief checks the existence of a value in a HashTable
 * @param hashTable the HashTable to search
 * @param value the value to search for
 * @return whether or not the specified HashTable contains the
 *         specified value
 */
int ht_containsValue(const struct HashTable *hashTable, const void *value, const unsigned int valuelen);

/**
 * @brief adds a key/value pair to a HashTable
 * @param hashTable the HashTable to add to
 * @param key the key to add or whose value to replace
 * @param value the value associated with the key
 * @return 0 if successful, -1 if an error was encountered
 */
int ht_put(struct HashTable *hashTable,
	   const void *key,
	   const unsigned int keylen,
	   void *value,
	   const unsigned int valuelen);

/**
 * @brief retrieves the value of a key in a HashTable
 * @param hashTable the HashTable to search
 * @param key the key whose value is desired
 * @param value the corresponding value
 * @param valuelen the length of the value
 * @return YES if found, NO otherwise
 */
int ht_get(const struct HashTable *hashTable,
	   const void *key,
	   const unsigned int keylen,
	   void **value,
	   unsigned int *valuelen);

/**
 * @brief removes a key/value pair from a HashTable
 * @param hashTable the HashTable to remove the key/value pair from
 * @param key the key specifying the key/value pair to be removed
 */
void ht_remove(struct HashTable *hashTable,
	       const void *key,
	       const unsigned int keylen);

/**
 * @brief removes all key/value pairs from a HashTable
 * @param hashTable the HashTable to remove all key/value pairs from
 */
void ht_removeAll(struct HashTable *hashTable);

/**
 * @brief returns the number of elements in a HashTable
 * @param hashTable the HashTable whose size is requested
 * @return the number of key/value pairs that are present in
 *         the specified HashTable
 */
long ht_size(const struct HashTable *hashTable);

/**
 * @brief returns the number of buckets in a HashTable
 * @param hashTable the HashTable whose number of buckets is requested
 * @return the number of buckets that are in the specified
 *         HashTable
 */
long ht_buckets(const struct HashTable *hashTable);

/**
 * @brief reorganizes a HashTable to be more efficient
 * @param hashTable the HashTable to be reorganized
 * @param numOfBuckets the number of buckets to rehash the HashTable to.
 *                     Should be prime.  Ideally, the number of buckets
 *                     should be between 1/5 and 1 times the expected
 *                     number of elements in the HashTable.  Values much
 *                     more or less than this will result in wasted memory
 *                     or decreased performance respectively.  If 0 is
 *                     specified, an appropriate number of buckets is
 *                     automatically calculated.
 */
void ht_rehash(struct HashTable *hashTable,
	       long numOfBuckets);

/**
 * @brief sets the ideal element-to-bucket ratio of a HashTable
 * @param hashTable a HashTable
 * @param idealRatio the ideal element-to-bucket ratio.  When a rehash
 *                   occurs (either manually via a call to the
 *                   HashTableRehash() function or automatically due the
 *                   the triggering of one of the thresholds below), the
 *                   number of buckets in the HashTable will be
 *                   recalculated to be a prime number that achieves (as
 *                   closely as possible) this ideal ratio.  Must be a
 *                   positive number.
 * @param lowerRehashThreshold the element-to-bucket ratio that is considered
 *                     unacceptably low (i.e., too few elements per bucket).
 *                     If the actual ratio falls below this number, a
 *                     rehash will automatically be performed.  Must be
 *                     lower than the value of idealRatio.  If no ratio
 *                     is considered unacceptably low, a value of 0.0 can
 *                     be specified.
 * @param upperRehashThreshold the element-to-bucket ratio that is considered
 *                     unacceptably high (i.e., too many elements per bucket).
 *                     If the actual ratio rises above this number, a
 *                     rehash will automatically be performed.  Must be
 *                     higher than idealRatio.  However, if no ratio
 *                     is considered unacceptably high, a value of 0.0 can
 *                     be specified.
 */
void ht_setIdealRatio(struct HashTable *hashTable,
		      float idealRatio,
		      float lowerRehashThreshold,
		      float upperRehashThreshold);

#define HT_PUT(ht, key, val) ht_put(ht, key, sizeof(key), val, sizeof(val))
#define HT_GET(ht, key, val, vallen) ht_get(ht, key, sizeof(key), val, vallen)
#define HT_CONTAINS_KEY(ht, key) ht_containsKey(ht, key, sizeof(key))
#define HT_CONTAINS_VALUE(ht, value) ht_containsValue(ht, value, sizeof(value))
#define HT_REMOVE(ht, key) ht_remove(ht, key, sizeof(key))

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_UTIL_CONTAINERS_H */
#endif
/* end of gnunet_util_containers.h */
