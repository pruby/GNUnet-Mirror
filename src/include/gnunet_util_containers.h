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
#include <extractor.h>

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/* ******************* bloomfilter ***************** */

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

/* ****************** metadata ******************* */

/**
 * Meta data to associate with a file, directory or namespace.
 */
struct GNUNET_MetaData;

/**
 * Iterator over meta data.
 * @return GNUNET_OK to continue to iterate, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_MetaDataProcessor) (EXTRACTOR_KeywordType type,
                                         const char *data, void *closure);

/**
 * Create a fresh MetaData token.
 */
struct GNUNET_MetaData *GNUNET_meta_data_create (void);

/**
 * Duplicate a MetaData token.
 */
struct GNUNET_MetaData *GNUNET_meta_data_duplicate (const struct
                                                    GNUNET_MetaData *meta);

/**
 * Free meta data.
 */
void GNUNET_meta_data_destroy (struct GNUNET_MetaData *md);

/**
 * Test if two MDs are equal.
 */
int GNUNET_meta_data_test_equal (const struct GNUNET_MetaData *md1,
                                 const struct GNUNET_MetaData *md2);


/**
 * Extend metadata.
 * @return GNUNET_OK on success, GNUNET_SYSERR if this entry already exists
 */
int GNUNET_meta_data_insert (struct GNUNET_MetaData *md,
                             EXTRACTOR_KeywordType type, const char *data);

/**
 * Remove an item.
 * @return GNUNET_OK on success, GNUNET_SYSERR if the item does not exist in md
 */
int GNUNET_meta_data_delete (struct GNUNET_MetaData *md,
                             EXTRACTOR_KeywordType type, const char *data);

/**
 * Add the current time as the publication date
 * to the meta-data.
 */
void GNUNET_meta_data_add_publication_date (struct GNUNET_MetaData *md);

/**
 * Iterate over MD entries, excluding thumbnails.
 *
 * @return number of entries
 */
int GNUNET_meta_data_get_contents (const struct GNUNET_MetaData *md,
                                   GNUNET_MetaDataProcessor
                                   iterator, void *closure);

/**
 * Get the first MD entry of the given type.
 * @return NULL if we do not have any such entry,
 *  otherwise client is responsible for freeing the value!
 */
char *GNUNET_meta_data_get_by_type (const struct GNUNET_MetaData
                                    *md, EXTRACTOR_KeywordType type);

/**
 * Get the first matching MD entry of the given types.
 * @paarm ... -1-terminated list of types
 * @return NULL if we do not have any such entry,
 *  otherwise client is responsible for freeing the value!
 */
char *GNUNET_meta_data_get_first_by_types (const struct
                                           GNUNET_MetaData *md, ...);

/**
 * Get a thumbnail from the meta-data (if present).
 *
 * @param thumb will be set to the thumbnail data.  Must be
 *        freed by the caller!
 * @return number of bytes in thumbnail, 0 if not available
 */
size_t GNUNET_meta_data_get_thumbnail (const struct GNUNET_MetaData
                                       *md, unsigned char **thumb);

/**
 * Extract meta-data from a file.
 *
 * @return GNUNET_SYSERR on error, otherwise the number
 *   of meta-data items obtained
 */
int GNUNET_meta_data_extract_from_file (struct GNUNET_GE_Context *ectx,
                                        struct GNUNET_MetaData *md,
                                        const char *filename,
                                        EXTRACTOR_ExtractorList * extractors);

/* = 0 */
#define GNUNET_SERIALIZE_FULL GNUNET_NO

/* = 1 */
#define GNUNET_SERIALIZE_PART GNUNET_YES

/* disallow compression (if speed is important) */
#define GNUNET_SERIALIZE_NO_COMPRESS 2


/**
 * Serialize meta-data to target.
 *
 * @param size maximum number of bytes available
 * @param part is it ok to just write SOME of the
 *        meta-data to match the size constraint,
 *        possibly discarding some data? GNUNET_YES/GNUNET_NO.
 * @return number of bytes written on success,
 *         GNUNET_SYSERR on error (typically: not enough
 *         space)
 */
int GNUNET_meta_data_serialize (struct GNUNET_GE_Context *ectx,
                                const struct GNUNET_MetaData *md,
                                char *target, unsigned int size, int part);

/**
 * Compute size of the meta-data in
 * serialized form.
 * @part flags (partial ok, may compress?)
 */
unsigned int GNUNET_meta_data_get_serialized_size (const struct
                                                   GNUNET_MetaData
                                                   *md, int part);

/**
 * Deserialize meta-data.  Initializes md.
 * @param size number of bytes available
 * @return MD on success, NULL on error (i.e.
 *         bad format)
 */
struct GNUNET_MetaData *GNUNET_meta_data_deserialize (struct
                                                      GNUNET_GE_Context
                                                      *ectx,
                                                      const char
                                                      *input,
                                                      unsigned int size);

/**
 * Does the meta-data claim that this is a directory?
 * Checks if the mime-type is that of a GNUnet directory.
 *
 * @return GNUNET_YES if it is, GNUNET_NO if it is not, GNUNET_SYSERR if
 *  we have no mime-type information (treat as 'GNUNET_NO')
 */
int GNUNET_meta_data_test_for_directory (const struct GNUNET_MetaData *md);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_UTIL_CONTAINERS_H */
#endif
/* end of gnunet_util_containers.h */
