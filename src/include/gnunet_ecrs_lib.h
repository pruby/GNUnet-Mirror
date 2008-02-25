/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_ecrs_lib.h
 * @brief support for ECRS encoding of files
 * @author Christian Grothoff
 */

#ifndef GNUNET_ECRS_LIB_H
#define GNUNET_ECRS_LIB_H

#include "gnunet_util_core.h"
#include "gnunet_core.h"
#include <extractor.h>

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Just the version number of the AFS/ESED/ESED2/ECRS implementation.
 * History:
 *
 * 1.x.x: initial version with triple GNUNET_hash and merkle tree
 * 2.x.x: root node with mime-type, filename and version number
 * 2.1.x: combined CHK/3HASH encoding with 25:1 super-nodes
 * 2.2.x: with directories
 * 3.0.x: with namespaces
 * 3.1.x: with namespace meta-data
 * 3.2.x: with collections
 * 4.0.x: with expiration, variable meta-data, kblocks
 * 4.1.x: with new error and configuration handling
 * 5.0.x: with location URIs
 * 6.x.x: who knows? :-)
 */
#define GNUNET_ECRS_VERSION "5.1.0"

#define GNUNET_DIRECTORY_MIME  "application/gnunet-directory"
#define GNUNET_DIRECTORY_MAGIC "\211GND\r\n\032\n"
#define GNUNET_DIRECTORY_EXT   ".gnd"


#define GNUNET_ECRS_URI_PREFIX      "gnunet://ecrs/"
#define GNUNET_ECRS_SEARCH_INFIX    "ksk/"
#define GNUNET_ECRS_SUBSPACE_INFIX  "sks/"
#define GNUNET_ECRS_FILE_INFIX      "chk/"
#define GNUNET_ECRS_LOCATION_INFIX  "loc/"


/**
 * Fixed SBlock updateInterval codes. Positive values
 * are interpreted as durations (in seconds) for periodical
 * updates.
 */
#define GNUNET_ECRS_SBLOCK_UPDATE_SPORADIC  -1
#define GNUNET_ECRS_SBLOCK_UPDATE_NONE       0



/* ***************** metadata API (meta.c) ******************** */

/**
 * Meta data to associate with a file, directory or namespace.
 */
struct GNUNET_ECRS_MetaData;

/**
 * Iterator over meta data.
 * @return GNUNET_OK to continue to iterate, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_ECRS_MetaDataProcessor) (EXTRACTOR_KeywordType type,
                                              const char *data,
                                              void *closure);

/**
 * Iterator over keywords
 * @return GNUNET_OK to continue to iterate, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_ECRS_KeywordIterator) (const char *data, void *closure);

/**
 * Create a fresh MetaData token.
 */
struct GNUNET_ECRS_MetaData *GNUNET_ECRS_meta_data_create (void);

/**
 * Duplicate a MetaData token.
 */
struct GNUNET_ECRS_MetaData *GNUNET_ECRS_meta_data_duplicate (const struct
                                                              GNUNET_ECRS_MetaData
                                                              *meta);

/**
 * Free meta data.
 */
void GNUNET_ECRS_meta_data_destroy (struct GNUNET_ECRS_MetaData *md);

/**
 * Test if two MDs are equal.
 */
int GNUNET_ECRS_meta_data_test_equal (const struct GNUNET_ECRS_MetaData *md1,
                                      const struct GNUNET_ECRS_MetaData *md2);


/**
 * Extend metadata.
 * @return GNUNET_OK on success, GNUNET_SYSERR if this entry already exists
 */
int GNUNET_ECRS_meta_data_insert (struct GNUNET_ECRS_MetaData *md,
                                  EXTRACTOR_KeywordType type,
                                  const char *data);

/**
 * Remove an item.
 * @return GNUNET_OK on success, GNUNET_SYSERR if the item does not exist in md
 */
int GNUNET_ECRS_meta_data_delete (struct GNUNET_ECRS_MetaData *md,
                                  EXTRACTOR_KeywordType type,
                                  const char *data);

/**
 * Add the current time as the publication date
 * to the meta-data.
 */
void GNUNET_ECRS_meta_data_add_publication_date (struct GNUNET_ECRS_MetaData
                                                 *md);

/**
 * Iterate over MD entries, excluding thumbnails.
 *
 * @return number of entries
 */
int GNUNET_ECRS_meta_data_get_contents (const struct GNUNET_ECRS_MetaData *md,
                                        GNUNET_ECRS_MetaDataProcessor
                                        iterator, void *closure);

/**
 * Get the first MD entry of the given type.
 * @return NULL if we do not have any such entry,
 *  otherwise client is responsible for freeing the value!
 */
char *GNUNET_ECRS_meta_data_get_by_type (const struct GNUNET_ECRS_MetaData
                                         *md, EXTRACTOR_KeywordType type);

/**
 * Get the first matching MD entry of the given types.
 * @paarm ... -1-terminated list of types
 * @return NULL if we do not have any such entry,
 *  otherwise client is responsible for freeing the value!
 */
char *GNUNET_ECRS_meta_data_get_first_by_types (const struct
                                                GNUNET_ECRS_MetaData *md,
                                                ...);

/**
 * Get a thumbnail from the meta-data (if present).
 *
 * @param thumb will be set to the thumbnail data.  Must be
 *        freed by the caller!
 * @return number of bytes in thumbnail, 0 if not available
 */
size_t GNUNET_ECRS_meta_data_get_thumbnail (const struct GNUNET_ECRS_MetaData
                                            *md, unsigned char **thumb);

/**
 * Extract meta-data from a file.
 *
 * @return GNUNET_SYSERR on error, otherwise the number
 *   of meta-data items obtained
 */
int GNUNET_ECRS_meta_data_extract_from_file (struct GNUNET_GE_Context *ectx,
                                             struct GNUNET_ECRS_MetaData *md,
                                             const char *filename,
                                             EXTRACTOR_ExtractorList *
                                             extractors);

/* = 0 */
#define GNUNET_ECRS_SERIALIZE_FULL GNUNET_NO

/* = 1 */
#define GNUNET_ECRS_SERIALIZE_PART GNUNET_YES

/* disallow compression (if speed is important) */
#define GNUNET_ECRS_SERIALIZE_NO_COMPRESS 2


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
int GNUNET_ECRS_meta_data_serialize (struct GNUNET_GE_Context *ectx,
                                     const struct GNUNET_ECRS_MetaData *md,
                                     char *target, unsigned int size,
                                     int part);

/**
 * Compute size of the meta-data in
 * serialized form.
 * @part flags (partial ok, may compress?)
 */
unsigned int GNUNET_ECRS_meta_data_get_serialized_size (const struct
                                                        GNUNET_ECRS_MetaData
                                                        *md, int part);

/**
 * Deserialize meta-data.  Initializes md.
 * @param size number of bytes available
 * @return MD on success, NULL on error (i.e.
 *         bad format)
 */
struct GNUNET_ECRS_MetaData *GNUNET_ECRS_meta_data_deserialize (struct
                                                                GNUNET_GE_Context
                                                                *ectx,
                                                                const char
                                                                *input,
                                                                unsigned int
                                                                size);

/**
 * Does the meta-data claim that this is a directory?
 * Checks if the mime-type is that of a GNUnet directory.
 *
 * @return GNUNET_YES if it is, GNUNET_NO if it is not, GNUNET_SYSERR if
 *  we have no mime-type information (treat as 'GNUNET_NO')
 */
int GNUNET_ECRS_meta_data_test_for_directory (const struct
                                              GNUNET_ECRS_MetaData *md);

/**
 * Suggest a better filename for a file (and do the
 * renaming).
 */
char *GNUNET_ECRS_suggest_better_filename (struct GNUNET_GE_Context *ectx,
                                           const char *filename);

/* ******************** URI (uri.c) ************************ */

/**
 * A URI (in internal representation).
 */
struct GNUNET_ECRS_URI;

/**
 * Convert a URI to a UTF-8 String.
 */
char *GNUNET_ECRS_uri_to_string (const struct GNUNET_ECRS_URI *uri);

/**
 * Convert a UTF-8 String to a URI.
 */
struct GNUNET_ECRS_URI *GNUNET_ECRS_string_to_uri (struct GNUNET_GE_Context
                                                   *ectx, const char *uri);

/**
 * Free URI.
 */
void GNUNET_ECRS_uri_destroy (struct GNUNET_ECRS_URI *uri);

/**
 * How many keywords are ANDed in this keyword URI?
 * @return 0 if this is not a keyword URI
 */
unsigned int GNUNET_ECRS_uri_get_keyword_count_from_ksk (const struct
                                                         GNUNET_ECRS_URI
                                                         *uri);

/**
 * Iterate over all keywords in this keyword URI?
 * @return -1 if this is not a keyword URI, otherwise number of
 *   keywords iterated over until iterator aborted
 */
int GNUNET_ECRS_uri_get_keywords_from_ksk (const struct GNUNET_ECRS_URI *uri,
                                           GNUNET_ECRS_KeywordIterator
                                           iterator, void *cls);

/**
 * Obtain the identity of the peer offering the data
 * @return -1 if this is not a location URI, otherwise GNUNET_OK
 */
int GNUNET_ECRS_uri_get_peer_identity_from_loc (const struct GNUNET_ECRS_URI
                                                *uri,
                                                GNUNET_PeerIdentity * peer);

/**
 * Obtain the URI of the content itself.
 *
 * @return NULL if argument is not a location URI
 */
struct GNUNET_ECRS_URI *GNUNET_ECRS_uri_get_content_uri_from_loc (const struct
                                                                  GNUNET_ECRS_URI
                                                                  *uri);

/**
 * Function that produces a signature for
 * a particular piece of content.
 */
typedef int (*GNUNET_ECRS_SignFunction) (void *cls,
                                         unsigned short size,
                                         const void *data,
                                         GNUNET_RSA_Signature * result);

/**
 * Construct a location URI.
 *
 * @param baseURI content offered by the sender
 * @param sender identity of the peer with the content
 * @param expirationTime how long will the content be offered?
 * @param signer function to call for obtaining
 *        RSA signatures for "sender".
 * @return the location URI
 */
struct GNUNET_ECRS_URI *GNUNET_ECRS_location_to_uri (const struct
                                                     GNUNET_ECRS_URI *baseUri,
                                                     const
                                                     GNUNET_RSA_PublicKey *
                                                     peer,
                                                     GNUNET_Int32Time
                                                     expirationTime,
                                                     GNUNET_ECRS_SignFunction
                                                     signer,
                                                     void *signer_cls);


/**
 * Duplicate URI.
 */
struct GNUNET_ECRS_URI *GNUNET_ECRS_uri_duplicate (const struct
                                                   GNUNET_ECRS_URI *uri);

/**
 * Expand a keyword-URI by duplicating all keywords,
 * adding the current date (YYYY-MM-DD) after each
 * keyword.
 */
struct GNUNET_ECRS_URI *GNUNET_ECRS_uri_expand_keywords_with_date (const
                                                                   struct
                                                                   GNUNET_ECRS_URI
                                                                   *uri);

/**
 * Convert a NULL-terminated array of keywords
 * to an ECRS URI.
 */
struct GNUNET_ECRS_URI *GNUNET_ECRS_keyword_strings_to_uri (const char
                                                            *keyword[]);

/**
 * Create an ECRS URI from a single user-supplied string of keywords.
 * The string may contain the reserved word 'AND' to create a boolean
 * search over multiple keywords.
 *
 * @return an ECRS URI for the given keywords, NULL
 *  if keywords is not legal (i.e. empty).
 */
struct GNUNET_ECRS_URI *GNUNET_ECRS_keyword_string_to_uri (struct GNUNET_GE_Context *ectx, const char *keywords);       /* helper.c */

/**
 * Create an ECRS URI from a user-supplied command line of keywords.
 * The command line may contain the reserved word 'AND' to create a
 * boolean search over multiple keywords.
 *
 * @return an ECRS URI for the given keywords, NULL
 *  if keywords is not legal (i.e. empty).
 */
struct GNUNET_ECRS_URI *GNUNET_ECRS_keyword_command_line_to_uri (struct GNUNET_GE_Context *ectx, unsigned int argc, const char **argv); /* helper.c */

/**
 * Create an ECRS URI from a user-supplied list of keywords.
 * The keywords are NOT separated by AND but already
 * given individually.
 *
 * @return an ECRS URI for the given keywords, NULL
 *  if keywords is not legal (i.e. empty).
 */
struct GNUNET_ECRS_URI *GNUNET_ECRS_keyword_list_to_uri (struct
                                                         GNUNET_GE_Context
                                                         *ectx,
                                                         unsigned int
                                                         num_keywords,
                                                         const char
                                                         **keywords);

/**
 * Test if two URIs are equal.
 */
int GNUNET_ECRS_uri_test_equal (const struct GNUNET_ECRS_URI *u1,
                                const struct GNUNET_ECRS_URI *u2);

/**
 * Is this a namespace URI?
 */
int GNUNET_ECRS_uri_test_sks (const struct GNUNET_ECRS_URI *uri);

/**
 * Get the (globally unique) name for the given
 * namespace.
 *
 * @return the name (GNUNET_hash) of the namespace, caller
 *  must free it.
 */
char *GNUNET_ECRS_get_namespace_name (const GNUNET_HashCode * nsid);

/**
 * Get the ID of a namespace from the given
 * namespace URI.
 */
int GNUNET_ECRS_uri_get_namespace_from_sks (const struct GNUNET_ECRS_URI *uri,
                                            GNUNET_HashCode * nsid);

/**
 * Get the content ID of an SKS URI.
 */
int GNUNET_ECRS_uri_get_content_hash_from_sks (const struct GNUNET_ECRS_URI
                                               *uri, GNUNET_HashCode * nsid);

/**
 * Is this a keyword URI?
 */
int GNUNET_ECRS_uri_test_ksk (const struct GNUNET_ECRS_URI *uri);

/**
 * Is this a file (or directory) URI?
 */
int GNUNET_ECRS_uri_test_chk (const struct GNUNET_ECRS_URI *uri);

/**
 * What is the size of the file that this URI
 * refers to?
 */
unsigned long long GNUNET_ECRS_uri_get_file_size (const struct GNUNET_ECRS_URI
                                                  *uri);

/**
 * Is this a location URI?
 */
int GNUNET_ECRS_uri_test_loc (const struct GNUNET_ECRS_URI *uri);



/**
 * Construct a keyword-URI from meta-data (take all entries
 * in the meta-data and construct one large keyword URI
 * that lists all keywords that can be found in the meta-data).
 */
struct GNUNET_ECRS_URI *GNUNET_ECRS_meta_data_to_uri (const struct
                                                      GNUNET_ECRS_MetaData
                                                      *md);


typedef struct
{
  struct GNUNET_ECRS_MetaData *meta;
  struct GNUNET_ECRS_URI *uri;
} GNUNET_ECRS_FileInfo;


/**
 * @param scls must be of type "struct GNUNET_ECRS_URI **"
 */
int
GNUNET_ECRS_getopt_configure_set_keywords (GNUNET_CommandLineProcessorContext
                                           * ctx, void *scls,
                                           const char *option,
                                           const char *value);

/**
 * @param scls must be of type "struct GNUNET_ECRS_MetaData **"
 */
int
GNUNET_ECRS_getopt_configure_set_metadata (GNUNET_CommandLineProcessorContext
                                           * ctx, void *scls,
                                           const char *option,
                                           const char *value);



/* ************************* sharing API ***************** */

/**
 * Notification of ECRS to a client about the progress of an insertion
 * operation.
 *
 * @param totalBytes number of bytes that will need to be inserted
 * @param completedBytes number of bytes that have been inserted
 * @param eta absolute estimated time for the completion of the operation
 */
typedef void (*GNUNET_ECRS_UploadProgressCallback)
  (unsigned long long totalBytes,
   unsigned long long completedBytes, GNUNET_CronTime eta, void *closure);

/**
 * Should the operation be aborted?  Callback used by many functions
 * below to check if the user has aborted the operation early.  Can
 * also be used for time-outs.  Note that sending a signal (SIGALRM)
 * might be required in addition to TestTerminate to achieve
 * an 'instant' time-out in case that the function is currently
 * sleeping or performing some other blocking operation (which would
 * be aborted by any signal, after which the functions will call
 * this callback to check if they should continue).
 *
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort with deleting
 *  temporary files, GNUNET_NO to abort without deleting temporary files
 */
typedef int (*GNUNET_ECRS_TestTerminate) (void *closure);

/**
 * Index or insert a file.
 *
 * @param priority what is the priority for OUR node to
 *   keep this file available?  Use 0 for maximum anonymity and
 *   minimum reliability...
 * @param doIndex GNUNET_YES for index, GNUNET_NO for insertion,
 *                GNUNET_SYSERR for simulation
 * @param uri set to the URI of the uploaded file
 * @return GNUNET_SYSERR if the upload failed (i.e. not enough space
 *  or gnunetd not running)
 */
int GNUNET_ECRS_file_upload (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, const char *filename, int doIndex, unsigned int anonymityLevel, unsigned int priority, GNUNET_CronTime expirationTime,        /* absolute time */
                             GNUNET_ECRS_UploadProgressCallback upcb, void *upcbClosure, GNUNET_ECRS_TestTerminate tt, void *ttClosure, struct GNUNET_ECRS_URI **uri);  /* upload.c */

/**
 * Test if a file is indexed.
 *
 * @return GNUNET_YES if the file is indexed, GNUNET_NO if not, GNUNET_SYSERR on errors
 *  (i.e. filename could not be accessed and thus we have problems
 *  checking; also possible that the file was modified after indexing;
 *  in either case, if GNUNET_SYSERR is returned the user should probably
 *  be notified that 'something is wrong')
 */
int GNUNET_ECRS_file_test_indexed (struct GNUNET_GE_Context *ectx,
                                   struct GNUNET_GC_Configuration *cfg,
                                   const char *filename);

/**
 * @return GNUNET_OK to continue iteration, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_ECRS_FileProcessor) (const char *filename, void *cls);

/**
 * Iterate over all indexed files.
 *
 * This function will ONLY work if gnunetd runs on the
 * same machine as the current process and if the indexed
 * files could be symlinked.  If indexed files had to be
 * uploaded to a remote machine or copied, the original
 * names will have been lost.  In that case, the iterator
 * will NOT iterate over these files.
 *
 * @return number of files indexed, GNUNET_SYSERR if iterator aborted
 */
int GNUNET_ECRS_get_indexed_files (struct GNUNET_GE_Context *ectx,
                                   struct GNUNET_GC_Configuration *cfg,
                                   GNUNET_ECRS_FileProcessor iterator,
                                   void *closure);

/**
 * Unindex a file.
 *
 * @return GNUNET_SYSERR if the unindexing failed (i.e. not indexed)
 */
int GNUNET_ECRS_file_unindex (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, const char *filename, GNUNET_ECRS_UploadProgressCallback upcb, void *upcbClosure, GNUNET_ECRS_TestTerminate tt, void *ttClosure);    /* unindex.c */


/**
 * Create a new namespace (and publish an advertismement).
 * This publishes both an NBlock in the namespace itself
 * as well as KNBlocks under all keywords specified in
 * the advertisementURI.
 *
 * @param name the name for the namespace
 * @param anonymityLevel for the namespace advertismement
 * @param priority for the namespace advertisement
 * @param expiration for the namespace advertisement
 * @param advertisementURI the keyword (!) URI to advertise the
 *        namespace under (KNBlock)
 * @param meta meta-data for the namespace advertisement
 * @param rootEntry name of the root entry in the namespace (for
 *        the namespace advertisement)
 * @param rootURI set to the URI of the namespace, NULL if
 *        no advertisement was created
 *
 * @return URI on success, NULL on error (namespace already exists)
 */
struct GNUNET_ECRS_URI *GNUNET_ECRS_namespace_create (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, const char *name, const struct GNUNET_ECRS_MetaData *meta, unsigned int anonymityLevel, unsigned int priority, GNUNET_CronTime expiration, const struct GNUNET_ECRS_URI *advertisementURI, const GNUNET_HashCode * rootEntry);       /* namespace.c */

/**
 * Check if the given namespace exists (locally).
 * @param hc if non-null, also check that this is the
 *   hc of the public key
 * @return GNUNET_OK if the namespace exists, GNUNET_SYSERR if not
 */
int GNUNET_ECRS_namespace_test_exists (struct GNUNET_GE_Context *ectx,
                                       struct GNUNET_GC_Configuration *cfg,
                                       const char *name,
                                       const GNUNET_HashCode * hc);

/**
 * Delete a local namespace.  Only prevents future insertions
 * into the namespace, does not delete any content from
 * the network!
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_ECRS_namespace_delete (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, const char *namespaceName);      /* namespace.c */

/**
 * Callback with information about local (!) namespaces.
 * Contains the name of the local namespace and the global
 * ID.
 */
typedef int (*GNUNET_ECRS_NamespaceInfoProcessor) (const GNUNET_HashCode * id,
                                                   const char *name,
                                                   void *closure);

/**
 * Build a list of all available local (!) namespaces
 * The returned names are only the nicknames since
 * we only iterate over the local namespaces.
 *
 * @param list where to store the names (is allocated, caller frees)
 * @return GNUNET_SYSERR on error, otherwise the number of pseudonyms in list
 */
int GNUNET_ECRS_get_namespaces (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, GNUNET_ECRS_NamespaceInfoProcessor cb, void *cls); /* namespace.c */

/**
 * Add an entry into a namespace.
 *
 * @param name in which namespace to publish, use just the
 *        nickname of the namespace
 * @param dst to which URI should the namespace entry refer?
 * @param md what meta-data should be associated with the
 *        entry?
 * @return URI on success, NULL on error
 */
struct GNUNET_ECRS_URI *GNUNET_ECRS_namespace_add_content (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, const char *name, unsigned int anonymityLevel, unsigned int priority, GNUNET_CronTime expirationTime, GNUNET_Int32Time creationTime, GNUNET_Int32Time updateInterval, const GNUNET_HashCode * thisId, const GNUNET_HashCode * nextId, const struct GNUNET_ECRS_URI *dst, const struct GNUNET_ECRS_MetaData *md);        /* namespace.c */

/**
 * Add an entry into the K-space (keyword space).
 *
 * @param uri what is the URI under which the entry
 *        should be published (must be a keyword URI)
 * @param dst to which URI should the entry refer?
 * @param md what meta-data should be associated with the
 *        entry?
 */
int GNUNET_ECRS_publish_under_keyword (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, const struct GNUNET_ECRS_URI *uri, unsigned int anonymityLevel, unsigned int priority, GNUNET_CronTime expirationTime, const struct GNUNET_ECRS_URI *dst, const struct GNUNET_ECRS_MetaData *md);   /* keyspace.c */

/**
 * The search has found another result.  Callback to notify
 * whoever is controlling the search.
 *
 * @param uri the URI of the datum
 * @param key under which the result was found (GNUNET_hash of keyword),
 *        NULL if no key is known
 * @param isRoot is this a namespace root advertisement?
 * @param md a description for the URI
 * @return GNUNET_OK, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_ECRS_SearchResultProcessor)
  (const GNUNET_ECRS_FileInfo * fi,
   const GNUNET_HashCode * key, int isRoot, void *closure);

struct GNUNET_ECRS_SearchContext;

/**
 * Start search for content (asynchronous version).
 *
 * @param uri specifies the search parameters
 * @param uri set to the URI of the uploaded file
 */
struct GNUNET_ECRS_SearchContext *GNUNET_ECRS_search_start (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, const struct GNUNET_ECRS_URI *uri, unsigned int anonymityLevel, GNUNET_ECRS_SearchResultProcessor spcb, void *spcbClosure);    /* search.c */

/**
 * Stop search for content.
 *
 * @param uri specifies the search parameters
 * @param uri set to the URI of the uploaded file
 */
void GNUNET_ECRS_search_stop (struct GNUNET_ECRS_SearchContext *sctx);

/**
 * Search for content (synchronous version).
 *
 * @param uri specifies the search parameters
 * @param uri set to the URI of the uploaded file
 */
int GNUNET_ECRS_search (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, const struct GNUNET_ECRS_URI *uri, unsigned int anonymityLevel, GNUNET_ECRS_SearchResultProcessor spcb, void *spcbClosure, GNUNET_ECRS_TestTerminate tt, void *ttClosure); /* search.c */

/**
 * Notification of ECRS to a client about the progress of an insertion
 * operation.
 *
 * @param totalBytes number of bytes that will need to be downloaded,
 *        excluding inner blocks; the value given here will
 *        be one larger than the requested download size to signal
 *        an error.  In that case, all other values will be 0,
 *        except form "lastBlock" which will point to an error
 *        message describing the problem.
 * @param completedBytes number of bytes that have been obtained
 * @param eta absolute estimated time for the completion of the operation
 * @param lastBlockOffset offset of the last block that was downloaded,
 *        -1 as long as GNUNET_NO leaf of the file-tree has been obtained.  Note
 *        that inner nodes are _not_ counted here
 * @param lastBlock plaintext of the last block that was downloaded
 * @param lastBlockSize size of the last block that was downloaded
 */
typedef void (*GNUNET_ECRS_DownloadProgressCallback)
  (unsigned long long totalBytes,
   unsigned long long completedBytes,
   GNUNET_CronTime eta,
   unsigned long long lastBlockOffset,
   const char *lastBlock, unsigned int lastBlockSize, void *closure);

struct GNUNET_ECRS_DownloadContext;

/**
 * Download parts of a file ASYNCHRONOUSLY.  Note that this will store
 * the blocks at the respective offset in the given file.  Also, the
 * download is still using the blocking of the underlying ECRS
 * encoding.  As a result, the download may *write* outside of the
 * given boundaries (if offset and length do not match the 32k ECRS
 * block boundaries).  <p>
 *
 * This function should be used to focus a download towards a
 * particular portion of the file (optimization), not to strictly
 * limit the download to exactly those bytes.
 *
 * @param uri the URI of the file (determines what to download)
 * @param filename where to store the file
 * @param no_temporaries set to GNUNET_YES to disallow generation of temporary files
 * @param start starting offset
 * @param length length of the download (starting at offset)
 */
struct GNUNET_ECRS_DownloadContext
  *GNUNET_ECRS_file_download_partial_start (struct GNUNET_GE_Context *ectx,
                                            struct GNUNET_GC_Configuration
                                            *cfg,
                                            const struct GNUNET_ECRS_URI *uri,
                                            const char *filename,
                                            unsigned long long offset,
                                            unsigned long long length,
                                            unsigned int anonymityLevel,
                                            int no_temporaries,
                                            GNUNET_ECRS_DownloadProgressCallback
                                            dpcb, void *dpcbClosure);

/**
 * Stop a download (aborts if download is incomplete).
 */
int
GNUNET_ECRS_file_download_partial_stop (struct GNUNET_ECRS_DownloadContext
                                        *rm);

/**
 * DOWNLOAD a file.
 *
 * @param uri the URI of the file (determines what to download)
 * @param filename where to store the file
 */
int GNUNET_ECRS_file_download (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, const struct GNUNET_ECRS_URI *uri, const char *filename, unsigned int anonymityLevel, GNUNET_ECRS_DownloadProgressCallback dpcb, void *dpcbClosure, GNUNET_ECRS_TestTerminate tt, void *ttClosure); /* download.c */

/**
 * DOWNLOAD parts of a file.  Note that this will store
 * the blocks at the respective offset in the given file.
 * Also, the download is still using the blocking of the
 * underlying ECRS encoding.  As a result, the download
 * may *write* outside of the given boundaries (if offset
 * and length do not match the 32k ECRS block boundaries).
 * <p>
 *
 * This function should be used to focus a download towards a
 * particular portion of the file (optimization), not to strictly
 * limit the download to exactly those bytes.
 *
 * @param uri the URI of the file (determines what to download)
 * @param filename where to store the file
 * @param no_temporaries set to GNUNET_YES to disallow generation of temporary files
 * @param start starting offset
 * @param length length of the download (starting at offset)
 */
int GNUNET_ECRS_file_download_partial (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, const struct GNUNET_ECRS_URI *uri, const char *filename, unsigned long long offset, unsigned long long length, unsigned int anonymityLevel, int no_temporaries, GNUNET_ECRS_DownloadProgressCallback dpcb, void *dpcbClosure, GNUNET_ECRS_TestTerminate tt, void *ttClosure);       /* download.c */

/**
 * Iterate over all entries in a directory.  Note that directories
 * are structured such that it is possible to iterate over the
 * individual blocks as well as over the entire directory.  Thus
 * a client can call this function on the lastBlock in the
 * GNUNET_ECRS_DownloadProgressCallback.
 *
 * @param data pointer to the beginning of the directory
 * @param len number of bytes in data
 * @param md set to the MD for the directory if the first
 *   block is part of data
 * @return number of entries on success, GNUNET_SYSERR if the
 *         directory is malformed
 */
int GNUNET_ECRS_directory_list_contents (struct GNUNET_GE_Context *ectx, const char *data, unsigned long long len, struct GNUNET_ECRS_MetaData **md, GNUNET_ECRS_SearchResultProcessor spcb, void *spcbClosure);        /* directory.c */

/**
 * Create a directory.
 *
 * @param data pointer set to the beginning of the directory
 * @param len set to number of bytes in data
 * @param count number of entries in uris and metaDatas
 * @param uris URIs of the files in the directory
 * @param metaDatas meta-data for the files (must match
 *        respective values at same offset in in uris)
 * @param meta meta-data for the directory.  The meta entry
 *        is extended with the mime-type for a GNUnet directory.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_ECRS_directory_create (struct GNUNET_GE_Context *ectx, char **data, unsigned long long *len, unsigned int count, const GNUNET_ECRS_FileInfo * fis, struct GNUNET_ECRS_MetaData *meta);       /* directory.c */

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
