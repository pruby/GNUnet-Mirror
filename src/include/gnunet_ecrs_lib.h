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
#include "gnunet_fs_lib.h"
#include <extractor.h>

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Version number of the implementation.
 * History:
 *
 * 1.x.x: initial version with triple GNUNET_hash and merkle tree
 * 2.x.x: root node with mime-type, filename and version number
 * 2.1.x: combined GNUNET_EC_ContentHashKey/3HASH encoding with 25:1 super-nodes
 * 2.2.x: with directories
 * 3.0.x: with namespaces
 * 3.1.x: with namespace meta-data
 * 3.2.x: with collections
 * 4.0.x: with expiration, variable meta-data, kblocks
 * 4.1.x: with new error and configuration handling
 * 5.0.x: with location URIs
 * 6.0.0: with support for OR in KSKs
 * 6.1.x: with simplified namespace support
 * 7.0.0: who knows? :-)
 */
#define GNUNET_ECRS_VERSION "6.0.0"

#define GNUNET_DIRECTORY_MIME  "application/gnunet-directory"
#define GNUNET_DIRECTORY_MAGIC "\211GND\r\n\032\n"
#define GNUNET_DIRECTORY_EXT   ".gnd"


#define GNUNET_ECRS_URI_PREFIX      "gnunet://ecrs/"
#define GNUNET_ECRS_SEARCH_INFIX    "ksk/"
#define GNUNET_ECRS_SUBSPACE_INFIX  "sks/"
#define GNUNET_ECRS_FILE_INFIX      "chk/"
#define GNUNET_ECRS_LOCATION_INFIX  "loc/"

/**
 * Iterator over keywords
 *
 * @param keyword the keyword
 * @param is_mandatory is the keyword mandatory (in a search)
 * @return GNUNET_OK to continue to iterate, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_ECRS_KeywordIterator) (const char *keyword,
                                            int is_mandatory, void *closure);

/**
 * Does the meta-data claim that this is a directory?
 * Checks if the mime-type is that of a GNUnet directory.
 *
 * @return GNUNET_YES if it is, GNUNET_NO if it is not, GNUNET_SYSERR if
 *  we have no mime-type information (treat as 'GNUNET_NO')
 */
int GNUNET_meta_data_test_for_directory (const struct GNUNET_MetaData *md);

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
 * Get a unique key from a URI.  This is for putting URIs
 * into HashMaps.  The key may change between ECRS implementations.
 */
void GNUNET_ECRS_uri_to_key (const struct GNUNET_ECRS_URI *uri,
                             GNUNET_HashCode * key);

/**
 * Convert a URI to a UTF-8 String.
 */
char *GNUNET_ECRS_uri_to_string (const struct GNUNET_ECRS_URI *uri);

/**
 * Convert keyword URI to a human readable format
 * (i.e. the search query that was used in the first place)
 */
char *GNUNET_ECRS_ksk_uri_to_human_readable_string (const struct
                                                    GNUNET_ECRS_URI *uri);

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
 * Iterate over all keywords in this keyword URI.
 *
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
 * @param expiration_time how long will the content be offered?
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
 * Create an ECRS URI from a single user-supplied string of keywords.
 * The string is broken up at spaces into individual keywords.
 * Keywords that start with "+" are mandatory.  Double-quotes can
 * be used to prevent breaking up strings at spaces (and also
 * to specify non-mandatory keywords starting with "+").
 *
 * Keywords must contain a balanced number of double quotes and
 * double quotes can not be used in the actual keywords (for
 * example, the string '""foo bar""' will be turned into two
 * "OR"ed keywords 'foo' and 'bar', not into '"foo bar"'.
 *
 * @return an ECRS URI for the given keywords, NULL
 *  if keywords is not legal (i.e. empty).
 */
struct GNUNET_ECRS_URI *GNUNET_ECRS_keyword_string_to_uri (struct
                                                           GNUNET_GE_Context
                                                           *ectx,
                                                           const char
                                                           *keywords);

/**
 * Create an ECRS URI from a user-supplied command line of keywords.
 * Arguments should start with "+" to indicate mandatory
 * keywords.
 *
 * @param argc number of keywords
 * @param argv keywords (double quotes are not required for
 *             keywords containing spaces; however, double
 *             quotes are required for keywords starting with
 *             "+"); there is no mechanism for having double
 *             quotes in the actual keywords (if the user
 *             did specifically specify double quotes, the
 *             caller should convert each double quote
 *             into two single quotes).
 * @return an ECRS URI for the given keywords, NULL
 *  if keywords is not legal (i.e. empty).
 */
struct GNUNET_ECRS_URI *GNUNET_ECRS_keyword_command_line_to_uri (struct
                                                                 GNUNET_GE_Context
                                                                 *ectx,
                                                                 unsigned int
                                                                 argc,
                                                                 const char
                                                                 **argv);

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
 * Get the ID of a namespace from the given
 * namespace URI.
 */
int GNUNET_ECRS_uri_get_namespace_from_sks (const struct GNUNET_ECRS_URI *uri,
                                            GNUNET_HashCode * nsid);

/**
 * Get the content identifier of an SKS URI.
 *
 * @return NULL on error
 */
char *GNUNET_ECRS_uri_get_content_id_from_sks (const struct GNUNET_ECRS_URI
                                               *uri);


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
struct GNUNET_ECRS_URI *GNUNET_meta_data_to_uri (const struct
                                                 GNUNET_MetaData *md);


typedef struct
{
  struct GNUNET_MetaData *meta;
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
 * @param scls must be of type "struct GNUNET_MetaData **"
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
int GNUNET_ECRS_file_upload (struct GNUNET_GE_Context *ectx,
                             struct GNUNET_GC_Configuration *cfg,
                             const char *filename,
                             int doIndex,
                             unsigned int anonymityLevel,
                             unsigned int priority,
                             GNUNET_CronTime expirationTime,
                             GNUNET_ECRS_UploadProgressCallback upcb,
                             void *upcbClosure,
                             GNUNET_ECRS_TestTerminate tt,
                             void *ttClosure, struct GNUNET_ECRS_URI **uri);

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
int GNUNET_ECRS_file_unindex (struct GNUNET_GE_Context *ectx,
                              struct GNUNET_GC_Configuration *cfg,
                              const char *filename,
                              GNUNET_ECRS_UploadProgressCallback upcb,
                              void *upcbClosure,
                              GNUNET_ECRS_TestTerminate tt, void *ttClosure);


/**
 * Create a new namespace (and publish an advertismement).
 * This publishes both an GNUNET_EC_NBlock in the namespace itself
 * as well as KNBlocks under all keywords specified in
 * the advertisementURI.
 *
 * @param anonymity_level for the namespace advertismement
 * @param priority for the namespace advertisement
 * @param expiration for the namespace advertisement
 * @param advertisementURI the keyword (!) URI to advertise the
 *        namespace under (GNUNET_EC_KNBlock)
 * @param meta meta-data for the namespace advertisement
 *        (will be used to derive a name)
 * @param rootEntry name of the root entry in the namespace (for
 *        the namespace advertisement)
 *
 * @return URI on success, NULL on error
 */
struct GNUNET_ECRS_URI *GNUNET_ECRS_namespace_create (struct GNUNET_GE_Context
                                                      *ectx,
                                                      struct
                                                      GNUNET_GC_Configuration
                                                      *cfg,
                                                      const struct
                                                      GNUNET_MetaData
                                                      *meta,
                                                      unsigned int
                                                      anonymityLevel,
                                                      unsigned int priority,
                                                      GNUNET_CronTime
                                                      expiration,
                                                      const struct
                                                      GNUNET_ECRS_URI
                                                      *advertisementURI,
                                                      const char *rootEntry);

/**
 * Check if the given namespace exists (locally).
 *
 * @return GNUNET_OK if the namespace exists, GNUNET_SYSERR if not
 */
int GNUNET_ECRS_namespace_test_exists (struct GNUNET_GE_Context *ectx,
                                       struct GNUNET_GC_Configuration *cfg,
                                       const GNUNET_HashCode * hc);

/**
 * Delete a local namespace.  Only prevents future insertions
 * into the namespace, does not delete any content from
 * the network!
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_ECRS_namespace_delete (struct GNUNET_GE_Context *ectx,
                                  struct GNUNET_GC_Configuration *cfg,
                                  const GNUNET_HashCode * pid);

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
int GNUNET_ECRS_get_namespaces (struct GNUNET_GE_Context *ectx,
                                struct GNUNET_GC_Configuration *cfg,
                                GNUNET_ECRS_NamespaceInfoProcessor cb,
                                void *cls);

/**
 * Add an entry into a namespace.
 *
 * @param pid in which namespace to publish
 * @param dst to which URI should the namespace entry refer?
 * @param md what meta-data should be associated with the
 *        entry?
 * @param thisId name of this entry in the namespace (keyword/identifier)
 * @param nextId name of the update for this entry (to be published in
 *               the future; maybe NULL)
 * @return URI on success, NULL on error
 */
struct GNUNET_ECRS_URI *GNUNET_ECRS_namespace_add_content (struct
                                                           GNUNET_GE_Context
                                                           *ectx,
                                                           struct
                                                           GNUNET_GC_Configuration
                                                           *cfg,
                                                           const
                                                           GNUNET_HashCode *
                                                           pid,
                                                           unsigned int
                                                           anonymityLevel,
                                                           unsigned int
                                                           priority,
                                                           GNUNET_CronTime
                                                           expirationTime,
                                                           const
                                                           char *thisId,
                                                           const
                                                           char *nextId,
                                                           const struct
                                                           GNUNET_ECRS_URI
                                                           *dst,
                                                           const struct
                                                           GNUNET_MetaData
                                                           *md);

/**
 * Add an entry into the K-space (keyword space).
 *
 * @param uri what is the URI under which the entry
 *        should be published (must be a keyword URI)
 * @param dst to which URI should the entry refer?
 * @param md what meta-data should be associated with the
 *        entry?
 */
int GNUNET_ECRS_publish_under_keyword (struct GNUNET_GE_Context *ectx,
                                       struct GNUNET_GC_Configuration *cfg,
                                       const struct GNUNET_ECRS_URI *uri,
                                       unsigned int anonymityLevel,
                                       unsigned int priority,
                                       GNUNET_CronTime expirationTime,
                                       const struct GNUNET_ECRS_URI *dst,
                                       const struct GNUNET_MetaData *md);

/**
 * The search has found another result.  Callback to notify
 * whoever is controlling the search.
 *
 * @param fi the URI and metadata of the result
 * @param key under which the result was found (GNUNET_hash of keyword),
 *        NULL if no key is known
 * @param isRoot is this a namespace root advertisement?
 * @return GNUNET_OK, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_ECRS_SearchResultProcessor)
  (const GNUNET_ECRS_FileInfo * fi,
   const GNUNET_HashCode * key, int isRoot, void *closure);

struct GNUNET_ECRS_SearchContext;

/**
 * Start search for content (asynchronous version).
 *
 * @param sc context to use for searching, you can pass NULL (then
 *        ECRS will manage its own context); if you pass non-NULL,
 *        search_stop must be called before you can destroy the sc.
 * @param uri specifies the search parameters;
 *        this must be a simple URI (with a single
 *        keyword)
 */
struct GNUNET_ECRS_SearchContext *GNUNET_ECRS_search_start (struct
                                                            GNUNET_GE_Context
                                                            *ectx,
                                                            struct
                                                            GNUNET_GC_Configuration
                                                            *cfg,
                                                            struct
                                                            GNUNET_FS_SearchContext
                                                            *sc,
                                                            const struct
                                                            GNUNET_ECRS_URI
                                                            *uri,
                                                            unsigned int
                                                            anonymityLevel,
                                                            GNUNET_ECRS_SearchResultProcessor
                                                            spcb,
                                                            void
                                                            *spcbClosure);

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
int GNUNET_ECRS_search (struct GNUNET_GE_Context *ectx,
                        struct GNUNET_GC_Configuration *cfg,
                        const struct GNUNET_ECRS_URI *uri,
                        unsigned int anonymityLevel,
                        GNUNET_ECRS_SearchResultProcessor spcb,
                        void *spcbClosure,
                        GNUNET_ECRS_TestTerminate tt, void *ttClosure);

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
 * @param sc context to use for searching, you can pass NULL (then
 *        ECRS will manage its own context); if you pass non-NULL,
 *        partial_stop must be called before you can destroy the sc.
 * @param uri the URI of the file (determines what to download)
 * @param filename where to store the file, maybe NULL (then no file is
 *        created on disk)
 * @param no_temporaries set to GNUNET_YES to disallow generation of temporary files
 * @param start starting offset
 * @param length length of the download (starting at offset)
 */
struct GNUNET_ECRS_DownloadContext
  *GNUNET_ECRS_file_download_partial_start (struct GNUNET_GE_Context *ectx,
                                            struct GNUNET_GC_Configuration
                                            *cfg,
                                            struct GNUNET_FS_SearchContext
                                            *sc,
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
int GNUNET_ECRS_file_download (struct GNUNET_GE_Context *ectx,
                               struct GNUNET_GC_Configuration *cfg,
                               const struct GNUNET_ECRS_URI *uri,
                               const char *filename,
                               unsigned int anonymityLevel,
                               GNUNET_ECRS_DownloadProgressCallback dpcb,
                               void *dpcbClosure,
                               GNUNET_ECRS_TestTerminate tt, void *ttClosure);

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
int GNUNET_ECRS_file_download_partial (struct GNUNET_GE_Context *ectx,
                                       struct GNUNET_GC_Configuration *cfg,
                                       const struct GNUNET_ECRS_URI *uri,
                                       const char *filename,
                                       unsigned long long offset,
                                       unsigned long long length,
                                       unsigned int anonymityLevel,
                                       int no_temporaries,
                                       GNUNET_ECRS_DownloadProgressCallback
                                       dpcb, void *dpcbClosure,
                                       GNUNET_ECRS_TestTerminate tt,
                                       void *ttClosure);

/**
 * Iterate over all entries in a directory.  Note that directories
 * are structured such that it is possible to iterate over the
 * individual blocks as well as over the entire directory.  Thus
 * a client can call this function on the lastBlock in the
 * GNUNET_ECRS_DownloadProgressCallback.
 *
 * @param data pointer to the beginning of the directory
 * @param len number of bytes in data
 * @param offset stores the number of bytes into directory to start listing
 *   on input and where the next element begins on output, can be NULL
 * @param md set to the MD for the directory if the first
 *   block is part of data
 * @return number of entries on success, GNUNET_SYSERR if the
 *         directory is malformed
 */
int GNUNET_ECRS_directory_list_contents (struct GNUNET_GE_Context *ectx,
                                         const char *data,
                                         unsigned long long len,
                                         unsigned long long *offset,
                                         struct GNUNET_MetaData **md,
                                         GNUNET_ECRS_SearchResultProcessor
                                         spcb, void *spcbClosure);

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
int GNUNET_ECRS_directory_create (struct GNUNET_GE_Context *ectx,
                                  char **data,
                                  unsigned long long *len,
                                  unsigned int count,
                                  const GNUNET_ECRS_FileInfo * fis,
                                  struct GNUNET_MetaData *meta);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
