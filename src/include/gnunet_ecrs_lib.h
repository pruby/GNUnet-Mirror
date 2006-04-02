/*
     This file is part of GNUnet
     (C) 2004, 2005 Christian Grothoff (and other contributing authors)

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

#include "gnunet_util.h"
#include <extractor.h>

/**
 * Just the version number of the AFS/ESED/ESED2/ECRS implementation.
 * History:
 *
 * 1.x.x: initial version with triple hash and merkle tree
 * 2.x.x: root node with mime-type, filename and version number
 * 2.1.x: combined CHK/3HASH encoding with 25:1 super-nodes
 * 2.2.x: with directories
 * 3.0.x: with namespaces
 * 3.1.x: with namespace meta-data
 * 3.2.x: with collections
 * 4.0.x: with expiration, variable meta-data, kblocks
 * 5.x.x: who knows? :-)
 */
#define AFS_VERSION "4.0.1"

#define GNUNET_DIRECTORY_MIME  "application/gnunet-directory"
#define GNUNET_DIRECTORY_MAGIC "\211GND\r\n\032\n"
#define GNUNET_DIRECTORY_EXT   ".gnd"


#define ECRS_URI_PREFIX      "gnunet://ecrs/"
#define ECRS_SEARCH_INFIX    "ksk/"
#define ECRS_SUBSPACE_INFIX  "sks/"
#define ECRS_FILE_INFIX      "chk/"
#define ECRS_LOCATION_INFIX  "loc/"


/**
 * Fixed SBlock updateInterval codes. Positive values
 * are interpreted as durations (in seconds) for periodical
 * updates.
 */
#define ECRS_SBLOCK_UPDATE_SPORADIC  -1
#define ECRS_SBLOCK_UPDATE_NONE       0



/* ***************** metadata API (meta.c) ******************** */

/**
 * Meta data to associate with a file, directory or namespace.
 */
struct ECRS_MetaData;

/**
 * Iterator over meta data.
 * @return OK to continue to iterate, SYSERR to abort
 */
typedef int (*ECRS_MetaDataIterator)(EXTRACTOR_KeywordType type,
				     const char * data,
				     void * closure);

/**
 * Iterator over keywords
 * @return OK to continue to iterate, SYSERR to abort
 */
typedef int (*ECRS_KeywordIterator)(const char * data,
				    void * closure);

/**
 * Create a fresh MetaData token.
 */
struct ECRS_MetaData * ECRS_createMetaData(void);

/**
 * Duplicate a MetaData token.
 */
struct ECRS_MetaData * ECRS_dupMetaData(const struct ECRS_MetaData * meta);

/**
 * Free meta data.
 */
void ECRS_freeMetaData(struct ECRS_MetaData * md);

/**
 * Test if two MDs are equal.
 */
int ECRS_equalsMetaData(const struct ECRS_MetaData * md1,
			const struct ECRS_MetaData * md2);
			

/**
 * Extend metadata.
 * @return OK on success, SYSERR if this entry already exists
 */
int ECRS_addToMetaData(struct ECRS_MetaData * md,
		       EXTRACTOR_KeywordType type,
		       const char * data);

/**
 * Remove an item.
 * @return OK on success, SYSERR if the item does not exist in md
 */
int ECRS_delFromMetaData(struct ECRS_MetaData * md,
			 EXTRACTOR_KeywordType type,
			 const char * data);

/**
 * Add the current time as the publication date
 * to the meta-data.
 */
void ECRS_addPublicationDateToMetaData(struct ECRS_MetaData * md);

/**
 * Iterate over MD entries, excluding thumbnails.
 *
 * @return number of entries
 */
int ECRS_getMetaData(const struct ECRS_MetaData * md,
		     ECRS_MetaDataIterator iterator,
		     void * closure);

/**
 * Get the first MD entry of the given type.
 * @return NULL if we do not have any such entry,
 *  otherwise client is responsible for freeing the value!
 */
char * ECRS_getFromMetaData(const struct ECRS_MetaData * md,
			    EXTRACTOR_KeywordType type);

/**
 * Get the first matching MD entry of the given types.
 * @param ... -1-terminated list of types
 * @return NULL if we do not have any such entry,
 *  otherwise client is responsible for freeing the value!
 */
char * ECRS_getFirstFromMetaData(const struct ECRS_MetaData * md,
				 ...);

/**
 * Get a thumbnail from the meta-data (if present).
 *
 * @param thumb will be set to the thumbnail data.  Must be
 *        freed by the caller!
 * @return number of bytes in thumbnail, 0 if not available
 */
size_t ECRS_getThumbnailFromMetaData(const struct ECRS_MetaData * md,
				     unsigned char ** thumb);
		
/**
 * Extract meta-data from a file.
 *
 * @return SYSERR on error, otherwise the number
 *   of meta-data items obtained
 */
int ECRS_extractMetaData(struct ECRS_MetaData * md,
			 const char * filename,
			 EXTRACTOR_ExtractorList * extractors);

/* = 0 */
#define ECRS_SERIALIZE_FULL NO

/* = 1 */
#define ECRS_SERIALIZE_PART YES

/* disallow compression (if speed is important) */
#define ECRS_SERIALIZE_NO_COMPRESS 2


/**
 * Serialize meta-data to target.
 *
 * @param size maximum number of bytes available
 * @param part is it ok to just write SOME of the
 *        meta-data to match the size constraint,
 *        possibly discarding some data? YES/NO.
 * @return number of bytes written on success,
 *         SYSERR on error (typically: not enough
 *         space)
 */
int ECRS_serializeMetaData(const struct ECRS_MetaData * md,
			   char * target,
			   unsigned int size,
			   int part);

/**
 * Compute size of the meta-data in
 * serialized form.
 * @part flags (partial ok, may compress?)
 */
unsigned int ECRS_sizeofMetaData(const struct ECRS_MetaData * md,
				 int part);

/**
 * Deserialize meta-data.  Initializes md.
 * @param size number of bytes available
 * @return MD on success, NULL on error (i.e.
 *         bad format)
 */
struct ECRS_MetaData *
ECRS_deserializeMetaData(const char * input,
			 unsigned int size);

/**
 * Does the meta-data claim that this is a directory?
 * Checks if the mime-type is that of a GNUnet directory.
 *
 * @return YES if it is, NO if it is not, SYSERR if
 *  we have no mime-type information (treat as 'NO')
 */
int ECRS_isDirectory(const struct ECRS_MetaData * md);

/**
 * Suggest a better filename for a file (and do the
 * renaming).
 */
char * ECRS_suggestFilename(const char * filename);

/* ******************** URI (uri.c) ************************ */

/**
 * A URI (in internal representation).
 */
struct ECRS_URI;

/**
 * Convert a URI to a UTF-8 String.
 */
char * ECRS_uriToString(const struct ECRS_URI * uri);

/**
 * Convert a NULL-terminated array of keywords
 * to an ECRS URI.
 */
struct ECRS_URI * ECRS_keywordsToUri(const char * keyword[]);

/**
 * Convert a UTF-8 String to a URI.
 */
struct ECRS_URI * ECRS_stringToUri(const char * uri);

/**
 * Free URI.
 */
void ECRS_freeUri(struct ECRS_URI * uri);

/**
 * How many keywords are ANDed in this keyword URI?
 * @return 0 if this is not a keyword URI
 */
unsigned int ECRS_countKeywordsOfUri(const struct ECRS_URI * uri);

/**
 * Iterate over all keywords in this keyword URI?
 * @return -1 if this is not a keyword URI, otherwise number of
 *   keywords iterated over until iterator aborted
 */
int ECRS_getKeywordsFromUri(const struct ECRS_URI * uri,
			    ECRS_KeywordIterator iterator,
			    void * cls);

/**
 * Duplicate URI.
 */
struct ECRS_URI * ECRS_dupUri(const struct ECRS_URI * uri);

/**
 * Expand a keyword-URI by duplicating all keywords,
 * adding the current date (YYYY-MM-DD) after each
 * keyword.
 */
struct ECRS_URI * ECRS_dateExpandKeywordUri(const struct ECRS_URI * uri);

/**
 * Test if two URIs are equal.
 */
int ECRS_equalsUri(const struct ECRS_URI * u1,
		   const struct ECRS_URI * u2);

/**
 * Is this a namespace URI?
 */
int ECRS_isNamespaceUri(const struct ECRS_URI * uri);

/**
 * Get the (globally unique) name for the given
 * namespace.
 *
 * @return the name (hash) of the namespace, caller
 *  must free it.
 */
char * ECRS_getNamespaceName(const HashCode512 * nsid);

/**
 * Get the ID of a namespace from the given
 * namespace URI.
 */
int ECRS_getNamespaceId(const struct ECRS_URI * uri,
			HashCode512 * nsid);

/**
 * Get the content ID of an SKS URI.
 */
int ECRS_getSKSContentHash(const struct ECRS_URI * uri,
			   HashCode512 * nsid);

/**
 * Is this a keyword URI?
 */
int ECRS_isKeywordUri(const struct ECRS_URI * uri);

/**
 * Is this a file (or directory) URI?
 */
int ECRS_isFileUri(const struct ECRS_URI * uri);

/**
 * What is the size of the file that this URI
 * refers to?
 */
unsigned long long ECRS_fileSize(const struct ECRS_URI * uri);

/**
 * Is this a location URI? (DHT specific!)
 */
int ECRS_isLocationUri(const struct ECRS_URI * uri);

/**
 * Construct a keyword-URI from meta-data (take all entries
 * in the meta-data and construct one large keyword URI
 * that lists all keywords that can be found in the meta-data).
 */
struct ECRS_URI * ECRS_metaDataToUri(const struct ECRS_MetaData * md);


typedef struct {
  struct ECRS_MetaData * meta;
  struct ECRS_URI * uri;
} ECRS_FileInfo;

/* ************************* sharing API ***************** */

/**
 * Notification of ECRS to a client about the progress of an insertion
 * operation.
 *
 * @param totalBytes number of bytes that will need to be inserted
 * @param completedBytes number of bytes that have been inserted
 * @param eta absolute estimated time for the completion of the operation
 */
typedef void (*ECRS_UploadProgressCallback)
  (unsigned long long totalBytes,
   unsigned long long completedBytes,
   cron_t eta,
   void * closure);

/**
 * Should the operation be aborted?  Callback used by many functions
 * below to check if the user has aborted the operation early.  Can
 * also be used for time-outs.  Note that sending a signal (SIGALRM,
 * SIGINT) might be required in addition to TestTerminate to achieve
 * an 'instant' time-out in case that the function is currently
 * sleeping or performing some other blocking operation (which would
 * be aborted by any signal, after which the functions will call
 * this callback to check if they should continue).
 *
 * @return OK to continue, SYSERR to abort
 */
typedef int (*ECRS_TestTerminate)(void * closure);

/**
 * Index or insert a file.
 *
 * @param priority what is the priority for OUR node to
 *   keep this file available?  Use 0 for maximum anonymity and
 *   minimum reliability...
 * @param doIndex YES for index, NO for insertion
 * @param uri set to the URI of the uploaded file
 * @return SYSERR if the upload failed (i.e. not enough space
 *  or gnunetd not running)
 */
int ECRS_uploadFile(const char * filename,
		    int doIndex,
		    unsigned int anonymityLevel,
		    unsigned int priority,
		    cron_t expirationTime, /* absolute time */
		    ECRS_UploadProgressCallback upcb,
		    void * upcbClosure,
		    ECRS_TestTerminate tt,
		    void * ttClosure,
		    struct ECRS_URI ** uri); /* upload.c */

/**
 * Test if a file is indexed.
 *
 * @return YES if the file is indexed, NO if not, SYSERR on errors
 *  (i.e. filename could not be accessed and thus we have problems
 *  checking; also possible that the file was modified after indexing;
 *  in either case, if SYSERR is returned the user should probably
 *  be notified that 'something is wrong')
 */
int ECRS_isFileIndexed(const char * filename);

/**
 * @return OK to continue iteration, SYSERR to abort
 */
typedef int (*ECRS_FileIterator)(const char * filename,
				 void * cls);

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
 * @return number of files indexed, SYSERR if iterator aborted
 */
int ECRS_iterateIndexedFiles(ECRS_FileIterator iterator,
			     void * closure);

/**
 * Unindex a file.
 *
 * @return SYSERR if the unindexing failed (i.e. not indexed)
 */
int ECRS_unindexFile(const char * filename,
		     ECRS_UploadProgressCallback upcb,
		     void * upcbClosure,
		     ECRS_TestTerminate tt,
		     void * ttClosure); /* unindex.c */


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
struct ECRS_URI *
ECRS_createNamespace(const char * name,
		     const struct ECRS_MetaData * meta,
		     unsigned int anonymityLevel,
		     unsigned int priority,
		     cron_t expiration,
		     const struct ECRS_URI * advertisementURI,
		     const HashCode512 * rootEntry); /* namespace.c */

/**
 * Check if the given namespace exists (locally).
 * @param hc if non-null, also check that this is the
 *   hc of the public key
 * @return OK if the namespace exists, SYSERR if not
 */
int ECRS_testNamespaceExists(const char * name,
			     const HashCode512 * hc);

/**
 * Delete a local namespace.  Only prevents future insertions
 * into the namespace, does not delete any content from
 * the network!
 *
 * @return OK on success, SYSERR on error
 */
int ECRS_deleteNamespace(const char * namespaceName); /* namespace.c */

/**
 * Callback with information about local (!) namespaces.
 * Contains the name of the local namespace and the global
 * ID.
 */
typedef int (*ECRS_NamespaceInfoCallback)(const HashCode512 * id,
					  const char * name,
					  void * closure);

/**
 * Build a list of all available local (!) namespaces
 * The returned names are only the nicknames since
 * we only iterate over the local namespaces.
 *
 * @param list where to store the names (is allocated, caller frees)
 * @return SYSERR on error, otherwise the number of pseudonyms in list
 */
int ECRS_listNamespaces(ECRS_NamespaceInfoCallback cb,
			void * cls); /* namespace.c */

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
struct ECRS_URI *
ECRS_addToNamespace(const char * name,
		    unsigned int anonymityLevel,
		    unsigned int priority,
		    cron_t expirationTime,
		    TIME_T creationTime,
		    TIME_T updateInterval,
		    const HashCode512 * thisId,
		    const HashCode512 * nextId,
		    const struct ECRS_URI * dst,
		    const struct ECRS_MetaData * md); /* namespace.c */

/**
 * Add an entry into the K-space (keyword space).
 *
 * @param uri what is the URI under which the entry
 *        should be published (must be a keyword URI)
 * @param dst to which URI should the entry refer?
 * @param md what meta-data should be associated with the
 *        entry?
 */
int ECRS_addToKeyspace(const struct ECRS_URI * uri,
		       unsigned int anonymityLevel,
		       unsigned int priority,
		       cron_t expirationTime,
		       const struct ECRS_URI * dst,
		       const struct ECRS_MetaData * md); /* keyspace.c */

/**
 * The search has found another result.  Callback to notify
 * whoever is controlling the search.
 *
 * @param uri the URI of the datum
 * @param key under which the result was found (hash of keyword),
 *        NULL if no key is known
 * @param isRoot is this a namespace root advertisement?
 * @param md a description for the URI
 * @return OK, SYSERR to abort
 */
typedef int (*ECRS_SearchProgressCallback)
  (const ECRS_FileInfo * fi,
   const HashCode512 * key,
   int isRoot,
   void * closure);

/**
 * Search for content.
 *
 * @param timeout how long to wait (relative)
 * @param uri specifies the search parameters
 * @param uri set to the URI of the uploaded file
 */
int ECRS_search(const struct ECRS_URI * uri,
		unsigned int anonymityLevel,
		cron_t timeout,
		ECRS_SearchProgressCallback spcb,
		void * spcbClosure,
		ECRS_TestTerminate tt,
		void * ttClosure); /* search.c */

/**
 * Notification of ECRS to a client about the progress of an insertion
 * operation.
 *
 * @param totalBytes number of bytes that will need to be downloaded,
 *        excluding inner blocks
 * @param completedBytes number of bytes that have been obtained
 * @param eta absolute estimated time for the completion of the operation
 * @param lastBlockOffset offset of the last block that was downloaded,
 *        -1 as long as NO leaf of the file-tree has been obtained.  Note
 *        that inner nodes are _not_ counted here
 * @param lastBlock plaintext of the last block that was downloaded
 * @param lastBlockSize size of the last block that was downloaded
 */
typedef void (*ECRS_DownloadProgressCallback)
  (unsigned long long totalBytes,
   unsigned long long completedBytes,
   cron_t eta,
   unsigned long long lastBlockOffset,
   const char * lastBlock,
   unsigned int lastBlockSize,
   void * closure);

/**
 * Download a file.
 *
 * @param uri the URI of the file (determines what to download)
 * @param filename where to store the file
 */
int ECRS_downloadFile(const struct ECRS_URI * uri,
		      const char * filename,
		      unsigned int anonymityLevel,
		      ECRS_DownloadProgressCallback dpcb,
		      void * dpcbClosure,
		      ECRS_TestTerminate tt,
		      void * ttClosure); /* download.c */

/**
 * Iterate over all entries in a directory.  Note that directories
 * are structured such that it is possible to iterate over the
 * individual blocks as well as over the entire directory.  Thus
 * a client can call this function on the lastBlock in the
 * ECRS_DownloadProgressCallback.
 *
 * @param data pointer to the beginning of the directory
 * @param len number of bytes in data
 * @param md set to the MD for the directory if the first
 *   block is part of data
 * @return number of entries on success, SYSERR if the
 *         directory is malformed
 */
int ECRS_listDirectory(const char * data,
		       unsigned long long len,
		       struct ECRS_MetaData ** md,
		       ECRS_SearchProgressCallback spcb,
		       void * spcbClosure); /* directory.c */

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
 * @return OK on success, SYSERR on error
 */
int ECRS_createDirectory(char ** data,
			 unsigned long long * len,
			 unsigned int count,
			 const ECRS_FileInfo * fis,
			 struct ECRS_MetaData * meta); /* directory.c */


#endif
