/*
     This file is part of GNUnet

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
#define AFS_VERSION "4.0.0"

#define GNUNET_DIRECTORY_MIME  "application/gnunet-directory"
#define GNUNET_DIRECTORY_MAGIC "\211GND\r\n\032\n"
#define GNUNET_DIRECTORY_EXT   ".gnd"


#define ECRS_URI_PREFIX      "gnunet://ecrs/"
#define ECRS_SEARCH_INFIX    "ksk/"
#define ECRS_SUBSPACE_INFIX  "sks/"
#define ECRS_FILE_INFIX      "chk/"
#define ECRS_LOCATION_INFIX  "loc/"


/* ***************** metadata API (meta.c) ******************** */

/**
 * Meta data to associate with a file, directory or namespace.
 */
struct ECRS_MetaData;

/**
 * Iterator over meta data.
 */
typedef int (*ECRS_MetaDataIterator)(EXTRACTOR_KeywordType type,
				     const char * data,
				     void * closure);

/**
 * Create a fresh MetaData token.
 */
struct ECRS_MetaData * ECRS_createMetaData();

/**
 * Duplicate a MetaData token.
 */
struct ECRS_MetaData * ECRS_dupMetaData(const struct ECRS_MetaData * meta);

/**
 * Free meta data.
 */
void ECRS_freeMetaData(struct ECRS_MetaData * md);

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
 */
unsigned int ECRS_sizeofMetaData(const struct ECRS_MetaData * md);

/**
 * Deserialize meta-data.  Initializes md.
 * @param size number of bytes available
 * @return OK on success, SYSERR on error (i.e. 
 *         bad format)
 */
int ECRS_deserializeMetaData(struct ECRS_MetaData ** md,
			     const char * input,
			     unsigned int size);

/**
 * Does the meta-data claim that this is a directory?
 * Checks if the mime-type is that of a GNUnet directory.
 *
 * @return YES if it is, NO if it is not, SYSERR if
 *  we have no mime-type information (treat as 'NO')
 */ 
int ECRS_isDirectory(struct ECRS_MetaData * md);

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
 * Duplicate URI.
 */
struct ECRS_URI * ECRS_dupUri(const struct ECRS_URI * uri);

/**
 * Is this a namespace URI?
 */
int ECRS_isNamespaceURI(const struct ECRS_URI * uri);

/**
 * Get the (globally unique) name for the given
 * namespace.
 *
 * @return the name (hash) of the namespace, caller
 *  must free it.
 */
char * ECRS_getNamespaceName(const struct ECRS_URI * uri);

/**
 * Is this a keyword URI?
 */
int ECRS_isKeywordURI(const struct ECRS_URI * uri);

/**
 * Is this a file (or directory) URI?
 */
int ECRS_isFileURI(const struct ECRS_URI * uri);

/**
 * What is the size of the file that this URI
 * refers to?
 */
unsigned long long ECRS_fileSize(const struct ECRS_URI * uri);

/**
 * Is this a location URI? (DHT specific!)
 */
int ECRS_isLocationURI(const struct ECRS_URI * uri);

/**
 * Are these two URIs equal?
 */
int ECRS_equalsUri(const struct ECRS_URI * uri1,
		   const struct ECRS_URI * uri2);

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
 * @return OK on success, SYSERR on error (namespace already exists)
 */
int ECRS_createNamespace(const char * name,
			 const struct ECRS_MetaData * meta,
			 unsigned int anonymityLevel,
			 unsigned int priority,
			 cron_t expiration,
			 const struct ECRS_URI * advertisementURI,
			 const HashCode512 * rootEntry,
			 struct ECRS_URI ** rootURI); /* namespace.c */

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
 * Build a list of all available local (!) namespaces
 * The returned names are only the nicknames since
 * we only iterate over the local namespaces.
 *
 * @param list where to store the names (is allocated, caller frees)
 * @return SYSERR on error, otherwise the number of pseudonyms in list
 */
int ECRS_listNamespaces(char *** list); /* namespace.c */

/**
 * Add an entry into a namespace.
 *
 * @param name in which namespace to publish, use just the
 *        nickname of the namespace
 * @param dst to which URI should the namespace entry refer?
 * @param md what meta-data should be associated with the
 *        entry?
 * @param uri set to the resulting URI
 */
int ECRS_addToNamespace(const char * name,
			unsigned int anonymityLevel,
			unsigned int priority,
			cron_t expirationTime,
			cron_t creationTime,
			cron_t updateInterval,
			const HashCode512 * thisId,
			const HashCode512 * nextId,
			const struct ECRS_URI * dst,
			const struct ECRS_MetaData * md,
			struct ECRS_URI ** uri); /* namespace.c */

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
 * @param md a description for the URI
 * @return OK, SYSERR to abort 
 */
typedef int (*ECRS_SearchProgressCallback)
  (const ECRS_FileInfo * fi,
   const HashCode512 * key,
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
		       unsigned int len,
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
