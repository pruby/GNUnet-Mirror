/*
     This file is part of GNUnet.
     (C) 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/esed2/collection.c 
 * @brief Helper functions for building a collection
 * @author Christian Grothoff
 *
 * A collection is a special kind of namespace.
 * A collection is the set of files provided by the same user,
 * but unlike namespaces it is automatically managed by 
 * the GNUnet UI.  A collection is a single directory in
 * a namespace that is automatically updated each time the 
 * user updates or deletes a file.  That is, once the user 
 * starts a collection the gnunet-tools will always keep the
 * corresponding directory and namespace entries up-to-date.
 *
 * A good way of thinking about a collection is a lazy user's
 * namespace.
 */

#include "gnunet_afs_esed2.h"
#include "platform.h"

/**
 * Entry in the state-DB that caches the current
 * collection.
 */ 
#define COLLECTION "collection"

/**
 * Start a new collection.  Creates a fresh pseudonym
 * and starts collecting data into the corresponding
 * collection.  Note that calling startCollection will
 * affect GNUnet until the next time startCollection or
 * stopCollection is called -- and this is independent of
 * the process that called startCollection exiting!
 *
 * @param name the name for the collection
 * @param desc the description of the collection
 * @param realname the real name of the user hosting the collection
 * @param uri a URI associated with the collection
 * @param contact a contact address for contacting the host
 * @return OK on success, SYSERR on error
 */ 
int startCollection(const char * name,
		    const char * desc,
		    const char * realname,
		    const char * uri,
		    const char * contact) {
  PrivateKey key;
  SBlock * sb;
  NBlock * nb;
  HashCode160 id;
  HashCode160 nextId;
  FileIdentifier fi;
  int ok;

  GNUNET_ASSERT(name != NULL);
  if (strlen(name) > MAX_NAME_LEN-8) {
    LOG(LOG_ERROR,
	_("Name for collection is too long (maximum is %u characters).\n"),
	MAX_NAME_LEN-8);
    return SYSERR;
  }

  key = createPseudonym(name, NULL);
  if (key == NULL)
    return SYSERR;
  memset(&id, 0, sizeof(HashCode160));
  makeRandomId(&nextId);
  memset(&fi, 0, sizeof(FileIdentifier));
  sb = buildSBlock(key,
		   &fi,
		   desc,		   
		   realname,
		   GNUNET_DIRECTORY_MIME,
		   0,
		   SBLOCK_UPDATE_SPORADIC,
		   &id,
		   &nextId);
  nb = buildNBlock(key,
		   name,
		   desc,
		   realname,
		   GNUNET_DIRECTORY_MIME,
		   uri,
		   contact,
		   &nextId);
  freePrivateKey(key);
  GNUNET_ASSERT( (nb != NULL) &&
		 (sb != NULL) );


  /* the collection is empty at this point, which
     is why we don't publish it yet */
  ok = stateWriteContent(COLLECTION,
			 sizeof(SBlock),
			 sb);
  decryptNBlock(nb);
  if (ok == OK)
    ok = stateAppendContent(COLLECTION,
			    sizeof(NBlock),
			    nb);
  FREE(sb);
  FREE(nb);
  return ok;
}

/**
 * Makes a root-node available to the current collection.
 * If we are currently not collecting, this function does
 * nothing.
 *
 * @param root the file identifier that was produced
 */
void publishToCollection(const RootNode * root) {
  int len;
  int size;
  CONTENT_Block * blocks;
  SBlock sblock;  
  const NBlock * nblock;  
  SBlock * sb;
  GNUNET_TCP_SOCKET * sock;
  char * name;
  char * desc;
  HashCode160 key;
  PrivateKey hk;
  HashCode160 nextId;
  int i;
  FileIdentifier fid;
   
  GNUNET_ASSERT(sizeof(RootNode) == sizeof(CONTENT_Block));
  GNUNET_ASSERT(sizeof(SBlock) == sizeof(CONTENT_Block));
      
  blocks = NULL;
  len = stateReadContent(COLLECTION,
			 (void**)&blocks);
  if (len == -1)
    return; /* collection not active */
  if (len < sizeof(SBlock) + sizeof(NBlock)) {
    LOG(LOG_WARNING,
	_("Collection database corrupt, will stop to collect.\n"));
    stopCollection();
    FREE(blocks);
    return;
  }

  /* append */
  size = len / sizeof(CONTENT_Block);
  GROW(blocks,
       size,
       size+1);
  memcpy(&blocks[size-1],
	 root,
	 sizeof(RootNode));

  /* publish! */
  /* steps:
     a) decompile nblock/sblock
     b) build directory, insert!
     c) build updated sblock, insert!
     d) build keyword advertisement, insert!
  */
  memset(&key, 0, sizeof(HashCode160));  
  decryptSBlock(&key, (const SBlock*) &blocks[0], &sblock);
  nblock = (const NBlock*) &blocks[1];
  desc = STRNDUP(&sblock.description[0], MAX_DESC_LEN);
  name = STRNDUP(&nblock->nickname[0], MAX_NAME_LEN-8);
  
  hk = readPseudonym(name, NULL);
  if (hk == NULL) {
    LOG(LOG_ERROR,
	_("Could not find pseudonym for collection '%s'.\n"),
	name);
    FREE(name);
    FREE(desc);
    FREE(blocks);
    return;
  }
  FREE(name);

  sock = getClientSocket();
  if (sock == NULL) {
    FREE(desc);
    FREE(blocks);
    freePrivateKey(hk);
    LOG(LOG_ERROR,
	_("Could not connect to gnunetd.\n"));
    return;
  }

  i = insertDirectory(sock,
		      size-2,
		      (const RootNode*) &blocks[2],
		      "/",
		      &fid,
		      NULL,
		      NULL);
  if (i == SYSERR) {
    FREE(desc);
    FREE(blocks);
    releaseClientSocket(sock);
    freePrivateKey(hk);
    return;
  }
  makeRandomId(&nextId);
  /* finally we can create the next SBlock */
  sb = buildSBlock(hk,
		   &fid,
		   desc,
		   "/",
		   GNUNET_DIRECTORY_MIME,
		   TIME(NULL),
		   SBLOCK_UPDATE_SPORADIC,
		   &sblock.nextIdentifier,
		   &nextId);
  freePrivateKey(hk);
  FREE(desc);
  GNUNET_ASSERT(OK == verifySBlock(sb));

  /* we do this each time to refresh the nblock */
  if (OK != insertRootWithKeyword(sock,
				  (const RootNode*) nblock,
				  COLLECTION,
				  getConfigurationInt("GNUNET-INSERT",
						      "CONTENT-PRIORITY")))
    printf(_("Error inserting collection advertisement under keyword '%s'. "
	     "Is gnunetd running and space available?\n"),
	   "collection");

  /* also (re)publish sblock in namespace! */
  if (OK != insertSBlock(sock,
			 sb)) 
    printf(_("Error inserting SBlock into namespace. "
	     "Is gnunetd running and space available?\n"));
  FREE(sb);
  releaseClientSocket(sock);

  sblock.nextIdentifier = nextId; /* for the next update! */
  encryptSBlock(&key, &sblock, (SBlock*) &blocks[0]);

  /* store! */
  stateWriteContent(COLLECTION,
		    size * sizeof(CONTENT_Block),
		    blocks);
  FREE(blocks);
} 

/**
 * Close the current collection.  Future insertions
 * are no longer collected.
 */
int stopCollection() {
  return stateUnlinkFromDB(COLLECTION);
}

/* end of collection.c */
