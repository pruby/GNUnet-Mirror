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
 * @file applications/fs/fsui/collection.c 
 * @brief Helper functions for building a collection
 * @author Christian Grothoff
 *
 * A collection is a special kind of namespace.  A collection is the
 * set of files provided by the same user, but unlike namespaces it is
 * automatically managed by the GNUnet UI.  A collection is a single
 * directory in a namespace that is automatically updated each time
 * the user updates or deletes a file.  That is, once the user starts
 * a collection the gnunet-tools will always keep the corresponding
 * directory and namespace entries up-to-date.
 *
 * A good way of thinking about a collection is a lazy user's
 * namespace.
 *
 * TODO:
 * - collection of URIs + MetaData
 * - publishing of the data
 */

#include "platform.h"
#include "gnunet_fsui_lib.h"
#include "fsui.h"

/**
 * Entry in the state-DB that caches the current
 * collection.
 */ 
#define COLLECTION "collection"

/**
 * How long does a collection advertisement live?
 */
#define COLLECTION_ADV_LIFETIME (12 * cronMONTHS)

#define DEFAULT_ADVERTISEMENT_PRIORITY 128

typedef struct CollectionData {
  DataContainer hdr;
  HashCode512 nextId;
  char name[1];
} CollectionData;


/**
 * Start collection.
 */
int FSUI_startCollection(struct FSUI_Context * ctx,
			 unsigned int anonymityLevel,
			 const char * name,
			 const struct ECRS_MetaData * meta) {
  struct ECRS_URI * advertisement;
  struct ECRS_URI * rootURI;
  HashCode512 nextId;
  cron_t now;
  unsigned int prio;
  CollectionData * cd;

  FSUI_stopCollection(ctx); /* cancel old collection */
  GNUNET_ASSERT(name != NULL);
  advertisement = FSUI_parseCharKeywordURI(COLLECTION);
  GNUNET_ASSERT(advertisement != NULL);
  cronTime(&now);
  prio = getConfigurationInt("FS",
			     "ADVERTISEMENT-PRIORITY");
  if (prio == 0)
    prio = DEFAULT_ADVERTISEMENT_PRIORITY;
  makeRandomId(&nextId);
  if (OK != ECRS_createNamespace(name,
				 meta,
				 anonymityLevel,
				 prio,
				 now + COLLECTION_ADV_LIFETIME,
				 advertisement,
				 &nextId,
				 &rootURI)) {
    ECRS_freeUri(advertisement);
    return SYSERR;
  }
  ECRS_freeUri(advertisement);
  ECRS_freeUri(rootURI);
  cd = MALLOC(sizeof(CollectionData) + strlen(name));
  ctx->collectionData = &cd->hdr;
  cd->hdr.size = ntohl(sizeof(CollectionData) + strlen(name));
  cd->nextId = nextId;
  strcpy(cd->name, name);
  return OK;
}

/**
 * Stop collection.
 *
 * @return OK on success, SYSERR if no collection is active
 */
int FSUI_stopCollection(struct FSUI_Context * ctx) {
  CollectionData * cd;

  if (ctx->collectionData == NULL)
    return SYSERR;
  cd = (CollectionData*) ctx->collectionData;
  ECRS_deleteNamespace(cd->name);
  FREE(cd);
  ctx->collectionData = NULL;  
  return OK;
}

/**
 * Are we using a collection?
 *
 * @return NULL if there is no collection, otherwise its name
 */
const char * FSUI_getCollection(struct FSUI_Context * ctx) {
  CollectionData * cd;

  cd = (CollectionData*) ctx->collectionData;
  if (cd == NULL)
    return NULL;
  return &cd->name[0];
}





/* end of collection.c */
