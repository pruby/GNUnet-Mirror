/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/module/afs.c
 * @brief main functions of the anonymous file sharing service
 * @author Christian Grothoff
 *
 * AFS CORE. This is the code that is plugged into the GNUnet core to
 * enable Anonymous File Sharing.
 */

#include "afs.h"
#include "routing.h"
#include "handler.h"
#include "querymanager.h"
#include "manager.h"
#include "fileindex.h"
#include "bloomfilter.h"
#include "migration.h"

/**
 * Global core API.
 */
CoreAPIForApplication * coreAPI = NULL;

/**
 * Initialize the AFS module. This method name must match
 * the library name (libgnunet_XXX => initialize_XXX).
 * @return SYSERR on errors
 */
int initialize_afs_protocol(CoreAPIForApplication * capi) {
  int ok = OK;
  int * sbit;
  int version;

  if (getConfigurationInt("AFS",
			  "DISKQUOTA") <= 0)
    errexit(_("You must specify a postive number for '%s' in the configuration in section '%s'.\n"),
	    "DISKQUOTA", "AFS");

  /* AFS version check; current AFS version is 0.6.2
     (we only bump this version number if the DB changes!) */
  sbit = NULL;
  if (sizeof(int) == stateReadContent("VERSION",
				      (void**)&sbit)) {
    version = *sbit;
    FREE(sbit);
    if (ntohl(version) != 0x0620)
      errexit(_("Please run \"gnunet-check -u\" first!\n"));
  } else {
    FREENONNULL(sbit);  
    /* first start (or garbled version number), just write version tag */
    version = htonl(0x0620);  
    stateWriteContent("VERSION",
		      sizeof(int),
		      &version);
  }


  coreAPI = capi;  
  initFileIndex();
  initAnonymityPolicy(coreAPI);
  initManager();
  initBloomfilters();
  initQueryManager();
  initRouting();
  initAFSHandler();
  initMigration();
  LOG(LOG_DEBUG,
      "AFS registering handlers %d %d %d and %d %d %d %d %d %d %d %d %d %d %d %d\n",
      AFS_p2p_PROTO_QUERY,
      AFS_p2p_PROTO_3HASH_RESULT,
      AFS_p2p_PROTO_CHK_RESULT,
      AFS_CS_PROTO_QUERY,
      AFS_CS_PROTO_INSERT_CHK,
      AFS_CS_PROTO_INSERT_3HASH,
      AFS_CS_PROTO_INDEX_BLOCK,
      AFS_CS_PROTO_INDEX_FILE,
      AFS_CS_PROTO_INDEX_SUPER,
      AFS_CS_PROTO_DELETE_CHK,
      AFS_CS_PROTO_DELETE_3HASH,
      AFS_CS_PROTO_UNINDEX_BLOCK,
      AFS_CS_PROTO_UNINDEX_FILE,
      AFS_CS_PROTO_UNINDEX_SUPER,
      AFS_CS_PROTO_UPLOAD_FILE);

  /* p2p handlers */
  if (SYSERR == capi->registerHandler(AFS_p2p_PROTO_QUERY,
				      &handleQUERY))
    ok = SYSERR; 
  if (SYSERR == capi->registerHandler(AFS_p2p_PROTO_3HASH_RESULT,
				      &handle3HASH_CONTENT))
    ok = SYSERR; 
  if (SYSERR == capi->registerHandler(AFS_p2p_PROTO_CHK_RESULT,
				      &handleCHK_CONTENT))
    ok = SYSERR; 

  /* CS handlers */
  if (SYSERR == capi->registerClientHandler(AFS_CS_PROTO_QUERY,
					    (CSHandler)&csHandleRequestQuery))
    ok = SYSERR; 
  if (SYSERR == capi->registerClientHandler(AFS_CS_PROTO_INSERT_CHK,
					    (CSHandler)&csHandleRequestInsertCHK))
    ok = SYSERR; 
  if (SYSERR == capi->registerClientHandler(AFS_CS_PROTO_INSERT_3HASH,
					    (CSHandler)&csHandleRequestInsert3HASH))
    ok = SYSERR; 
  if (SYSERR == capi->registerClientHandler(AFS_CS_PROTO_INDEX_BLOCK,
					    (CSHandler)&csHandleRequestIndexBlock))
    ok = SYSERR;       
  if (SYSERR == capi->registerClientHandler(AFS_CS_PROTO_INDEX_FILE,
					    (CSHandler)&csHandleRequestIndexFile))
    ok = SYSERR; 
  if (SYSERR == capi->registerClientHandler(AFS_CS_PROTO_INDEX_SUPER,
					    (CSHandler)&csHandleRequestIndexSuper))
    ok = SYSERR; 
  if (SYSERR == capi->registerClientHandler(AFS_CS_PROTO_DELETE_CHK,
					    (CSHandler)&csHandleRequestDeleteCHK))
    ok = SYSERR; 
  if (SYSERR == capi->registerClientHandler(AFS_CS_PROTO_DELETE_3HASH,
					    (CSHandler)&csHandleRequestDelete3HASH))
    ok = SYSERR; 
  if (SYSERR == capi->registerClientHandler(AFS_CS_PROTO_UNINDEX_BLOCK,
					    (CSHandler)&csHandleRequestUnindexBlock))
    ok = SYSERR;       
  if (SYSERR == capi->registerClientHandler(AFS_CS_PROTO_UNINDEX_FILE,
					    (CSHandler)&csHandleRequestUnindexFile))
    ok = SYSERR; 
  if (SYSERR == capi->registerClientHandler(AFS_CS_PROTO_UNINDEX_SUPER,
					    (CSHandler)&csHandleRequestUnindexSuper))
    ok = SYSERR; 
  /* namespaces */
  if (SYSERR == capi->registerClientHandler(AFS_CS_PROTO_NSQUERY,
					    (CSHandler)&csHandleRequestNSQuery))
    ok = SYSERR;
  if (SYSERR == capi->registerClientHandler(AFS_CS_PROTO_INSERT_SBLOCK,
					    (CSHandler)&csHandleRequestInsertSBlock))
    ok = SYSERR;
  if (SYSERR == capi->registerClientHandler(AFS_CS_PROTO_UPLOAD_FILE,
					    (CSHandler)&csHandleRequestUploadFile))
    ok = SYSERR;
  if (SYSERR == capi->registerClientHandler(AFS_CS_PROTO_LINK_FILE,
					    (CSHandler)&csHandleRequestLinkFile))
    ok = SYSERR;
  if (SYSERR == capi->registerClientHandler(AFS_CS_PROTO_GET_AVG_PRIORITY,
					    (CSHandler)&csHandleRequestAvgPriority))
    ok = SYSERR;
  if (SYSERR == capi->registerHandler(AFS_p2p_PROTO_NSQUERY,
				      &handleNSQUERY))
    ok = SYSERR;
  if (SYSERR == capi->registerHandler(AFS_p2p_PROTO_SBLOCK_RESULT,
				      &handleSBLOCK_CONTENT))
    ok = SYSERR;  
  return ok;
}

void done_afs_protocol() {
  doneBloomfilters();
  /* p2p handlers */
  coreAPI->unregisterHandler(AFS_p2p_PROTO_QUERY,
			     &handleQUERY);
  coreAPI->unregisterHandler(AFS_p2p_PROTO_3HASH_RESULT,
			     &handle3HASH_CONTENT);
  coreAPI->unregisterHandler(AFS_p2p_PROTO_CHK_RESULT,
			     &handleCHK_CONTENT);

  /* CS handlers */
  coreAPI->unregisterClientHandler(AFS_CS_PROTO_QUERY,
				   (CSHandler)&csHandleRequestQuery);
  coreAPI->unregisterClientHandler(AFS_CS_PROTO_INSERT_CHK,
				   (CSHandler)&csHandleRequestInsertCHK);
  coreAPI->unregisterClientHandler(AFS_CS_PROTO_INSERT_3HASH,
				   (CSHandler)&csHandleRequestInsert3HASH);
  coreAPI->unregisterClientHandler(AFS_CS_PROTO_INDEX_BLOCK,
				   (CSHandler)&csHandleRequestIndexBlock);
  coreAPI->unregisterClientHandler(AFS_CS_PROTO_INDEX_FILE,
				   (CSHandler)&csHandleRequestIndexFile);
  coreAPI->unregisterClientHandler(AFS_CS_PROTO_INDEX_SUPER,
				   (CSHandler)&csHandleRequestIndexSuper);
  coreAPI->unregisterClientHandler(AFS_CS_PROTO_DELETE_CHK,
				   (CSHandler)&csHandleRequestDeleteCHK);
  coreAPI->unregisterClientHandler(AFS_CS_PROTO_DELETE_3HASH,
				   (CSHandler)&csHandleRequestDelete3HASH);
  coreAPI->unregisterClientHandler(AFS_CS_PROTO_UNINDEX_BLOCK,
				   (CSHandler)&csHandleRequestUnindexBlock);
  coreAPI->unregisterClientHandler(AFS_CS_PROTO_UNINDEX_FILE,
				   (CSHandler)&csHandleRequestUnindexFile);
  coreAPI->unregisterClientHandler(AFS_CS_PROTO_UNINDEX_SUPER,
				   (CSHandler)&csHandleRequestUnindexSuper);
  coreAPI->unregisterClientHandler(AFS_CS_PROTO_UPLOAD_FILE,
				   (CSHandler)&csHandleRequestUploadFile);
  coreAPI->unregisterClientHandler(AFS_CS_PROTO_LINK_FILE,
				   (CSHandler)&csHandleRequestLinkFile);
  coreAPI->unregisterClientHandler(AFS_CS_PROTO_GET_AVG_PRIORITY,
				   (CSHandler)&csHandleRequestAvgPriority);
  doneMigration();
  doneQueryManager();
  doneRouting();
  doneManager();
  doneFileIndex();
  doneAnonymityPolicy();
  coreAPI = NULL;
}

/* end of afs.c */
