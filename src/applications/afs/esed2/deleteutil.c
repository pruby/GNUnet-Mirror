/*
     This file is part of GNUnet.
     (C) 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/esed2/deleteutil.c
 * @author Krista Bennett
 * @author Christian Grothoff
 *
 * Break file that is deleted into blocks and encrypts
 * them according to the CHK-triple-hash-tree scheme.
 * Then sends delete-requests to gnunetd.
 */

#include "gnunet_afs_esed2.h"
#include "platform.h"

/**
 * Ask gnunetd for an index that matches the filename
 * @return the index, -1 on error
 */
static int askDeleteFilename(GNUNET_TCP_SOCKET * sock,
			     const char * fn) {
  char * filename;
  AFS_CS_INDEX_FILE * request;
  int result;

  filename 
    = expandFileName(fn);   
  request
    = MALLOC(sizeof(AFS_CS_INDEX_FILE));
  request->header.size 
    = htons(sizeof(AFS_CS_INDEX_FILE));
  request->header.type 
    = htons(AFS_CS_PROTO_UNINDEX_FILE);
  request->filesize
    = htonl(getFileSize(filename));
  getFileHash(filename,
	      &request->hash);
  FREE(filename);
  if ( (SYSERR == writeToSocket(sock,
				&request->header)) ||
       (SYSERR == readTCPResult(sock,
				&result)) ) {
    LOG(LOG_WARNING, 
	_("Could not request or receive data"
	  " from gnunetd. Is gnunetd running?\n"));
    result = -1;
  }
  FREE(request);
  return result;
}
  
/**
 * De-facto main method. Deletes a file under the given
 * name from the local GNUnet node.
 *
 * @param sock connection to gnunetd
 * @param filename the name of the file to delete
 * @param model the delete model used to
 *        update status information; points to NULL if
 *        no status updates shall be given, otherwise 
 *        to a method that takes two size_t arguments
 *        (retrieved so far, total).
 * @param model_data pointer that is passed to the model method
 * @return SYSERR on error, OK on success
 */
int deleteFile(GNUNET_TCP_SOCKET * sock,
	       const char * fn, 
	       ProgressModel model,
	       void * model_data) {
  NodeContext nc;
  size_t filesize;
  Block * top;
  char * filename;
  int ret;

  filename = expandFileName(fn);
  filesize = (size_t) getFileSize(filename);
  memset(&nc, 0, sizeof(NodeContext));
  nc.pmodel = model;
  nc.data = model_data;
  nc.stats.filesize = filesize;
  nc.priority = 0;
  ret = askDeleteFilename(sock, filename);
  if (ret <= 0) {
    FREE(filename);
    return SYSERR;
  }
  nc.index = (unsigned short) ret;
  if (SYSERR == createIOContext(&nc.ioc,
				filesize,
				filename,
				YES)) {    
    FREE(filename);
    return SYSERR;
  }
  if (filesize <= sizeof(CONTENT_Block))
    top = createTopDBlock(filesize);
  else
    top = createTopIBlock(filesize);
  if (SYSERR == top->vtbl->delete(top, &nc, sock)) {
    top->vtbl->done(top, NULL);
    freeIOC(&nc.ioc, NO);
    FREE(filename);
    return SYSERR;
  }
  freeIOC(&nc.ioc, NO);
  FREE(filename);
  top->vtbl->done(top, NULL);
  return OK;
}


/* end of deleteutil.c */
