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
 * @file applications/afs/esed2/downloadutil.c
 * @brief Download helper methods (which do the real work).
 * @author Christian Grothoff
 */

#include "gnunet_afs_esed2.h"
#include "platform.h"

typedef struct PMWrap {
  ProgressModel userModel;
  void * userData;
  NodeContext * nc;
} PMWrap;

static void pModelWrap(ProgressStats * stats,
		       PMWrap * wrap) {
  if (wrap->userModel != NULL) {
    wrap->userModel(stats, wrap->userData);
  }
  if (stats->progress == stats->filesize) {    
    if (stats->progress == 0)
      freeIOC(&wrap->nc->ioc,
	      NO);
    else
      freeIOC(&wrap->nc->ioc, 
	      YES);
    FREE(wrap->nc);
    FREE(wrap);
  }
}

/**
 * Download a file.
 *
 * @param fi the file identification (CHK, crc32, size) of the file
 * @param fileName the name of the file
 * @param model the download model used to
 *        update status information; points to NULL if
 *        no status updates shall be given, otherwise 
 *        to a method that takes two size_t arguments
 *        (retrieved so far, total).
 * @param data pointer that is passed to the model method
 * @return a request manager that can be used to abort on 
 *         success, NULL on error
 */
RequestManager * downloadFile(const FileIdentifier * fi,
			      const char * fileName,
			      ProgressModel model,
			      void * data) {
  NodeContext * nc;
  Block * top;
  RequestManager * rm;
  struct PMWrap * wrap;

  nc = MALLOC(sizeof(NodeContext));
  if ( (rm = createRequestManager()) == NULL )
    return NULL;

  if (SYSERR == createIOContext(&nc->ioc,
				(size_t)ntohl(fi->file_length),
				fileName,
				NO)) {
    destroyRequestManager(rm);
    return NULL;
  }
  wrap = MALLOC(sizeof(PMWrap));
  wrap->userModel = model;
  wrap->userData = data;
  wrap->nc = nc;
  nc->priority = 0; /* unused */
  nc->index = 0; /* unused */
  nc->pmodel = (ProgressModel) &pModelWrap;
  nc->data = wrap;
  memset(&nc->stats,
	 0,
	 sizeof(ProgressStats));
  nc->stats.filesize = (size_t) ntohl(fi->file_length);

  if (ntohl(fi->file_length) <= sizeof(CONTENT_Block))
    top = (Block*) createTopDBlock((size_t)ntohl(fi->file_length));
  else
    top = (Block*) createTopIBlock((size_t)ntohl(fi->file_length));
  memcpy(&top->chk,
	 &fi->chk,
	 sizeof(CHK_Hashes));
  rm->topCrc32 = ntohl(fi->crc);
  rm->top = top;
  top->vtbl->download(top, nc, rm);  
  return rm;
}
