/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/module/migration.c
 * @brief This module is responsible for pushing content out
 * into the network.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "migration.h"
#include "fs.h"

/**
 * Datastore service.
 */
static Datastore_ServiceAPI * datastore;

/**
 * Global core API.
 */
static CoreAPIForApplication * coreAPI;

/**
 * GAP service.
 */
static GAP_ServiceAPI * gap;

/**
 * DHT service.  Maybe NULL!
 */
static DHT_ServiceAPI * dht;

				  
/**
 * Callback method for pushing content into the network.
 * The method chooses either a "recently" deleted block
 * or content that has a hash close to the receiver ID
 * (randomized to guarantee diversity, unpredictability
 * etc.).<p>
 *
 * @param receiver the receiver of the message
 * @param position is the reference to the
 *        first unused position in the buffer where GNUnet is building
 *        the message
 * @param padding is the number of bytes left in that buffer.
 * @return the number of bytes written to
 *   that buffer (must be a positive number).
 */
static unsigned int
activeMigrationCallback(PeerIdentity * receiver,
			char * position,
			unsigned int padding) {
  unsigned int ret;
  HashCode160 key;
  Datastore_Value * content;
  GapWrapper * gw;
  unsigned int size;
  cron_t et;
 
  ret = 0;
  if (OK == datastore->getRandom(&receiver->hashPubKey,
				 padding,
				 &key,
				 &content,
				 0)) {
    size = sizeof(GapWrapper) + ntohl(content->size) - sizeof(Datastore_Value);
    gw = MALLOC(size);
    gw->dc.size = htonl(size);
    gw->type = content->type;
    et = ntohll(content->expirationTime);
    /* FIXME: mingle et? */
    gw->timeout = htonll(et);
    memcpy(&gw[1],
	   &content[1],
	   size - sizeof(GapWrapper));
    /* FIXME: check anonymity level,
       if 0, consider using DHT migration instead;
       if high, consider traffic volume before migrating */
    FREE(content);
    ret = gap->tryMigrate(&gw->dc,
			  ntohl(gw->type),
			  &key,
			  position,
			  padding);  
    FREE(gw);
  }
  return ret;
}

void initMigration(CoreAPIForApplication * capi,
		   Datastore_ServiceAPI * ds,
		   GAP_ServiceAPI * g,
		   DHT_ServiceAPI * d) {
  coreAPI = capi;
  datastore = ds;
  gap = g;
  dht = d;
  coreAPI->registerSendCallback(512,
				(BufferFillCallback)&activeMigrationCallback);
}

void doneMigration() {
  coreAPI->unregisterSendCallback(512,
				  (BufferFillCallback)&activeMigrationCallback);
  datastore = NULL;
  gap = NULL;
  dht = NULL;
  coreAPI = NULL;
}

/* end of migration.c */
