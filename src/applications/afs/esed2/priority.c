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
 * @file applications/afs/esed2/priority.c
 * @brief keep track of the maximum priority that we
 *   are currently using
 * @author Christian Grothoff
 */ 

#include "gnunet_afs_esed2.h"
#include "platform.h"

#define DEBUG_PRIORITY NO

static unsigned int maxPriority_;

static void trackPriority(void * unused) {
  GNUNET_TCP_SOCKET * sock;
  CS_HEADER req;
  int res;
  int ret;

  sock = getClientSocket();
  if (sock == NULL) {
    maxPriority_ = 0;
    return;
  }
  req.size = htons(sizeof(CS_HEADER));
  req.type = htons(AFS_CS_PROTO_GET_AVG_PRIORITY);
  
  ret = writeToSocket(sock,
		      &req);
  if (ret == OK) {
    ret = readTCPResult(sock,
			&res);
    if (ret == OK) {
      maxPriority_ = (unsigned int) (2*res+1);
#if DEBUG_PRIORITY
      LOG(LOG_DEBUG,
	  "LOG: current maximum priority: %u\n",
	  maxPriority_);
#endif
    } else
      maxPriority_ = 0;
  } else {
    maxPriority_ = 0;
  }
  releaseClientSocket(sock);
}

/**
 * This method must be called to start the priority
 * tracker.
 */
void startAFSPriorityTracker() {
  trackPriority(NULL);
  addCronJob(&trackPriority,
	     TTL_DECREMENT,
	     TTL_DECREMENT,
	     NULL);	     
}

/**
 * This method must be called to stop the priority
 * tracker.  Call after cron has been stopped.
 */
void stopAFSPriorityTracker() {
  delCronJob(&trackPriority,
	     TTL_DECREMENT,
	     NULL);	     
}

/**
 * What is the highest priority that AFS clients should
 * use for requests at this point in time?
 */
unsigned int getMaxPriority() {
  return maxPriority_;
}

/* end of priority.c */
