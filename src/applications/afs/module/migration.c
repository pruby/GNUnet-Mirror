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

#include "migration.h"
#include "manager.h"

#if VERBOSE_STATS
static int stat_handle_content_pushed;
#endif

/* use a 64-entry RCB buffer */
#define RCB_SIZE 128

/* how many blocks to cache from on-demand files in a row */
#define RCB_ONDEMAND_MAX 16

/**
 * Semaphore on which the RCB acquire thread waits
 * if the RCB buffer is full.
 */
static Semaphore * acquireMoreSignal;

static Semaphore * doneSignal;

/**
 * Lock for the RCB buffer.
 */
static Mutex lock;

/**
 * Buffer with pre-fetched, encoded random content for migration.
 */
typedef struct {
  HashCode160 hash;
  CONTENT_Block data;
} ContentBuffer;

static ContentBuffer * randomContentBuffer[RCB_SIZE];

/**
 * Highest index in RCB that is valid.
 */
static int rCBPos = 0;

/**
 * Acquire new block(s) to the migration buffer.
 *
 * Notes: holds lock while reading/encoding data,
 * might cause inefficiency -Igor.
 *
 **/
static void * rcbAcquire(void * unused) {
  int ok;

  while (1) {
    ContentIndex ce;
    CONTENT_Block * data;
    int readCount;

    SEMAPHORE_DOWN(acquireMoreSignal);
    if (doneSignal != NULL)
      break;
    MUTEX_LOCK(&lock);
    readCount = RCB_SIZE - rCBPos;
    if (readCount < RCB_ONDEMAND_MAX) {
      /* don't bother unless we have buffer space 
       * to read a larger block at one go */
      MUTEX_UNLOCK(&lock);
      continue;
    }
    data = NULL;
    ok = retrieveRandomContent(&ce,&data);
    if (ok == OK)  
      if (ntohs(ce.type) == LOOKUP_TYPE_3HASH ||
        ntohs(ce.type) == LOOKUP_TYPE_SUPER) { 
    
        ok = SYSERR; /* can not migrate these */
        FREENONNULL(data);
      }
    if (ok == OK) { 
      int i;

      if (ntohs(ce.fileNameIndex)>0) {
        /* if ondemand, encode a larger block right away */
        if (readCount>RCB_ONDEMAND_MAX)
          readCount = RCB_ONDEMAND_MAX;
        
          readCount = encodeOnDemand(&ce,
		                   &data,
		                   readCount);
          if (readCount != SYSERR)
            readCount = readCount / sizeof(CONTENT_Block);
      } else {
        readCount = 1;
      }
      
      if (read == SYSERR)
        ok = SYSERR;
      else
        for (i=0;i<readCount;i++) {
          randomContentBuffer[rCBPos]
            = MALLOC(sizeof(ContentBuffer));
          memcpy(&randomContentBuffer[rCBPos]->hash,
   	       &ce.hash,
  	       sizeof(HashCode160));
          memcpy(&randomContentBuffer[rCBPos]->data,
  	       &data[i],
  	       sizeof(CONTENT_Block));
          rCBPos++;
          /* we can afford to eat readCount-1 semaphores */
          if(i>0) {
            SEMAPHORE_DOWN_NONBLOCKING(acquireMoreSignal);
          }
        }
      FREENONNULL(data);
      MUTEX_UNLOCK(&lock);
    } 
    if (ok == SYSERR) {
      int load = getCPULoad();
      
      /* no need to hold the lock while sleeping */
      MUTEX_UNLOCK(&lock);

      if (load < 10)
        load = 10;
      sleep(load / 5); /* the higher the load, the longer the sleep,
		                      but at least 2 seconds */
      SEMAPHORE_UP(acquireMoreSignal); /* send myself signal to go again! */
    }
  }
  SEMAPHORE_UP(doneSignal);
  return NULL;
}


/**
 * Select content for active migration.  Takes the best match from the
 * randomContentBuffer (if the RCB is non-empty) and returns it.
 *
 * @return SYSERR if the RCB is empty
 */
static int selectMigrationContent(PeerIdentity * receiver,
				  ContentBuffer * content) {
  unsigned int dist;
  unsigned int minDist;
  int minIdx;
  int i;
  
  minIdx = -1;
  minDist = -1; /* max */
  MUTEX_LOCK(&lock);
  for (i=0;i<rCBPos;i++) {
    dist = distanceHashCode160(&randomContentBuffer[i]->hash,
			       &receiver->hashPubKey);
    if (dist < minDist) {
      minIdx = i;
      minDist = dist;
    }
  }
  if (minIdx == -1) {
    MUTEX_UNLOCK(&lock);
    return SYSERR;
  }
  memcpy(&content->hash,
         &randomContentBuffer[minIdx]->hash,
	 sizeof(HashCode160));
  memcpy(&content->data,
         &randomContentBuffer[minIdx]->data,
	 sizeof(CONTENT_Block));
  
  FREE(randomContentBuffer[minIdx]);
  randomContentBuffer[minIdx] = randomContentBuffer[--rCBPos];
  randomContentBuffer[rCBPos] = NULL;
  MUTEX_UNLOCK(&lock);
  SEMAPHORE_UP(acquireMoreSignal);
  return OK;
}
				  
/**
 * Build a CHK reply message for some content
 * selected for migration.
 * @return OK on success, SYSERR on error
 */
static int buildCHKReply(ContentBuffer * content,
			 AFS_p2p_CHK_RESULT * pmsg) {
  pmsg->header.size 
    = htons(sizeof(AFS_p2p_CHK_RESULT));
  pmsg->header.type
    = htons(AFS_p2p_PROTO_CHK_RESULT);
  memcpy(&pmsg->result,
	 &content->data,
	 sizeof(CONTENT_Block));
  
  return OK;
}

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
static int activeMigrationCallback(PeerIdentity * receiver,
				   char * position,
				   int padding) {
  AFS_p2p_CHK_RESULT * pmsg;
  int res;
  ContentBuffer content;
  
  res = 0;
  memset(&content, 0, sizeof(ContentBuffer));
  while (padding - res > (int) sizeof(AFS_p2p_CHK_RESULT)) {
    if (SYSERR == selectMigrationContent(receiver,
					 &content)) 
      return res; /* nothing selected, that's the end */
    /* append it! */
    pmsg = (AFS_p2p_CHK_RESULT*) &position[res];
    if (OK == buildCHKReply(&content,
			    pmsg)) {
#if VERBOSE_STATS
      statChange(stat_handle_content_pushed, 1);
#endif
      res += sizeof(AFS_p2p_CHK_RESULT);
    } else 
      return res; /* abort early after any error */    
  }
  return res;
}

static PTHREAD_T gather_thread;

void initMigration() {

#if VERBOSE_STATS
  stat_handle_content_pushed
    = statHandle(_("# kb content pushed out as padding"));
#endif
  memset(&randomContentBuffer,
	 0, 
	 sizeof(ContentBuffer *)*RCB_SIZE);
  acquireMoreSignal = SEMAPHORE_NEW(RCB_SIZE);
  doneSignal = NULL;
  MUTEX_CREATE(&lock);
  if (0 != PTHREAD_CREATE(&gather_thread,
			  (PThreadMain)&rcbAcquire,
			  NULL,
			  64*1024)) 
    DIE_STRERROR("pthread_create");
  coreAPI->registerSendCallback(sizeof(AFS_p2p_CHK_RESULT),
				(BufferFillCallback)&activeMigrationCallback);
}

void doneMigration() {
  int i;
  void * unused;

  coreAPI->unregisterSendCallback(sizeof(AFS_p2p_CHK_RESULT),
				  (BufferFillCallback)&activeMigrationCallback);
  doneSignal = SEMAPHORE_NEW(0);
  SEMAPHORE_UP(acquireMoreSignal);
  SEMAPHORE_DOWN(doneSignal);
  SEMAPHORE_FREE(acquireMoreSignal);
  SEMAPHORE_FREE(doneSignal);
  MUTEX_DESTROY(&lock);
  for (i=0;i<RCB_SIZE;i++)
    FREENONNULL(randomContentBuffer[i]);
  PTHREAD_JOIN(&gather_thread, &unused);
}

/* end of migration.c */
