/*
     This file is part of GNUnet.
     (C) 2001, 2002 Christian Grothoff (and other contributing authors)

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
 * @author Christian Grothoff
 * @file applications/tbench/tbench.h
 **/
#ifndef TBENCH_TBENCH_H
#define TBENCH_TBENCH_H

#include "gnunet_core.h"

#define TBENCH_MSG_LENGTH 1024

typedef struct {
  p2p_HEADER header; 
  unsigned int iterationNum;
  unsigned int packetNum;
} TBENCH_p2p_MESSAGE;

typedef struct {
  TBENCH_p2p_MESSAGE p2p_message;
  char message[1];
} TBENCH_p2p_MESSAGE_GENERIC;

typedef struct {
  CS_HEADER header;
  unsigned int msgSize;
  unsigned int msgCnt;
  unsigned int iterations;
  PeerIdentity receiverId;
  unsigned int intPktSpace;	/* Inter packet space in milliseconds */
  unsigned int trainSize;
  unsigned int timeOut;		/* Time to wait for the arrival of a reply in secs */
} TBENCH_CS_MESSAGE;

typedef struct {
  CS_HEADER header;
  int max_loss;
  int min_loss;
  float mean_loss;
  float variance_loss;
  
  int max_time;
  int min_time;
  float mean_time;
  float variance_time;  
} TBENCH_CS_REPLY;

#endif
