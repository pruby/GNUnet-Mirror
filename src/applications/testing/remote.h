/*
     This file is part of GNUnet.
     (C) 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/testing/remote.h
 * @brief header for remote.c
 * @author Nathan Evans
 */

#ifndef REMOTE_H_
#define REMOTE_H_

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_identity_lib.h"
#include "gnunet_util.h"
#include "gnunet_remote_lib.h"


/**
 * Linked list of information about daemon processes.
 */
struct GNUNET_REMOTE_host_list
{
  struct GNUNET_REMOTE_host_list *next;
  struct GNUNET_REMOTE_friends_list *friend_entries;
  char *hostname;
  char *remote_friend_file_path;
  char *username;
  unsigned short port;
};

/* Simple linked list to store friends lists for each node,
 * for writing to the friends file
 */
struct GNUNET_REMOTE_friends_list
{
  struct GNUNET_REMOTE_friends_list *next;
  struct GNUNET_REMOTE_host_list *hostentry;
  GNUNET_EncName *nodeid;
};

/**
 * Establish a connection between two GNUnet daemons
 *
 * @param port1 client port of the first daemon
 * @param port2 client port of the second daemon
 * @param ip1 client ip or hostname for the first daemon
 * @param ip2 client ip or hostname for the second daemon
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_REMOTE_connect_daemons (char *hostname1, unsigned short port1,
                               char *hostname2, unsigned short port2,
                               FILE * dotOutFile);

/**
 * Because we need to copy over the friends file before actually connecting,
 * we call this function to get the information for the peers and store it
 * in a linked list, which is iterated over later to actually connect.
 *
 * @param port1 client port of the first daemon
 * @param port2 client port of the second daemon
 * @param ip1 client ip or hostname for the first daemon
 * @param ip2 client ip or hostname for the second daemon
 * @param host1entry the entry of host1 for the friends file of host2
 * @param host2entry the entry of host2 for the friends file of host1
 */
int
GNUNET_REMOTE_get_daemons_information (char *hostname1, unsigned short port1,
                                       char *hostname2, unsigned short port2,
                                       GNUNET_EncName ** host1entry,
                                       GNUNET_EncName ** host2entry);

/**
 * Create a topology (connect the running gnunetd's) that corresponds
 * to the type specified in type.
 */
int
GNUNET_REMOTE_create_topology (GNUNET_REMOTE_TOPOLOGIES type,
                               int number_of_daemons, FILE * dotOufFile,
                               double percentage);


#endif /*REMOTE_H_ */

/* end of remote.h */
