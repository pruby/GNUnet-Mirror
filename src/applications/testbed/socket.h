/*
     This file is part of GNUnet.
     (C) 2003 Christian Grothoff (and other contributing authors)

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
 * @author Ronaldo Alves Ferreira
 * @author Christian Grothoff
 * @author Murali Krishna Ramanathan
 * @file applications/testbed/socket.h
 **/
#ifndef TESTBED_SOCKET_H
#define TESTBED_SOCKET_H


/* the server or client socket for
   communication */
extern int sock;

/* types for socketSend / read */

#define SOCKET_PRINTF 0
#define SOCKET_RETVAL 1
#define SOCKET_BEGIN_COMMAND 2
#define SOCKET_ADD_ARGUMENT 3
#define SOCKET_END_COMMAND 4

void socketSend(unsigned int len,
		unsigned int type,
		void * data);
 
/**
 * Read a message from the socket.
 * @return the type of the message
 */
unsigned int readSocket(char ** rbuf,
			unsigned int * len);
 
void PRINTF(char * fmt,
	    ...);

#endif
