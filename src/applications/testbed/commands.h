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
 * @file applications/testbed/testbed.h
 **/
#ifndef TESTBED_COMMANDS_H
#define TESTBED_COMMANDS_H

/**
 * Signature of a command -- just like main()!
 */
typedef int (*CommandHandler)(int argc,
			      char * argv[]);

typedef struct CMD_ENTRY_ {
  /* the name of the command (what the user enters
     in the shell */
  char * command;
  /* help text */
  char * help;
  /* the function to run */
  CommandHandler handler;
} CMD_ENTRY;

extern CMD_ENTRY commands[];

/* flag used to signal "end of execution" */
extern int do_quit;

#endif
