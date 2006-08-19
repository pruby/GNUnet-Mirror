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
 * @file conf/bool.h
 * @brief Definition of "bool"
 * @author Nils Durner
 **/

#ifndef CONF_BOOL_H
#define CONF_BOOL_H

#ifndef __cplusplus
 #ifdef CURSES_LOC
  #include CURSES_LOC
 #else
  #ifndef bool
   #define bool int
  #endif
 #endif

 #ifndef true
  #define true 1
  #define false 0
 #endif
#endif

#endif
