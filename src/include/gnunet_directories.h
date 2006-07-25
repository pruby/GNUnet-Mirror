/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_directories.h
 * @brief directories and files in GNUnet (default locations)
 *
 * @author Christian Grothoff
 */

#ifndef GNUNET_DIRECTORIES
#define GNUNET_DIRECTORIES

#define DEFAULT_CLIENT_CONFIG_FILE "~/.gnunet/gnunet.conf"
#define DEFAULT_DAEMON_DIR         "/etc"
#define DEFAULT_DAEMON_CONFIG_FILE DEFAULT_DAEMON_DIR"/gnunetd.conf"
#define VAR_DIRECTORY              "/var/lib"
#define VAR_DAEMON_DIRECTORY       VAR_DIRECTORY"/gnunet"
#define VAR_DAEMON_CONFIG_FILE     VAR_DAEMON_DIRECTORY"/gnunetd.conf"
#define GNUNET_HOME_DIRECTORY      "~/.gnunet"
#define HOME_DAEMON_CONFIG_FILE    GNUNET_HOME_DIRECTORY"/gnunetd.conf"

#endif
