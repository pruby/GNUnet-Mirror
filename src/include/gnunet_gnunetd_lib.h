/*
     This file is part of GNUnet

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
 * @file include/gnunet_gnunetd_lib.h
 * @brief general support for user interface / gnunetd interaction
 * @author Christian Grothoff
 */

#ifndef GNUNET_GNUNETD_LIB_H
#define GNUNET_GNUNETD_LIB_H

/**
 * Is gnunetd running?
 * @return YES if gnunetd is running, NO if not
 */
int GNUNETD_checkRunning();

/**
 * Try starting gnunetd.
 *
 * @param cfg configuration file for gnunetd (maybe NULL if
 *        the client has no idea where the file is, then
 *        the default is used)
 * @return YES on success, NO if gnunetd was already running,
 *         SYSERR if trying to start gnunetd failed and gnunetd
 *         was not running (even if YES is returned, there is
 *         no guarantee that the start was successful, try
 *         checkRunning!)
 */
int GNUNETD_tryStart(char * cfg);


#endif
