/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_util_common.h
 * @brief commonly used definitions
 *
 * @author Nils Durner
 */

#ifndef GNUNET_UTIL_COMMON_H_
#define GNUNET_UTIL_COMMON_H_

/**
 * Named constants for return values.  The following
 * invariants hold: "GNUNET_NO == 0" (to allow "if (GNUNET_NO)")
 * "GNUNET_OK != GNUNET_SYSERR", "GNUNET_OK != GNUNET_NO", "GNUNET_NO != GNUNET_SYSERR"
 * and finally "GNUNET_YES != GNUNET_NO".
 */
#define GNUNET_OK      1
#define GNUNET_SYSERR -1
#define GNUNET_YES     1
#define GNUNET_NO      0

#if __STDC_VERSION__ < 199901L
# if __GNUC__ >= 2
#  define __func__ __FUNCTION__
# else
#  define __func__ "<unknown>"
# endif
#endif

#endif /*GNUNET_UTIL_COMMON_H_ */
