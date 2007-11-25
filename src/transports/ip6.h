/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file transports/ip6.h
 * @brief
 *
 * @author Christian Grothoff
 */

#ifndef IP6_H
#define IP6_H

/**
 * @brief Get the IPv6 address for the local machine.
 *
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int getPublicIP6Address (struct GNUNET_GC_Configuration *cfg,
                         struct GNUNET_GE_Context *ectx,
                         GNUNET_IPv6Address * address);

#endif
