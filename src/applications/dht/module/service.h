/*
      This file is part of GNUnet
      (C) 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file module/service.h
 * @brief internal GNUnet DHT service
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"

/**
 * Handle used to track GET activity.
 */
struct GNUNET_DHT_GetHandle
{
  /**
   * Key that we are looking for.
   */
  GNUNET_HashCode key;

  /**
   * Function to call for each result.
   */
  GNUNET_ResultProcessor callback;

  /**
   * Extra argument to callback.
   */
  void *cls;

  /**
   * Type of the content that we are looking for.
   */
  unsigned int type;

};

/* end of service.h */
