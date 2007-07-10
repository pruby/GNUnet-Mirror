/*
      This file is part of GNUnet
      (C) 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_stats_service.h
 * @brief API to the stats-module
 * @author Christian Grothoff
 */

#ifndef GNUNET_STATS_SERVICE_API_H
#define GNUNET_STATS_SERVICE_API_H


#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * @brief API to the stats service
 */
typedef struct
{

  /**
   * Get a handle to a statistical entity.
   *
   * @param name a description of the entity
   * @return a handle for updating the associated value
   */
  int (*create) (const char *name);

  /**
   * Manipulate statistics.  Sets the core-statistics associated with
   * the handle to value.
   *
   * @param handle the handle for the value to change
   * @param value to what the value should be set
   */
  void (*set) (const int handle, const unsigned long long value);

  /**
   * Get statistics associated with the handle.
   * @param handle the handle for the value to get
   * @return value associated with the handle
   */
  unsigned long long (*get) (const int handle);

  /**
   * Manipulate statistics.  Changes the statistics associated
   * with the value by delta.
   *
   * @param handle the handle for the value to change
   * @param delta by how much should the value be changed
   */
  void (*change) (const int handle, const int delta);

} Stats_ServiceAPI;

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif /* STATS_SERVICE_API_H */
