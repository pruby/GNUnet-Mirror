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
 * @file include/gnunet_state_service.h
 * @brief module to help keep some small bits of persistent state by name
 * @author Christian Grothoff
 */

#ifndef GNUNET_STATE_SERVICE_API_H
#define GNUNET_STATE_SERVICE_API_H


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
   * Read the contents of a bucket to a buffer.
   *
   * @param fn the hashcode representing the entry
   * @param result the buffer to write the result to
   *        (*result should be NULL, sufficient space is allocated)
   * @return the number of bytes read on success, -1 on failure
   */
  int (*read) (struct GNUNET_GE_Context * ectx, const char *name,
               void **result);

  /**
   * Append content to file.
   *
   * @param fn the key for the entry
   * @param len the number of bytes in block
   * @param block the data to store
   * @return GNUNET_SYSERR on error, GNUNET_OK if ok.
   */
  int (*append) (struct GNUNET_GE_Context * ectx,
                 const char *name, int len, const void *block);

  /**
   * Write content to a file.
   *
   * @param fn the key for the entry
   * @param len the number of bytes in block
   * @param block the data to store
   * @return GNUNET_SYSERR on error, GNUNET_OK if ok.
   */
  int (*write) (struct GNUNET_GE_Context * ectx,
                const char *name, int len, const void *block);

  /**
   * Free space in the database by removing one file
   * @param name the hashcode representing the name of the file
   *        (without directory)
   */
  int (*unlink) (struct GNUNET_GE_Context * ectx, const char *name);

} GNUNET_State_ServiceAPI;

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif /* STATE_SERVICE_API_H */
