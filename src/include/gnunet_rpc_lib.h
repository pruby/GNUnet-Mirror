/*
      This file is part of GNUnet
      (C) 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_rpc_lib.h
 * @brief Definition of the RPC library routines
 * @author Antti Salonen, Christian Grothoff
 */

#ifndef GNUNET_RPC_LIB_H
#define GNUNET_RPC_LIB_H

#include "gnunet_core.h"
#include "gnunet_util.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Type of RPC arguments.
 */
struct GNUNET_RPC_CallParameters;

/**
 * RPC argument handling helper functions.
 */
struct GNUNET_RPC_CallParameters *GNUNET_RPC_parameters_create (void);

void GNUNET_RPC_parameters_destroy (struct GNUNET_RPC_CallParameters *param);

unsigned int GNUNET_RPC_parameters_count (const struct
                                          GNUNET_RPC_CallParameters *param);

void GNUNET_RPC_parameters_add (struct GNUNET_RPC_CallParameters *param,
                                const char *name,
                                unsigned int dataLength, const void *data);

/**
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_RPC_parameters_get_value_by_name (const struct
                                             GNUNET_RPC_CallParameters *param,
                                             const char *name,
                                             unsigned int *dataLength,
                                             void const **data);

/**
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_RPC_parameters_get_value_by_index (const struct
                                              GNUNET_RPC_CallParameters
                                              *param, unsigned int i,
                                              unsigned int *dataLength,
                                              void const **data);

/**
 * Serialize the param array.
 *
 * @param target must point to at least GNUNET_RPC_parameters_get_serialized_size(param) bytes of memory.
 */
void GNUNET_RPC_parameters_serialize (const struct GNUNET_RPC_CallParameters
                                      *param, char *target);

/**
 * Deserialize parameters from buffer.
 */
struct GNUNET_RPC_CallParameters *GNUNET_RPC_parameters_deserialize (const
                                                                     char
                                                                     *buffer,
                                                                     size_t
                                                                     size);

/**
 * How many bytes are required to serialize the param array?
 */
size_t GNUNET_RPC_parameters_get_serialized_size (const struct
                                                  GNUNET_RPC_CallParameters
                                                  *param);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif /* GNUNET_RPC_SERVICE_H */
