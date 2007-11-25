/*
      This file is part of GNUnet
      (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_rpc_service.h
 * @brief Definition of the RPC service
 * @author Antti Salonen, Christian Grothoff
 */

#ifndef GNUNET_RPC_SERVICE_H
#define GNUNET_RPC_SERVICE_H

#include "gnunet_core.h"
#include "gnunet_util_containers.h"
#include "gnunet_blockstore.h"
#include "gnunet_rpc_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * The function was called successfully and the return values
 * are included in the message.
 */
#define GNUNET_RPC_ERROR_OK 0

/**
 * The peer does not know anything about the desired RPC function.
 */
#define GNUNET_RPC_ERROR_UNKNOWN_FUNCTION 1

/**
 * The return value cannot be put into a single message (but
 * otherwise the call was received and processed).
 */
#define GNUNET_RPC_ERROR_RETURN_VALUE_TOO_LARGE 2

/**
 * The RPC call timed out
 */
#define GNUNET_RPC_ERROR_TIMEOUT 3

/**
 * An unknown error occured during processing of the RPC call.
 */
#define GNUNET_RPC_ERROR_UNKNOWN 4

/**
 * Invalid reply format.
 */
#define GNUNET_RPC_ERROR_REPLY_MALFORMED 5

/**
 * Prototype for synchronous RPC functions.
 */
typedef void (*GNUNET_RPC_SynchronousFunction) (const GNUNET_PeerIdentity *
                                                caller,
                                                GNUNET_RPC_CallParameters *
                                                arguments,
                                                GNUNET_RPC_CallParameters *
                                                results);

/**
 * Opaque RPC internal per-RPC data.
 */
struct GNUNET_RPC_CallHandle;

/**
 * GNUNET_RSA_Signature of the callback function for the ASYNC_RPC to
 * be called upon completion of the ASYNC function.
 */
typedef void (*GNUNET_RPC_CompleteCallback) (GNUNET_RPC_CallParameters *
                                             results, int errorCode,
                                             struct GNUNET_RPC_CallHandle *
                                             context);

/**
 * Prototype for asynchronous RPC functions.
 */
typedef void (*GNUNET_RPC_AsynchronousFunction) (const GNUNET_PeerIdentity *
                                                 caller,
                                                 GNUNET_RPC_CallParameters *
                                                 arguments,
                                                 GNUNET_RPC_CompleteCallback
                                                 callback,
                                                 struct GNUNET_RPC_CallHandle
                                                 * context);


/**
 * Function to call once an asynchronous RPC completes.
 */
typedef void (*GNUNET_RPC_AsynchronousCompletionCallback) (const
                                                           GNUNET_PeerIdentity
                                                           * responder,
                                                           GNUNET_RPC_CallParameters
                                                           * results,
                                                           void *closure);

struct GNUNET_RPC_RequestHandle;

/**
 * The RPC service API.
 */
typedef struct
{

  /**
   * Perform a synchronous RPC.
   */
  int (*RPC_execute) (const GNUNET_PeerIdentity * receiver,
                      const char *name,
                      GNUNET_RPC_CallParameters * request_param,
                      GNUNET_RPC_CallParameters * return_param,
                      unsigned int importance, GNUNET_CronTime timeout);

  /**
   * Register a synchronous RPC function.
   */
  int (*RPC_register) (const char *name, GNUNET_RPC_SynchronousFunction func);

  /**
   * Unregister a synchronous RPC function.
   */
  int (*RPC_unregister) (const char *name,
                         GNUNET_RPC_SynchronousFunction func);

  /**
   * Register an asynchronous RPC function.
   */
  int (*RPC_register_async) (const char *name,
                             GNUNET_RPC_AsynchronousFunction func);


  /**
   * Unregister an asynchronous RPC function.
   */
  int (*RPC_unregister_async) (const char *name,
                               GNUNET_RPC_AsynchronousFunction func);

  /**
   * Start an asynchronous RPC.
   *
   * @param timeout when should we stop trying the RPC
   * @param callback function to call with the return value from
   *        the RPC
   * @param closure extra argument to callback
   * @return value required to stop the RPC (and the RPC must
   *  be explicitly stopped to free resources!)
   */
  struct GNUNET_RPC_RequestHandle *(*RPC_start) (const GNUNET_PeerIdentity *
                                                 receiver, const char *name,
                                                 GNUNET_RPC_CallParameters *
                                                 request_param,
                                                 unsigned int importance,
                                                 GNUNET_CronTime timeout,
                                                 GNUNET_RPC_AsynchronousCompletionCallback
                                                 callback, void *closure);

  /**
   * Stop an asynchronous RPC.
   *
   * @param record the return value from RPC_start
   * @return GNUNET_RPC_ERROR_OK if the RPC was successful
   */
  int (*RPC_stop) (struct GNUNET_RPC_RequestHandle * record);


} GNUNET_RPC_ServiceAPI;

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif /* GNUNET_RPC_SERVICE_H */
