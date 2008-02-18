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
 * @file include/gnunet_rpc_service.h
 * @brief Definition of the RPC service
 * @author Antti Salonen, Christian Grothoff
 */

#ifndef GNUNET_RPC_SERVICE_H
#define GNUNET_RPC_SERVICE_H

#include "gnunet_core.h"
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
 * RPC_stop was called before a response was received
 */
#define GNUNET_RPC_ERROR_ABORTED 6

/**
 * Opaque RPC internal per-RPC data.
 */
struct GNUNET_RPC_CallHandle;

/**
 * Prototype for asynchronous RPC functions.
 *
 * @param caller who called the function?
 * @param arguments arguments to the call
 * @param context argument to pass to rpc->RPC_complete when the function is done
 */
typedef void (*GNUNET_RPC_AsynchronousFunction) (void *cls,
                                                 const GNUNET_PeerIdentity *
                                                 caller,
                                                 const struct
                                                 GNUNET_RPC_CallParameters *
                                                 arguments,
                                                 struct GNUNET_RPC_CallHandle
                                                 * context);


/**
 * Function to call once an asynchronous RPC completes.
 * A function of this type is called if we receive return
 * values from an RPC.
 * @param responder who responded
 * @param results return values
 * @param closure client-specific context
 */
typedef void (*GNUNET_RPC_AsynchronousCompletionCallback) (const
                                                           GNUNET_PeerIdentity
                                                           * responder,
                                                           const struct
                                                           GNUNET_RPC_CallParameters
                                                           * results,
                                                           unsigned int
                                                           errorCode,
                                                           void *closure);

struct GNUNET_RPC_RequestHandle;

/**
 * The RPC service API.
 */
typedef struct
{

  /**
   * Register an asynchronous RPC function.
   */
  int (*RPC_register) (const char *name,
                       GNUNET_RPC_AsynchronousFunction func, void *cls);


  /**
   * Unregister an asynchronous RPC function.
   */
  int (*RPC_unregister) (const char *name,
                         GNUNET_RPC_AsynchronousFunction func, void *cls);

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
                                                 const struct
                                                 GNUNET_RPC_CallParameters *
                                                 request_param,
                                                 unsigned int importance,
                                                 GNUNET_CronTime timeout,
                                                 GNUNET_RPC_AsynchronousCompletionCallback
                                                 callback, void *closure);

  /**
   * Stop an asynchronous RPC.  After calling this function,
   * the AsynchronousCompletionCallback of the corresponding
   * RPC_start request will no longer be called.  RPC_stop
   * must be called either to abort the RPC early or to
   * clean up the RPC's state after successful completion.
   * There must be one and only one call to RPC_stop for
   * each call to RPC_start.
   *
   * @param record the return value from RPC_start
   * @return GNUNET_RPC_ERROR_OK if the RPC was successful
   */
  int (*RPC_stop) (struct GNUNET_RPC_RequestHandle * record);

  /**
   * Tell RPC the result of an RPC call.  This function must
   * be called once and only once for each AsynchronousFunction
   * that is called from the RPC module.
   */
  void (*RPC_complete) (const struct GNUNET_RPC_CallParameters *
                        results, int errorCode,
                        struct GNUNET_RPC_CallHandle * context);

} GNUNET_RPC_ServiceAPI;

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif /* GNUNET_RPC_SERVICE_H */
