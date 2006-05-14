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
#include "gnunet_blockstore.h"

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * The function was called successfully and the return values
 * are included in the message.
 */
#define RPC_ERROR_OK 0

/**
 * The peer does not know anything about the desired RPC function.
 */
#define RPC_ERROR_UNKNOWN_FUNCTION 1

/**
 * The return value cannot be put into a single message (but
 * otherwise the call was received and processed).
 */
#define RPC_ERROR_RETURN_VALUE_TOO_LARGE 2

/**
 * The RPC call timed out
 */
#define RPC_ERROR_TIMEOUT 3

/**
 * An unknown error occured during processing of the RPC call.
 */
#define RPC_ERROR_UNKNOWN 4

/**
 * Invalid reply format.
 */
#define RPC_ERROR_REPLY_MALFORMED 5

/**
 * Type of RPC arguments.
 */
#define RPC_Param struct Vector

/**
 * Prototype for synchronous RPC functions.
 */
typedef void (*RPC_Function)(const PeerIdentity * caller,
			     RPC_Param * arguments,
			     RPC_Param * results);

/**
 * Opaque RPC internal per-RPC data.
 */
struct CallInstance;

/**
 * Signature of the callback function for the ASYNC_RPC to
 * be called upon completion of the ASYNC function.
 */
typedef void (*Async_RPC_Complete_Callback)(RPC_Param * results,
					    int errorCode,
					    struct CallInstance * context);

/**
 * Prototype for asynchronous RPC functions.
 */
typedef void (*ASYNC_RPC_Function)(const PeerIdentity * caller,
				   RPC_Param * arguments,
				   Async_RPC_Complete_Callback callback,
				   struct CallInstance * context);


/**
 * Function to call once an asynchronous RPC completes.
 */
typedef void (*RPC_Complete)(const PeerIdentity * responder,
			     RPC_Param * results,
			     void * closure);

struct RPC_Record;

/**
 * The RPC service API.
 */
typedef struct {

  /**
   * Perform a synchronous RPC.
   */
  int (*RPC_execute)(const PeerIdentity * receiver,
		     const char * name,
		     RPC_Param * request_param,
		     RPC_Param * return_param,
		     unsigned int importance,
		     cron_t timeout);

  /**
   * Register a synchronous RPC function.
   */
  int (*RPC_register)(const char * name,
		      RPC_Function func);

  /**
   * Unregister a synchronous RPC function.
   */
  int (*RPC_unregister)(const char * name,
			RPC_Function func);

  /**
   * Register an asynchronous RPC function.
   */
  int (*RPC_register_async)(const char * name,
			    ASYNC_RPC_Function func);


  /**
   * Unregister an asynchronous RPC function.
   */
  int (*RPC_unregister_async)(const char * name,
			      ASYNC_RPC_Function func);

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
  struct RPC_Record * (*RPC_start)(const PeerIdentity * receiver,
				   const char * name,
				   RPC_Param * request_param,
				   unsigned int importance,
				   cron_t timeout,
				   RPC_Complete callback,
				   void * closure);

  /**
   * Stop an asynchronous RPC.
   *
   * @param record the return value from RPC_start
   * @return RPC_ERROR_OK if the RPC was successful
   */
  int (*RPC_stop)(struct RPC_Record * record);


} RPC_ServiceAPI;

/* **************** RPC library functions ****************** */

/**
 * RPC argument handling helper functions.
 */
RPC_Param * RPC_paramNew(void);

void RPC_paramFree(RPC_Param * param);

unsigned int RPC_paramCount(RPC_Param *param);

void RPC_paramAdd(RPC_Param * param,
		  const char * name,
		  unsigned int dataLength,
		  const void * data);

void RPC_paramAddDataContainer(RPC_Param * param,
			       const char * name,
			       const DataContainer * data);

const char * RPC_paramName(RPC_Param * param,
			   unsigned int i);

unsigned int RPC_paramIndex(RPC_Param * param,
			    const char * name);

/**
 * @return OK on success, SYSERR on error
 */
int RPC_paramValueByName(RPC_Param * param,
			 const char * name,
			 unsigned int * dataLength,
			 void ** data);

/**
 * @return OK on success, SYSERR on error
 */
int RPC_paramValueByPosition(RPC_Param * param,
			     unsigned int i,
			     unsigned int * dataLength,
			     void ** data);

/**
 * Return the value of the given parameter in the RPC parameter structure.
 *
 * @param param Target RPC parameter structure
 * @param value set to the value of the parameter
 */
DataContainer *
RPC_paramDataContainerByPosition(RPC_Param *param,
				 unsigned int i);

/**
 * Return the value of the named parameter in the RPC parameter
 * structure.
 *
 * @param param Target RPC parameter structure
 * @param value set to the value of the named parameter
 * @return SYSERR on error
 */
DataContainer * RPC_paramDataContainerByName(RPC_Param *param,
					     const char *name);

/**
 * Serialize the param array.  target must point to at least
 * RPC_paramSize(param) bytes of memory.
 */
void RPC_paramSerialize(RPC_Param * param,
			char * target);

/**
 * Deserialize parameters from buffer.
 */
RPC_Param * RPC_paramDeserialize(char * buffer,
				 size_t size);

/**
 * How many bytes are required to serialize the param array?
 */
size_t RPC_paramSize(RPC_Param * param);


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif /* GNUNET_RPC_SERVICE_H */
