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
 * @file rpc/parameters.c
 * @brief  This file provides convenience methods for parameter
 * handling.
 * @author Antti Salonen, Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_rpc_service.h"

/**
 * A parameter to/from an RPC call. These (and nothing else) are stored in
 * the Vector of the RPC_Param structure.
 */
typedef struct {
  unsigned int dataLength;
  char * name;
  void * data;
} Parameter;

/**
 * Allocate a new, empty RPC parameter structure.
 *
 * @return An empty RPC_Param structure
 */
RPC_Param * RPC_paramNew() {
  return vectorNew(4);
}

/**
 * Free the memory used by an RPC parameter structure. All parameter names and
 * values residing in the structure are freed, and thus all pointers returned
 * by this abstractions become dangling.
 *
 * @param param The RPC parameter structure to be freed
 */
void RPC_paramFree(RPC_Param *param) {
  if (param == NULL)
    return;
  while (vectorSize(param) > 0) {
    Parameter * p = vectorRemoveLast (param);
    FREE(p->name);
    FREE(p->data);
    FREE(p);
  }
  vectorFree(param);
}

/**
 * Serialize the param array.  target must point to at least
 * RPC_paramSize(param) bytes of memory.
 */
void RPC_paramSerialize(RPC_Param * param,
			char * target) {
  int i;
  const char * paramName;
  unsigned int dataLength;
  void * paramValue;
  size_t pos;

  if (param == NULL)
    return;
  if (target == NULL)
    return;
  pos = 0;
  for (i = 0; i < RPC_paramCount(param); i++) {
    paramName = RPC_paramName(param, i);
    paramValue = NULL;
    RPC_paramValueByPosition(param,
			     i,
			     &dataLength,
			     &paramValue);
    memcpy(&target[pos],
	   paramName,
	   strlen(paramName)+1);
    pos += strlen(paramName)+1;
    *(unsigned int*) &target[pos] = htonl(dataLength);
    pos += sizeof(unsigned int);
    memcpy(&target[pos],
	   paramValue,
	   dataLength);
    pos += dataLength;
  }
}

/**
 * Deserialize parameters from buffer.
 */
RPC_Param * RPC_paramDeserialize(char * buffer,
				 size_t size) {
  RPC_Param * ret;
  size_t pos;
  size_t xpos;
  unsigned int dataLength;

  if (buffer == NULL)
    return NULL;
  ret = RPC_paramNew();
  pos = 0;
  while (pos < size) {
    xpos = pos;
    while ( (pos < size) &&
	    (buffer[pos] != '\0') )
      pos++;
    pos++;
    if (pos + sizeof(unsigned int) > size) {
      RPC_paramFree(ret);
      return NULL;
    }
    dataLength = ntohl(*(unsigned int*)&buffer[pos]);
    pos += sizeof(unsigned int);
    if ( (pos + dataLength < pos) ||
	 (pos + dataLength > size) ) {
      RPC_paramFree(ret);
      return NULL;
    }

    RPC_paramAdd(ret,
		 &buffer[xpos],
		 dataLength,
		 &buffer[pos]);
    pos += dataLength;
  }
  return ret;
}

/**
 * How many bytes are required to serialize the param array?
 */
size_t RPC_paramSize(RPC_Param * param) {
  int i;
  const char * paramName;
  unsigned int dataLength;
  void * paramValue;
  size_t pos;

  if (param == NULL)
    return 0;
  pos = 0;
  for (i = 0; i < RPC_paramCount(param); i++) {
    paramName = RPC_paramName(param, i);
    paramValue = NULL;
    RPC_paramValueByPosition(param,
			     i,
			     &dataLength,
			     &paramValue);
    if (pos + strlen(paramName)+1+sizeof(unsigned int) < pos)
      return 0;
    pos += strlen(paramName)+1;
    pos += sizeof(unsigned int);
    if (pos + dataLength < pos)
      return 0;
    pos += dataLength;
  }
  return pos;
}


/**
 * Return the number of parameters in an RPC parameter structure.
 *
 * @param param Target RPC parameter structure
 * @return The number of parameters
 */
unsigned int RPC_paramCount(RPC_Param *param) {
  if (param == NULL)
    return 0;
  return vectorSize(param);
}


/**
 * Add a new parameter to the RPC parameter structure. The parameter name and
 * value are copied to memory private to the RPC parameter collection. The
 * pointers returned by other functions point to this private memory and should
 * not be freed by the user of the abstraction.
 *
 * @param param Target RPC parameter structure
 * @param name Name of the parameter
 * @param dataLength Length of the value of the parameter
 * @param data Value of the parameter
 */

void RPC_paramAdd(RPC_Param *param,
		  const char *name,
		  unsigned int dataLength,
		  const void *data) {
  Parameter * new;

  if (param == NULL)
    return;
  new = MALLOC(sizeof (Parameter));
  new->name = STRDUP(name);
  new->dataLength = dataLength;
  if (dataLength == 0) {
    new->data = NULL;
  } else {
    new->data = MALLOC(dataLength);
    memcpy(new->data, data, dataLength);
  }
  vectorInsertLast(param, new);
}


/**
 * Add a new parameter to the RPC parameter structure. The parameter name and
 * value are copied to memory private to the RPC parameter collection. The
 * pointers returned by other functions point to this private memory and should
 * not be freed by the user of the abstraction.
 *
 * @param param Target RPC parameter structure
 * @param name Name of the parameter
 * @param dataLength Length of the value of the parameter
 * @param data Value of the parameter
 */
void RPC_paramAddDataContainer(RPC_Param *param,
			       const char *name,
			       const DataContainer * data) {
  Parameter * new;

  if (param == NULL)
    return;
  new = MALLOC(sizeof(Parameter));
  new->name = STRDUP(name);
  new->dataLength = ntohl(data->size) - sizeof(DataContainer);
  if (new->dataLength == 0) {
    new->data = NULL;
  } else {
    new->data = MALLOC(new->dataLength);
    memcpy(new->data,
	   &data[1],
	   new->dataLength);
  }
  vectorInsertLast(param, new);
}

/**
 * Return the name of the given parameter in the RPC parameter structure, the
 * first parameter being parameter number zero.
 *
 * @param param Target RPC parameter structure
 * @return Name of the parameter
 */
const char * RPC_paramName(RPC_Param *param,
			   unsigned int i) {
  Parameter * p;

  if (param == NULL)
    return NULL;
  p = vectorGetAt(param, i);
  if (p)
    return p->name;
  else
    return NULL;
}


/**
 * Return the value of the named parameter in the RPC parameter structure.
 *
 * @param param Target RPC parameter structure
 * @param value set to the value of the named parameter
 * @return SYSERR on error
 */
int RPC_paramValueByName(RPC_Param *param,
			 const char *name,
			 unsigned int * dataLength,
			 void ** value) {
  Parameter *p;

  if (param == NULL)
    return SYSERR;
  p = vectorGetFirst (param);
  while (p != NULL) {
    if (!strcmp (p->name, name)) {
      *value = p->data;
      *dataLength = p->dataLength;
      return OK;
    }
    p = vectorGetNext(param);
  }
		
  return SYSERR;
}

/**
 * Return the value of the named parameter in the RPC parameter structure.
 *
 * @param param Target RPC parameter structure
 * @param value set to the value of the named parameter
 * @return SYSERR on error
 */
DataContainer * RPC_paramDataContainerByName(RPC_Param *param,
					     const char *name) {
  Parameter * p;
  DataContainer * ret;

  if (param == NULL)
    return NULL;
  p = vectorGetFirst (param);
  while (p != NULL) {
    if (!strcmp (p->name, name)) {
      ret = MALLOC(sizeof(DataContainer)
		   + p->dataLength);
      ret->size = htonl(sizeof(DataContainer)
			+ p->dataLength);
      memcpy(&ret[1],
	     p->data,
	     p->dataLength);
      return ret;
    }
    p = vectorGetNext(param);
  }
		
  return NULL;
}

/**
 * Return the value of the given parameter in the RPC parameter structure.
 *
 * @param param Target RPC parameter structure
 * @param value set to the value of the parameter
 */
int RPC_paramValueByPosition(RPC_Param *param,
			     unsigned int i,
			     unsigned int * dataLength,
			     void ** value) {
  Parameter * p;

  if (param == NULL)
    return SYSERR;
  p = vectorGetAt(param, i);
  if (p != NULL) {
    *dataLength = p->dataLength;
    *value = p->data;
    return OK;
  }
  return SYSERR;
}

/**
 * Return the value of the given parameter in the RPC parameter structure.
 *
 * @param param Target RPC parameter structure
 * @param value set to the value of the parameter
 */
DataContainer *
RPC_paramDataContainerByPosition(RPC_Param *param,
				 unsigned int i) {
  Parameter * p;
  DataContainer * ret;

  if (param == NULL)
    return NULL;
  p = vectorGetAt(param, i);
  if (p != NULL) {
    ret = MALLOC(sizeof(DataContainer)
		 + p->dataLength);
    ret->size = htonl(sizeof(DataContainer)
		      + p->dataLength);
    memcpy(&ret[1],
	   p->data,
	   p->dataLength);
    return ret;
  }
  return NULL;
}

/* end of parameters.c */

