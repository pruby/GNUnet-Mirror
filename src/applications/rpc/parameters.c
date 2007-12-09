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
 * @file rpc/parameters.c
 * @brief  This file provides convenience methods for parameter
 * handling.
 * @author Antti Salonen, Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_rpc_lib.h"
#include "platform.h"

/**
 * A parameter to/from an RPC call. These (and nothing else) are stored in
 * the GNUNET_Vector of the GNUNET_RPC_CallParameters structure.
 */
typedef struct
{
  unsigned int dataLength;
  char *name;
  void *data;
} Parameter;

/**
 * Allocate a new, empty RPC parameter structure.
 *
 * @return An empty GNUNET_RPC_CallParameters structure
 */
GNUNET_RPC_CallParameters *
GNUNET_RPC_parameters_create ()
{
  return GNUNET_vector_create (4);
}

/**
 * Free the memory used by an RPC parameter structure. All parameter names and
 * values residing in the structure are freed, and thus all pointers returned
 * by this abstractions become dangling.
 *
 * @param param The RPC parameter structure to be freed
 */
void
GNUNET_RPC_parameters_destroy (GNUNET_RPC_CallParameters * param)
{
  if (param == NULL)
    return;
  while (GNUNET_vector_get_size (param) > 0)
    {
      Parameter *p = GNUNET_vector_delete_last (param);
      GNUNET_free (p->name);
      GNUNET_free (p->data);
      GNUNET_free (p);
    }
  GNUNET_vector_destroy (param);
}

/**
 * Serialize the param array.  target must point to at least
 * GNUNET_RPC_parameters_get_serialized_size(param) bytes of memory.
 */
void
GNUNET_RPC_parameters_serialize (GNUNET_RPC_CallParameters * param,
                                 char *target)
{
  int i;
  const char *paramName;
  unsigned int dataLength;
  void *paramValue;
  size_t pos;

  if (param == NULL)
    return;
  if (target == NULL)
    return;
  pos = 0;
  dataLength = 0;
  for (i = 0; i < GNUNET_RPC_parameters_count (param); i++)
    {
      paramName = GNUNET_RPC_parameters_get_name (param, i);
      paramValue = NULL;
      GNUNET_RPC_parameters_get_value_by_index (param, i, &dataLength,
                                                &paramValue);
      memcpy (&target[pos], paramName, strlen (paramName) + 1);
      pos += strlen (paramName) + 1;
      *(unsigned int *) &target[pos] = htonl (dataLength);
      pos += sizeof (unsigned int);
      memcpy (&target[pos], paramValue, dataLength);
      pos += dataLength;
    }
}

/**
 * Deserialize parameters from buffer.
 */
GNUNET_RPC_CallParameters *
GNUNET_RPC_parameters_deserialize (char *buffer, size_t size)
{
  GNUNET_RPC_CallParameters *ret;
  size_t pos;
  size_t xpos;
  unsigned int dataLength;

  if (buffer == NULL)
    return NULL;
  ret = GNUNET_RPC_parameters_create ();
  pos = 0;
  while (pos < size)
    {
      xpos = pos;
      while ((pos < size) && (buffer[pos] != '\0'))
        pos++;
      pos++;
      if (pos + sizeof (unsigned int) > size)
        {
          GNUNET_RPC_parameters_destroy (ret);
          return NULL;
        }
      dataLength = ntohl (*(unsigned int *) &buffer[pos]);
      pos += sizeof (unsigned int);
      if ((pos + dataLength < pos) || (pos + dataLength > size))
        {
          GNUNET_RPC_parameters_destroy (ret);
          return NULL;
        }

      GNUNET_RPC_parameters_add (ret, &buffer[xpos], dataLength,
                                 &buffer[pos]);
      pos += dataLength;
    }
  return ret;
}

/**
 * How many bytes are required to serialize the param array?
 */
size_t
GNUNET_RPC_parameters_get_serialized_size (GNUNET_RPC_CallParameters * param)
{
  int i;
  const char *paramName;
  unsigned int dataLength;
  void *paramValue;
  size_t pos;

  if (param == NULL)
    return 0;
  pos = 0;
  dataLength = 0;
  for (i = 0; i < GNUNET_RPC_parameters_count (param); i++)
    {
      paramName = GNUNET_RPC_parameters_get_name (param, i);
      paramValue = NULL;
      GNUNET_RPC_parameters_get_value_by_index (param, i, &dataLength,
                                                &paramValue);
      if (pos + strlen (paramName) + 1 + sizeof (unsigned int) < pos)
        return 0;
      pos += strlen (paramName) + 1;
      pos += sizeof (unsigned int);
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
unsigned int
GNUNET_RPC_parameters_count (GNUNET_RPC_CallParameters * param)
{
  if (param == NULL)
    return 0;
  return GNUNET_vector_get_size (param);
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

void
GNUNET_RPC_parameters_add (GNUNET_RPC_CallParameters * param,
                           const char *name, unsigned int dataLength,
                           const void *data)
{
  Parameter *new;

  if (param == NULL)
    return;
  new = GNUNET_malloc (sizeof (Parameter));
  new->name = GNUNET_strdup (name);
  new->dataLength = dataLength;
  if (dataLength == 0)
    {
      new->data = NULL;
    }
  else
    {
      new->data = GNUNET_malloc (dataLength);
      memcpy (new->data, data, dataLength);
    }
  GNUNET_vector_insert_last (param, new);
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
void
GNUNET_RPC_parameters_add_data_container (GNUNET_RPC_CallParameters * param,
                                          const char *name,
                                          const GNUNET_DataContainer * data)
{
  Parameter *new;

  if (param == NULL)
    return;
  new = GNUNET_malloc (sizeof (Parameter));
  new->name = GNUNET_strdup (name);
  new->dataLength = ntohl (data->size) - sizeof (GNUNET_DataContainer);
  if (new->dataLength == 0)
    {
      new->data = NULL;
    }
  else
    {
      new->data = GNUNET_malloc (new->dataLength);
      memcpy (new->data, &data[1], new->dataLength);
    }
  GNUNET_vector_insert_last (param, new);
}

/**
 * Return the name of the given parameter in the RPC parameter structure, the
 * first parameter being parameter number zero.
 *
 * @param param Target RPC parameter structure
 * @return Name of the parameter
 */
const char *
GNUNET_RPC_parameters_get_name (GNUNET_RPC_CallParameters * param,
                                unsigned int i)
{
  Parameter *p;

  if (param == NULL)
    return NULL;
  p = GNUNET_vector_get (param, i);
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
 * @return GNUNET_SYSERR on error
 */
int
GNUNET_RPC_parameters_get_value_by_name (GNUNET_RPC_CallParameters * param,
                                         const char *name,
                                         unsigned int *dataLength,
                                         void **value)
{
  Parameter *p;

  if (param == NULL)
    return GNUNET_SYSERR;
  p = GNUNET_vector_get_first (param);
  while (p != NULL)
    {
      if (!strcmp (p->name, name))
        {
          *value = p->data;
          *dataLength = p->dataLength;
          return GNUNET_OK;
        }
      p = GNUNET_vector_get_next (param);
    }

  return GNUNET_SYSERR;
}

/**
 * Return the value of the named parameter in the RPC parameter structure.
 *
 * @param param Target RPC parameter structure
 * @param value set to the value of the named parameter
 * @return GNUNET_SYSERR on error
 */
GNUNET_DataContainer *
GNUNET_RPC_parameters_get_data_container_by_name (GNUNET_RPC_CallParameters *
                                                  param, const char *name)
{
  Parameter *p;
  GNUNET_DataContainer *ret;

  if (param == NULL)
    return NULL;
  p = GNUNET_vector_get_first (param);
  while (p != NULL)
    {
      if (!strcmp (p->name, name))
        {
          ret = GNUNET_malloc (sizeof (GNUNET_DataContainer) + p->dataLength);
          ret->size = htonl (sizeof (GNUNET_DataContainer) + p->dataLength);
          memcpy (&ret[1], p->data, p->dataLength);
          return ret;
        }
      p = GNUNET_vector_get_next (param);
    }

  return NULL;
}

/**
 * Return the value of the given parameter in the RPC parameter structure.
 *
 * @param param Target RPC parameter structure
 * @param value set to the value of the parameter
 */
int
GNUNET_RPC_parameters_get_value_by_index (GNUNET_RPC_CallParameters * param,
                                          unsigned int i,
                                          unsigned int *dataLength,
                                          void **value)
{
  Parameter *p;

  if (param == NULL)
    return GNUNET_SYSERR;
  p = GNUNET_vector_get (param, i);
  if (p != NULL)
    {
      *dataLength = p->dataLength;
      *value = p->data;
      return GNUNET_OK;
    }
  return GNUNET_SYSERR;
}

/**
 * Return the value of the given parameter in the RPC parameter structure.
 *
 * @param param Target RPC parameter structure
 * @param value set to the value of the parameter
 */
GNUNET_DataContainer *
GNUNET_RPC_parameters_get_data_container_by_index (GNUNET_RPC_CallParameters *
                                                   param, unsigned int i)
{
  Parameter *p;
  GNUNET_DataContainer *ret;

  if (param == NULL)
    return NULL;
  p = GNUNET_vector_get (param, i);
  if (p != NULL)
    {
      ret = GNUNET_malloc (sizeof (GNUNET_DataContainer) + p->dataLength);
      ret->size = htonl (sizeof (GNUNET_DataContainer) + p->dataLength);
      memcpy (&ret[1], p->data, p->dataLength);
      return ret;
    }
  return NULL;
}

/* end of parameters.c */
