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
 * @file rpc/parameters.c
 * @brief  This file provides convenience methods for parameter
 * handling.
 * @author Antti Salonen, Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_rpc_lib.h"

/**
 * A linked list of parameters to/from an RPC call.
 */
struct Parameter
{
  struct Parameter *next;
  char *name;
  void *data;
  unsigned int dataLength;
};

struct GNUNET_RPC_CallParameters
{
  struct Parameter *list;
};


/**
 * Allocate a new, empty RPC parameter structure.
 *
 * @return An empty GNUNET_RPC_CallParameters structure
 */
struct GNUNET_RPC_CallParameters *
GNUNET_RPC_parameters_create ()
{
  struct GNUNET_RPC_CallParameters *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_RPC_CallParameters));
  ret->list = NULL;
  return ret;
}

/**
 * Free the memory used by an RPC parameter structure. All parameter names and
 * values residing in the structure are freed, and thus all pointers returned
 * by this abstractions become dangling.
 *
 * @param param The RPC parameter structure to be freed
 */
void
GNUNET_RPC_parameters_destroy (struct GNUNET_RPC_CallParameters *param)
{
  if (param == NULL)
    return;
  while (param->list != NULL)
    {
      struct Parameter *p = param->list;
      param->list = p->next;
      GNUNET_free (p->name);
      GNUNET_free (p->data);
      GNUNET_free (p);
    }
  GNUNET_free (param);
}

/**
 * Serialize the param array.  target must point to at least
 * GNUNET_RPC_parameters_get_serialized_size(param) bytes of memory.
 */
void
GNUNET_RPC_parameters_serialize (const struct GNUNET_RPC_CallParameters
                                 *param, char *target)
{
  const struct Parameter *pos;
  unsigned int dataLength;
  size_t off;

  if (param == NULL)
    return;
  if (target == NULL)
    return;
  off = 0;
  dataLength = 0;
  pos = param->list;
  while (pos != NULL)
    {
      memcpy (&target[off], pos->name, strlen (pos->name) + 1);
      off += strlen (pos->name) + 1;
      dataLength = htonl (pos->dataLength);
      memcpy (&target[off], &dataLength, sizeof (unsigned int));
      off += sizeof (unsigned int);
      memcpy (&target[off], pos->data, pos->dataLength);
      off += pos->dataLength;
      pos = pos->next;
    }
}

/**
 * Deserialize parameters from buffer.
 */
struct GNUNET_RPC_CallParameters *
GNUNET_RPC_parameters_deserialize (const char *buffer, size_t size)
{
  struct GNUNET_RPC_CallParameters *ret;
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
      memcpy (&dataLength, &buffer[pos], sizeof (unsigned int));
      dataLength = ntohl (dataLength);
      pos += sizeof (unsigned int);
      if ((pos + dataLength < pos) || (pos + dataLength > size))
        {
          GNUNET_RPC_parameters_destroy (ret);
          return NULL;
        }
      GNUNET_RPC_parameters_add (ret,
                                 &buffer[xpos], dataLength, &buffer[pos]);
      pos += dataLength;
    }
  return ret;
}

/**
 * How many bytes are required to serialize the param array?
 */
size_t
GNUNET_RPC_parameters_get_serialized_size (const struct
                                           GNUNET_RPC_CallParameters * param)
{
  const struct Parameter *pos;
  size_t off;

  if (param == NULL)
    return 0;
  off = 0;
  pos = param->list;
  while (pos != NULL)
    {
      {
        off += strlen (pos->name) + 1;
        off += sizeof (unsigned int);
        off += pos->dataLength;
        pos = pos->next;
      }
    }
  return off;
}

/**
 * Return the number of parameters in an RPC parameter structure.
 *
 * @param param Target RPC parameter structure
 * @return The number of parameters
 */
unsigned int
GNUNET_RPC_parameters_count (const struct GNUNET_RPC_CallParameters *param)
{
  const struct Parameter *pos;
  unsigned int s;

  s = 0;
  pos = param->list;
  while (pos != NULL)
    {
      s++;
      pos = pos->next;
    }
  return s;
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
GNUNET_RPC_parameters_add (struct GNUNET_RPC_CallParameters *param,
                           const char *name, unsigned int dataLength,
                           const void *data)
{
  struct Parameter *p;
  struct Parameter *pos;

  if (param == NULL)
    return;
  p = GNUNET_malloc (sizeof (struct Parameter));
  p->name = GNUNET_strdup (name);
  p->dataLength = dataLength;
  if (dataLength == 0)
    {
      p->data = NULL;
    }
  else
    {
      p->data = GNUNET_malloc (dataLength);
      memcpy (p->data, data, dataLength);
    }
  p->next = NULL;
  if (param->list == NULL)
    {
      param->list = p;
    }
  else
    {
      pos = param->list;
      while (pos->next != NULL)
        pos = pos->next;
      pos->next = p;
    }
}

/**
 * Return the value of the named parameter in the RPC parameter structure.
 *
 * @param param Target RPC parameter structure
 * @param value set to the value of the named parameter
 * @return GNUNET_SYSERR on error
 */
int
GNUNET_RPC_parameters_get_value_by_name (const struct
                                         GNUNET_RPC_CallParameters *param,
                                         const char *name,
                                         unsigned int *dataLength,
                                         void const **value)
{
  const struct Parameter *p;

  if (param == NULL)
    return GNUNET_SYSERR;
  p = param->list;
  while (p != NULL)
    {
      if (!strcmp (p->name, name))
        {
          *value = p->data;
          *dataLength = p->dataLength;
          return GNUNET_OK;
        }
      p = p->next;
    }
  return GNUNET_SYSERR;
}

/**
 * Return the value of the given parameter in the RPC parameter structure.
 *
 * @param param Target RPC parameter structure
 * @param value set to the value of the parameter
 */
int
GNUNET_RPC_parameters_get_value_by_index (const struct
                                          GNUNET_RPC_CallParameters *param,
                                          unsigned int i,
                                          unsigned int *dataLength,
                                          void const **value)
{
  struct Parameter *p;

  if (param == NULL)
    return GNUNET_SYSERR;
  p = param->list;
  while ((i > 0) && (p != NULL))
    {
      i--;
      p = p->next;
    }
  if (p != NULL)
    {
      *dataLength = p->dataLength;
      *value = p->data;
      return GNUNET_OK;
    }
  return GNUNET_SYSERR;
}

/* end of parameters.c */
