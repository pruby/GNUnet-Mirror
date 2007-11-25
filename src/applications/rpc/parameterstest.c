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
 * @file applications/rpc/parameterstest.c
 * @brief testcase for parameters.c
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "parameters.c"

int
main (int argc, char *argv[])
{
  GNUNET_RPC_CallParameters *p;
  void *buf;
  size_t size;
  unsigned int len;

  p = GNUNET_RPC_parameters_create ();

  if (GNUNET_SYSERR !=
      GNUNET_RPC_parameters_get_value_by_index (p, 0, &len, &buf))
    return 1;

  if (GNUNET_SYSERR !=
      GNUNET_RPC_parameters_get_value_by_name (p, "not there", &len, &buf))
    return 1;

  if (GNUNET_RPC_parameters_count (p) != 0)
    return 1;
  GNUNET_RPC_parameters_add (p, "foo", 4, "bar");
  GNUNET_RPC_parameters_add (p, "bar", 4, "foo");
  if (GNUNET_RPC_parameters_count (p) != 2)
    return 1;
  if (0 != strcmp (GNUNET_RPC_parameters_get_name (p, 0), "foo"))
    return 1;
  if (0 != strcmp (GNUNET_RPC_parameters_get_name (p, 1), "bar"))
    return 1;

  size = GNUNET_RPC_parameters_get_serialized_size (p);
  buf = GNUNET_malloc (size);
  GNUNET_RPC_parameters_serialize (p, buf);
  GNUNET_RPC_parameters_destroy (p);
  p = GNUNET_RPC_parameters_deserialize (buf, size);
  GNUNET_free (buf);
  if (p == NULL)
    return 1;
  buf = NULL;
  if (GNUNET_OK !=
      GNUNET_RPC_parameters_get_value_by_name (p, "foo", &len, &buf))
    return 1;
  if (strcmp ("bar", buf) != 0)
    return 1;
  buf = NULL;
  if (4 != len)
    return 1;
  if (GNUNET_OK !=
      GNUNET_RPC_parameters_get_value_by_index (p, 1, &len, &buf))
    return 1;
  if (strcmp ("foo", buf) != 0)
    return 1;
  if (4 != len)
    return 1;
  if (GNUNET_SYSERR !=
      GNUNET_RPC_parameters_get_value_by_index (p, 2, &len, &buf))
    return 1;

  if (GNUNET_SYSERR !=
      GNUNET_RPC_parameters_get_value_by_name (p, "not there", &len, &buf))
    return 1;
  GNUNET_RPC_parameters_destroy (p);

  return 0;
}
