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

int main(int argc, char * argv[]){
  RPC_Param * p;
  void * buf;
  size_t size;
  unsigned int len;

  p = RPC_paramNew();

  if (SYSERR != RPC_paramValueByPosition(p,
					 0,
					 &len,
					 &buf))
    return 1;

  if (SYSERR != RPC_paramValueByName(p,
				     "not there",
				     &len,
				     &buf))
    return 1;

  if (RPC_paramCount(p) != 0)
    return 1;
  RPC_paramAdd(p,
	       "foo",
	       4,
	       "bar");
  RPC_paramAdd(p,
	       "bar",
	       4,
	       "foo");
  if (RPC_paramCount(p) != 2)
    return 1;
  if (0 != strcmp(RPC_paramName(p, 0),
		  "foo"))
    return 1;
  if (0 != strcmp(RPC_paramName(p, 1),
		  "bar"))
    return 1;

  size = RPC_paramSize(p);
  buf = MALLOC(size);
  RPC_paramSerialize(p, buf);
  RPC_paramFree(p);
  p = RPC_paramDeserialize(buf,
			   size);
  FREE(buf);
  if (p == NULL)
    return 1;
  buf = NULL;
  if (OK != RPC_paramValueByName(p,
				 "foo",
				 &len,
				 &buf))
    return 1;
  if (strcmp("bar", buf) != 0)
    return 1;
  buf = NULL;
  if (4 != len)
    return 1;
  if (OK != RPC_paramValueByPosition(p,
				     1,
				     &len,
				     &buf))
    return 1;
  if (strcmp("foo", buf) != 0)
    return 1;
  if (4 != len)
    return 1;
  if (SYSERR != RPC_paramValueByPosition(p,
					 2,
					 &len,
					 &buf))
    return 1;

  if (SYSERR != RPC_paramValueByName(p,
				     "not there",
				     &len,
				     &buf))
    return 1;
  RPC_paramFree(p);

  return 0;
}
