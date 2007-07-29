/*
     This file is part of GNUnet.
     (C) 2007 Christian Grothoff (and other contributing authors)

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
 * @file util/network/ipchecktest.c
 * @brief testcase for util/network/ipcheck.c
 */

#include "gnunet_util.h"
#include "platform.h"

int
test ()
{
  struct CIDRNetwork *cidr;

  cidr = parse_ipv4_network_specification (NULL, "127.0.0.1;");
  if (cidr == NULL)
    return 1;
  FREE (cidr);
  cidr = parse_ipv4_network_specification (NULL, "127.0.0.1/8;");
  if (cidr == NULL)
    return 2;
  FREE (cidr);
  cidr = parse_ipv4_network_specification (NULL, "0.0.0.0/0;");
  if (cidr == NULL)
    return 4;
  FREE (cidr);
  return 0;
}

int
main (int argc, char *argv[])
{
  int ret;
  ret = test ();
  if (ret != 0)
    fprintf (stderr, "ERROR %d.\n", ret);
  return ret;
}

/* end of ipchecktest.c */
