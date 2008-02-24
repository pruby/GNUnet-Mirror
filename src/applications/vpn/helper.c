/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/vpn/helper.c
 * @author Michael John Wensley
 * @brief tunnel RFC 4193 in GNUnet
 *
 * TODO:
 * - use better naming conventions
 * - elimiante isEqualP and isEqual
 */

#include "helper.h"




/** Test if two GNUNET_RSA_PublicKey are equal or not */
int
isEqualP (const GNUNET_RSA_PublicKey * first,
          const GNUNET_RSA_PublicKey * second)
{
  return 0 == memcmp (first, second, sizeof (GNUNET_RSA_PublicKey));
}


/**
 * Render IPv4 or IPv6 packet info for logging.
 */
void
ipinfo (char *info, const struct ip6_hdr *fp)
{
  struct in_addr fr4;
  struct in_addr to4;

  if ((((const struct iphdr *) fp)->version == 4))
    {
      fr4.s_addr = ((const struct iphdr *) fp)->saddr;
      to4.s_addr = ((const struct iphdr *) fp)->daddr;
      sprintf (info, "IPv4 %s -> ", inet_ntoa (fr4));
      strcat (info, inet_ntoa (to4));
      return;
    }
  if ((((const struct iphdr *) fp)->version == 6))
    {
      sprintf (info,
               "IPv6 %x:%x:%x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x:%x:%x",
               ntohs (fp->ip6_src.s6_addr16[0]),
               ntohs (fp->ip6_src.s6_addr16[1]),
               ntohs (fp->ip6_src.s6_addr16[2]),
               ntohs (fp->ip6_src.s6_addr16[3]),
               ntohs (fp->ip6_src.s6_addr16[4]),
               ntohs (fp->ip6_src.s6_addr16[5]),
               ntohs (fp->ip6_src.s6_addr16[6]),
               ntohs (fp->ip6_src.s6_addr16[7]),
               ntohs (fp->ip6_dst.s6_addr16[0]),
               ntohs (fp->ip6_dst.s6_addr16[1]),
               ntohs (fp->ip6_dst.s6_addr16[2]),
               ntohs (fp->ip6_dst.s6_addr16[3]),
               ntohs (fp->ip6_dst.s6_addr16[4]),
               ntohs (fp->ip6_dst.s6_addr16[5]),
               ntohs (fp->ip6_dst.s6_addr16[6]),
               ntohs (fp->ip6_dst.s6_addr16[7]));
      return;
    }
  sprintf (info, "IPv%d ?", ((const struct iphdr *) fp)->version);
}



/** Test if two GNUNET_PeerIdentity are equal or not */
int
isEqual (const GNUNET_PeerIdentity * first,
         const GNUNET_PeerIdentity * second)
{
  return (0 == memcmp (first, second, sizeof (GNUNET_PeerIdentity))) ? -1 : 0;
}




/* convert GNUNET_PeerIdentity into network octet order IPv6 address */
void
id2net (struct in6_addr *buf, const GNUNET_PeerIdentity * them)
{
  unsigned char a, b, c, d, e;
  a = (them->hashPubKey.bits[0] >> 8) & 0xff;
  b = (them->hashPubKey.bits[0] >> 0) & 0xff;
  c = (them->hashPubKey.bits[1] >> 8) & 0xff;
  d = (them->hashPubKey.bits[1] >> 0) & 0xff;
  e = (them->hashPubKey.bits[2] >> 8) & 0xff;

  /* we are unique random */
  buf->s6_addr16[0] = htons (0xfd00 + a);
  buf->s6_addr16[1] = htons (b * 256 + c);
  buf->s6_addr16[2] = htons (d * 256 + e);

  /* IPv6 /48 subnet number is zero */
  buf->s6_addr16[3] = 0;

  /* IPV6 /64 interface is zero */
  buf->s6_addr16[4] = 0;
  buf->s6_addr16[5] = 0;
  buf->s6_addr16[6] = 0;
  buf->s6_addr16[7] = 0;
}
