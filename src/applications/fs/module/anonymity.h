/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/module/anonymity.h
 * @brief code for checking if cover traffic is sufficient
 * @author Christian Grothoff
 */

#ifndef ANONYMITY_H
#define ANONYMITY_H

#include "gnunet_traffic_service.h"

/**
 * consider traffic volume before sending out content.
 * ok, so this is not 100% clean since it kind-of
 * belongs into the gap code (since it is concerned
 * with anonymity and GAP messages).  So we should
 * probably move it below the callback by passing
 * the anonymity level along.  But that would
 * require changing the GNUNET_DataProcessor somewhat,
 * which would also be ugly.  So to keep things
 * simple, we do the anonymity-level check for
 * outgoing content right here.
 *
 * @return GNUNET_OK if cover traffic is sufficient
 */
int checkCoverTraffic (struct GNUNET_GE_Context *ectx,
                       GNUNET_Traffic_ServiceAPI * traffic,
                       unsigned int level);

#endif
