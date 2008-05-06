/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2008 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file applications/fs/gap/anonymity.c
 * @brief code for checking if cover traffic is sufficient
 * @author Christian Grothoff
 */

#include "platform.h"
#include "anonymity.h"
#include "gnunet_protocols.h"
#include "gnunet_traffic_service.h"

static GNUNET_Traffic_ServiceAPI *traffic;

static GNUNET_CoreAPIForPlugins *coreAPI;

int
GNUNET_FS_ANONYMITY_check (unsigned int level, unsigned short content_type)
{
  unsigned int count;
  unsigned int peers;
  unsigned int sizes;
  unsigned int timevect;

  if (level == 0)
    return GNUNET_OK;
  level--;
  if (traffic == NULL)
    return GNUNET_SYSERR;
  if (GNUNET_OK != traffic->get (5 * GNUNET_CRON_SECONDS / GNUNET_TRAFFIC_TIME_UNIT,    /* GNUNET_GAP_TTL_DECREMENT/TTU */
                                 content_type,
                                 GNUNET_TRAFFIC_TYPE_RECEIVED, &count, &peers,
                                 &sizes, &timevect))
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Failed to get traffic stats.\n"));
      return GNUNET_SYSERR;
    }
  if (level > 1000)
    {
      if (peers < level / 1000)
        {
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "Not enough cover traffic to satisfy anonymity requirements (%u, %u peers). "
                         "Result dropped.\n", level, peers);
          return GNUNET_SYSERR;
        }
      if (count < level % 1000)
        {
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "Not enough cover traffic to satisfy anonymity requirements (%u, %u messages). "
                         "Result dropped.\n", level, count);
          return GNUNET_SYSERR;
        }
    }
  else
    {
      if (count < level)
        {
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "Not enough cover traffic to satisfy anonymity requirements (%u, %u messages). "
                         "Result dropped.\n", level, count);
          return GNUNET_SYSERR;
        }
    }
  return GNUNET_OK;
}


/**
 * Initialize the migration module.
 */
void
GNUNET_FS_ANONYMITY_init (GNUNET_CoreAPIForPlugins * capi)
{
  coreAPI = capi;
  traffic = capi->service_request ("traffic");
}

void
GNUNET_FS_ANONYMITY_done ()
{
  if (traffic != NULL)
    {
      coreAPI->service_release (traffic);
      traffic = NULL;
    }
  coreAPI = NULL;
}

/* end of anonymity.c */
