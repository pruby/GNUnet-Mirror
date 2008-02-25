/*
     This file is part of GNUnet.
     (C) 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/hostlist/hostlist.c
 * @author Christian Grothoff
 * @brief application to provide an integrated hostlist HTTP server
 */

#include "platform.h"
#include <microhttpd.h>
#include "gnunet_identity_service.h"
#include "gnunet_stats_service.h"
#include "gnunet_protocols.h"

#define DEBUG_HOSTLIST GNUNET_NO

static struct MHD_Daemon *daemon_handle;

static GNUNET_CoreAPIForPlugins *coreAPI;

static GNUNET_Identity_ServiceAPI *identity;

static GNUNET_Stats_ServiceAPI *stats;

static int stat_request_count;

static int stat_hello_returned;

static int stat_bytes_returned;

static int
accept_policy_callback (void *cls,
                        const struct sockaddr *addr, socklen_t addrlen)
{
  return MHD_YES;               /* accept all */
}

/**
 * Context for host processor.
 */
struct HostSet
{
  /**
   * Bitmap describing acceptable protocols.
   */
  unsigned long long protocols;

  unsigned int size;

  unsigned char *data;
};

static int
host_processor (const GNUNET_PeerIdentity * peer,
                unsigned short protocol, int confirmed, void *data)
{
  struct HostSet *results = data;
  GNUNET_MessageHello *hello;
  unsigned int old;

  if ((GNUNET_YES != confirmed) ||
      ((results->protocols & (1LL << protocol)) == 0))
    return GNUNET_OK;
  hello = identity->identity2Hello (peer, protocol, GNUNET_NO);
  if (hello == NULL)
    return GNUNET_OK;
  if (stats != NULL)
    stats->change (stat_hello_returned, 1);
  old = results->size;
  GNUNET_array_grow (results->data,
                     results->size,
                     results->size + ntohs (hello->header.size));
  memcpy (&results->data[old], hello, ntohs (hello->header.size));
  GNUNET_free (hello);
  return GNUNET_OK;
}

static int
access_handler_callback (void *cls,
                         struct MHD_Connection *connection,
                         const char *url,
                         const char *method,
                         const char *version,
                         const char *upload_data,
                         unsigned int *upload_data_size, void **con_cls)
{
  static int dummy;
  struct MHD_Response *response;
  struct HostSet results;
  const char *protos;
  int ret;
  int i;

  if (0 != strcmp (method, MHD_HTTP_METHOD_GET))
    return MHD_NO;
  if (NULL == *con_cls)
    {
      (*con_cls) = &dummy;
      return MHD_YES;           /* send 100 continue */
    }
  if (*upload_data_size != 0)
    return MHD_NO;              /* do not support upload data */
  memset (&results, 0, sizeof (struct HostSet));
  protos = MHD_lookup_connection_value (connection,
                                        MHD_GET_ARGUMENT_KIND, "p");
  if ((protos == NULL) || (1 != sscanf (protos, "%llu", &results.protocols)))
    results.protocols = -1;
  for (i = GNUNET_TRANSPORT_PROTOCOL_NUMBER_MAX;
       i > GNUNET_TRANSPORT_PROTOCOL_NUMBER_NAT; i--)
    host_processor (coreAPI->myIdentity, i, GNUNET_YES, &results);
  identity->forEachHost (GNUNET_get_time (), &host_processor, &results);
  if (results.size == 0)
    return MHD_NO;              /* no known hosts!? */
  if (stats != NULL)
    stats->change (stat_bytes_returned, results.size);
  response = MHD_create_response_from_data (results.size,
                                            results.data, MHD_YES, MHD_NO);
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);
  if (stats != NULL)
    stats->change (stat_request_count, 1);
  return ret;
}

int
initialize_module_hostlist (GNUNET_CoreAPIForPlugins * capi)
{
  int ok = GNUNET_OK;
  unsigned long long port;

  if (-1 == GNUNET_GC_get_configuration_value_number (capi->cfg,
                                                      "HOSTLIST",
                                                      "PORT", 0, 65535, 8080,
                                                      &port))
    return GNUNET_SYSERR;
  identity = capi->request_service ("identity");
  if (identity == NULL)
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  coreAPI = capi;
  stats = capi->request_service ("stats");
  if (stats != NULL)
    {
      stat_request_count
        = stats->create (gettext_noop ("# hostlist requests received"));
      stat_hello_returned
        = stats->create (gettext_noop ("# hostlist HELLOs returned"));
      stat_bytes_returned
        = stats->create (gettext_noop ("# hostlist bytes returned"));
    }
  daemon_handle = MHD_start_daemon (MHD_USE_SELECT_INTERNALLY | MHD_USE_IPv6,
                                    (unsigned short) port,
                                    &accept_policy_callback,
                                    NULL,
                                    &access_handler_callback,
                                    NULL,
                                    MHD_OPTION_CONNECTION_LIMIT, 16,
                                    MHD_OPTION_PER_IP_CONNECTION_LIMIT, 1,
                                    MHD_OPTION_CONNECTION_TIMEOUT, 16,
                                    MHD_OPTION_CONNECTION_MEMORY_LIMIT,
                                    16 * 1024, MHD_OPTION_END);
  if (daemon_handle == NULL)
    {
      if (stats != NULL)
        {
          coreAPI->release_service (stats);
          stats = NULL;
        }
      coreAPI->release_service (identity);
      identity = NULL;
      return GNUNET_SYSERR;
    }
  GNUNET_GE_ASSERT (capi->ectx,
                    0 == GNUNET_GC_set_configuration_value_string (capi->cfg,
                                                                   capi->ectx,
                                                                   "ABOUT",
                                                                   "hostlist",
                                                                   gettext_noop
                                                                   ("integrated HTTP hostlist server")));
  return ok;
}

void
done_module_hostlist ()
{
  MHD_stop_daemon (daemon_handle);
  daemon_handle = NULL;
  if (stats != NULL)
    {
      coreAPI->release_service (stats);
      stats = NULL;
    }
  coreAPI->release_service (identity);
  identity = NULL;
  coreAPI = NULL;
}

/* end of hostlist.c */
