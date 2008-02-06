/*
     This file is part of GNUnet
     (C) 2001, 2002, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file server/core.c
 * @brief implementation of the GNUnet core API for applications
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_core.h"
#include "gnunet_identity_service.h"
#include "handler.h"
#include "tcpserver.h"
#include "core.h"

#define DEBUG_CORE GNUNET_NO

/**
 * Linked list of loaded protocols (for clean shutdown).
 */
typedef struct ShutdownList
{
  /**
   * Pointer to the library (as returned by dlopen).
   */
  struct GNUNET_PluginHandle *library;

  /**
   * Textual name of the library ("libgnunet_afs_protocol").
   */
  char *dsoName;

  /**
   * GNUNET_YES or GNUNET_NO: is the application initialized at this point?
   */
  int applicationInitialized;

  /**
   * Current number of users of the service API.
   */
  unsigned int serviceCount;

  /**
   * Pointer to the service API (or NULL if service not in use).
   */
  void *servicePTR;

  /**
   * This is a linked list.
   */
  struct ShutdownList *next;
} ShutdownList;

/**
 * Global for the core API.
 */
static GNUNET_CoreAPIForPlugins applicationCore;

/**
 * List of loaded modules and their status.
 */
static ShutdownList *shutdownList = NULL;

#define DSO_PREFIX "libgnunet"

/**
 * The identity of THIS node.
 */
static GNUNET_PeerIdentity myIdentity;

static GNUNET_Identity_ServiceAPI *identity;

/**
 * Load the application module named "pos".
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
loadApplicationModule (const char *rpos)
{
  int ok;
  ShutdownList *nxt;
  ShutdownList *spos;
  GNUNET_ApplicationPluginInitializationMethod mptr;
  struct GNUNET_PluginHandle *library;
  char *name;
  char *pos;

  pos = NULL;
  if (-1 == GNUNET_GC_get_configuration_value_string (applicationCore.cfg,
                                                      "MODULES", rpos, rpos,
                                                      &pos))
    return GNUNET_SYSERR;
  GNUNET_GE_ASSERT (applicationCore.ectx, pos != NULL);
  name = GNUNET_malloc (strlen (pos) + strlen ("module_") + 1);
  strcpy (name, "module_");
  strcat (name, pos);
  GNUNET_free (pos);

  nxt = shutdownList;
  while (nxt != NULL)
    {
      if (0 == strcmp (name, nxt->dsoName))
        {
          if (nxt->applicationInitialized == GNUNET_YES)
            {
              GNUNET_GE_LOG (applicationCore.ectx,
                             GNUNET_GE_WARNING | GNUNET_GE_DEVELOPER |
                             GNUNET_GE_BULK,
                             _
                             ("Application module `%s' already initialized!\n"),
                             name);
              GNUNET_free (name);
              return GNUNET_SYSERR;
            }
          else
            {
              mptr = GNUNET_plugin_resolve_function (nxt->library,
                                                     "initialize_",
                                                     GNUNET_YES);
              if (mptr == NULL)
                {
                  GNUNET_free (name);
                  return GNUNET_SYSERR;
                }
              ok = mptr (&applicationCore);
              if (ok == GNUNET_OK)
                nxt->applicationInitialized = GNUNET_YES;
              GNUNET_free (name);
              return ok;
            }
        }
      nxt = nxt->next;
    }

  library = GNUNET_plugin_load (applicationCore.ectx, DSO_PREFIX, name);
  if (library == NULL)
    {
      GNUNET_free (name);
      return GNUNET_SYSERR;
    }
  mptr = GNUNET_plugin_resolve_function (library, "initialize_", GNUNET_YES);
  if (mptr == NULL)
    {
      GNUNET_plugin_unload (library);
      GNUNET_free (name);
      return GNUNET_SYSERR;
    }
  nxt = GNUNET_malloc (sizeof (ShutdownList));
  nxt->next = shutdownList;
  nxt->dsoName = name;
  nxt->library = library;
  nxt->applicationInitialized = GNUNET_YES;
  nxt->serviceCount = 0;
  nxt->servicePTR = NULL;
  shutdownList = nxt;
  ok = mptr (&applicationCore);
  if (GNUNET_OK != ok)
    {
      /* undo loading */
      GNUNET_GE_LOG (applicationCore.ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_ADMIN |
                     GNUNET_GE_BULK,
                     _
                     ("Failed to load plugin `%s' at %s:%d.  Unloading plugin.\n"),
                     name, __FILE__, __LINE__);
      /* Note: we cannot assert that shutdownList == nxt here,
         so we have to traverse the list again! */
      nxt->applicationInitialized = GNUNET_NO;
      if (shutdownList == nxt)
        {
          spos = NULL;
        }
      else
        {
          spos = shutdownList;
          while (spos->next != nxt)
            {
              spos = spos->next;
              if (spos == NULL)
                {
                  GNUNET_GE_BREAK (applicationCore.ectx, 0);    /* should never happen! */
                  return ok;
                }
            }
        }
      if (spos == NULL)
        shutdownList = nxt->next;
      else
        spos->next = nxt->next;
      GNUNET_plugin_unload (library);
      GNUNET_free (name);
      GNUNET_free (nxt);
    }
  return ok;
}

static int
unloadApplicationModule (const char *name)
{
  ShutdownList *pos;
  ShutdownList *prev;
  GNUNET_ApplicationPluginShutdownMethod mptr;

  prev = NULL;
  pos = shutdownList;
  while ((pos != NULL) && (0 != strcmp (name, pos->dsoName)))
    pos = pos->next;

  if (pos == NULL)
    {
      GNUNET_GE_LOG (applicationCore.ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_BULK |
                     GNUNET_GE_DEVELOPER,
                     _("Could not shutdown `%s': application not loaded\n"),
                     name);
      return GNUNET_SYSERR;
    }

  if (pos->applicationInitialized != GNUNET_YES)
    {
      GNUNET_GE_LOG (applicationCore.ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK |
                     GNUNET_GE_DEVELOPER,
                     _
                     ("Could not shutdown application `%s': not initialized\n"),
                     name);
      return GNUNET_SYSERR;
    }
  mptr = GNUNET_plugin_resolve_function (pos->library, "done_", GNUNET_YES);
  if (mptr == NULL)
    {
      GNUNET_GE_LOG (applicationCore.ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_DEVELOPER |
                     GNUNET_GE_BULK,
                     _("Could not find '%s%s' method in library `%s'.\n"),
                     "done_", pos->dsoName, pos->dsoName);
      return GNUNET_SYSERR;
    }
  mptr ();
  pos->applicationInitialized = GNUNET_NO;
  if (pos->serviceCount > 0)
    return GNUNET_OK;

  /* compute prev! */
  if (pos == shutdownList)
    {
      prev = NULL;
    }
  else
    {
      prev = shutdownList;
      while (prev->next != pos)
        prev = prev->next;
    }
  GNUNET_plugin_unload (pos->library);
  if (prev == NULL)
    shutdownList = pos->next;
  else
    prev->next = pos->next;
  GNUNET_free (pos->dsoName);
  GNUNET_free (pos);
  return GNUNET_OK;
}

void *
GNUNET_CORE_request_service (const char *rpos)
{
  ShutdownList *nxt;
  GNUNET_ServicePluginInitializationMethod mptr;
  void *library;
  char *name;
  void *api;
  char *pos;

  /* subtyping, GNUnet style */
  pos = NULL;
  if (-1 == GNUNET_GC_get_configuration_value_string (applicationCore.cfg,
                                                      "MODULES", rpos, rpos,
                                                      &pos))
    return NULL;
  GNUNET_GE_ASSERT (applicationCore.ectx, pos != NULL);
  name = GNUNET_malloc (strlen (pos) + strlen ("module_") + 1);
  strcpy (name, "module_");
  strcat (name, pos);

  nxt = shutdownList;
  while (nxt != NULL)
    {
      if (0 == strcmp (name, nxt->dsoName))
        {
          if (nxt->serviceCount > 0)
            {
              if (nxt->servicePTR != NULL)
                nxt->serviceCount++;
              GNUNET_free (name);
              GNUNET_free (pos);
              return nxt->servicePTR;
            }
          else
            {
              mptr = GNUNET_plugin_resolve_function (nxt->library,
                                                     "provide_", GNUNET_YES);
              if (mptr == NULL)
                {
                  GNUNET_free (name);
                  GNUNET_free (pos);
                  return NULL;
                }
              nxt->servicePTR = mptr (&applicationCore);
              if (nxt->servicePTR != NULL)
                nxt->serviceCount++;
              GNUNET_free (name);
              GNUNET_free (pos);
              return nxt->servicePTR;
            }
        }
      nxt = nxt->next;
    }

  library = GNUNET_plugin_load (applicationCore.ectx, DSO_PREFIX, name);
  if (library == NULL)
    {
      GNUNET_free (name);
      GNUNET_free (pos);
      return NULL;
    }
  mptr = GNUNET_plugin_resolve_function (library, "provide_", GNUNET_YES);
  if (mptr == NULL)
    {
      GNUNET_plugin_unload (library);
      GNUNET_free (name);
      GNUNET_free (pos);
      return NULL;
    }
  nxt = GNUNET_malloc (sizeof (ShutdownList));
  nxt->next = shutdownList;
  nxt->dsoName = name;
  nxt->library = library;
  nxt->applicationInitialized = GNUNET_NO;
  nxt->serviceCount = 1;
  nxt->servicePTR = NULL;
  shutdownList = nxt;
  GNUNET_GE_LOG (applicationCore.ectx,
                 GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                 "Loading service `%s'\n", pos);
  api = mptr (&applicationCore);
  if (api != NULL)
    {
      nxt->servicePTR = api;
    }
  else
    {
      GNUNET_GE_LOG (applicationCore.ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_IMMEDIATE, "Failed to load service `%s'\n",
                     pos);
      nxt->serviceCount = 0;
    }
  GNUNET_free (pos);
  return api;
}

int
GNUNET_CORE_release_service (void *service)
{
  ShutdownList *pos;
  ShutdownList *prev;
  GNUNET_ApplicationPluginShutdownMethod mptr;

  if (service == NULL)
    return GNUNET_OK;
  prev = NULL;
  pos = shutdownList;
  while ((pos != NULL) && (pos->servicePTR != service))
    pos = pos->next;

  if (pos == NULL)
    {
      GNUNET_GE_LOG (applicationCore.ectx,
                     GNUNET_GE_BULK | GNUNET_GE_DEVELOPER | GNUNET_GE_ERROR,
                     _("Could not release %p: service not loaded\n"),
                     service);
      return GNUNET_SYSERR;
    }
  if (pos->serviceCount > 1)
    {
      pos->serviceCount--;
      return GNUNET_OK;         /* service still in use elsewhere! */
    }
  GNUNET_GE_LOG (applicationCore.ectx,
                 GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                 "Unloading service `%s'.\n", pos->dsoName);
  mptr =
    GNUNET_plugin_resolve_function (pos->library, "release_", GNUNET_YES);
  if (mptr == NULL)
    return GNUNET_SYSERR;
  mptr ();
  pos->serviceCount--;
  pos->servicePTR = NULL;

  if (pos->applicationInitialized == GNUNET_YES)
    return GNUNET_OK;           /* protocol still in use! */
  /* compute prev */
  if (pos == shutdownList)
    {
      prev = NULL;
    }
  else
    {
      prev = shutdownList;
      while (prev->next != pos)
        prev = prev->next;
    }
  if (prev == NULL)
    shutdownList = pos->next;
  else
    prev->next = pos->next;
  GNUNET_plugin_unload (pos->library);
  GNUNET_free (pos->dsoName);
  GNUNET_free (pos);
  return GNUNET_OK;
}

int
GNUNET_CORE_load_application_modules ()
{
  char *dso;
  char *next;
  char *pos;
  int ok;

  ok = GNUNET_OK;
  dso = NULL;
  if (-1 == GNUNET_GC_get_configuration_value_string (applicationCore.cfg,
                                                      "GNUNETD",
                                                      "APPLICATIONS",
                                                      "advertising fs getoption stats traffic",
                                                      &dso))
    return GNUNET_SYSERR;
  GNUNET_GE_ASSERT (applicationCore.ectx, dso != NULL);
  next = dso;
  do
    {
      while (*next == ' ')
        next++;
      pos = next;
      while ((*next != '\0') && (*next != ' '))
        next++;
      if (*next == '\0')
        {
          next = NULL;          /* terminate! */
        }
      else
        {
          *next = '\0';         /* add 0-termination for pos */
          next++;
        }
      if (strlen (pos) > 0)
        {
          GNUNET_GE_LOG (applicationCore.ectx,
                         GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_BULK,
                         "Loading application `%s'\n", pos);
          if (GNUNET_OK != loadApplicationModule (pos))
            ok = GNUNET_SYSERR;
        }
    }
  while (next != NULL);
  GNUNET_free (dso);
  return ok;
}

int
GNUNET_CORE_unload_application_modules ()
{
  ShutdownList *pos;
  ShutdownList *nxt;
  int ok;

  ok = GNUNET_OK;
  pos = shutdownList;
  while (pos != NULL)
    {
      nxt = pos->next;
      if ((pos->applicationInitialized == GNUNET_YES) &&
          (GNUNET_OK != unloadApplicationModule (pos->dsoName)))
        {
          GNUNET_GE_LOG (applicationCore.ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_DEVELOPER |
                         GNUNET_GE_BULK,
                         _("Could not properly shutdown application `%s'.\n"),
                         pos->dsoName);
          ok = GNUNET_SYSERR;
        }
      pos = nxt;
    }
  return GNUNET_OK;
}

/**
 * Initialize the CORE's globals.
 */
int
GNUNET_CORE_init (struct GNUNET_GE_Context *ectx,
                  struct GNUNET_GC_Configuration *cfg,
                  struct GNUNET_CronManager *cron,
                  struct GNUNET_LoadMonitor *monitor)
{
  applicationCore.ectx = ectx;
  applicationCore.cfg = cfg;
  applicationCore.load_monitor = monitor;
  applicationCore.cron = cron;
  applicationCore.version = 0;
  applicationCore.myIdentity = NULL;    /* for now */
  applicationCore.request_service = &GNUNET_CORE_request_service;       /* core.c */
  applicationCore.release_service = &GNUNET_CORE_release_service;       /* core.c */

  applicationCore.connection_send_plaintext = &GNUNET_CORE_connection_send_plaintext;   /* connection.c */
  applicationCore.unicast = &GNUNET_CORE_connection_unicast;    /* connection.c */
  applicationCore.connection_send_using_callback = &GNUNET_CORE_connection_send_using_callback; /* connection.c */
  applicationCore.forAllConnectedNodes = &GNUNET_CORE_connection_iterate_peers; /* connection.c */
  applicationCore.connection_register_send_callback = &GNUNET_CORE_connection_register_send_callback;   /* connection.c */
  applicationCore.connection_unregister_send_callback = &GNUNET_CORE_connection_unregister_send_callback;       /* connection.c */
  applicationCore.reserve_downstream_bandwidth = &GNUNET_CORE_connection_reserve_downstream_bandwidth;  /* connection.c */
  applicationCore.register_notify_peer_disconnect = &GNUNET_CORE_connection_register_notify_peer_disconnect;    /* connection .c */
  applicationCore.unregister_notify_peer_disconnect = &GNUNET_CORE_connection_unregister_notify_peer_disconnect;        /* connection .c */


  applicationCore.connection_register_send_notification_callback =
    &GNUNET_CORE_connection_register_send_notification_callback;
  applicationCore.
    connection_unregister_send_notification_callback =
    &GNUNET_CORE_connection_unregister_send_notification_callback;
  applicationCore.registerHandler = &GNUNET_CORE_p2p_register_handler;  /* handler.c */
  applicationCore.unregisterHandler = &GNUNET_CORE_p2p_unregister_handler;      /* handler.c */
  applicationCore.plaintext_register_handler = &GNUNET_CORE_plaintext_register_handler; /* handler.c */
  applicationCore.plaintext_unregister_handler = &GNUNET_CORE_plaintext_unregister_handler;     /* handler.c */
  applicationCore.p2p_test_handler_registered = &GNUNET_CORE_p2p_test_handler_registered;       /* handler.c */

  applicationCore.offerTSessionFor = &GNUNET_CORE_connection_consider_takeover; /* connection.c */
  applicationCore.connection_assign_session_key_to_peer = &GNUNET_CORE_connection_assign_session_key_to_peer;   /* connection.c */
  applicationCore.connection_get_session_key_of_peer = &GNUNET_CORE_connection_get_session_key_of_peer; /* connection.c */
  applicationCore.connection_mark_session_as_confirmed = &GNUNET_CORE_connection_mark_session_as_confirmed;     /* connection.c */
  applicationCore.preferTrafficFrom = &GNUNET_CORE_connection_update_traffic_preference_for_peer;       /* connection.c */
  applicationCore.queryPeerStatus = &GNUNET_CORE_connection_get_bandwidth_assigned_to_peer;     /* connection.c */
  applicationCore.connection_disconnect_from_peer = &GNUNET_CORE_connection_disconnect_from_peer;       /* connection.c */

  applicationCore.sendValueToClient = &GNUNET_CORE_cs_send_result_to_client;    /* tcpserver.c */
  applicationCore.cs_send_to_client = &GNUNET_CORE_cs_send_to_client;   /* tcpserver.c */
  applicationCore.registerClientHandler = &GNUNET_CORE_register_handler;        /* tcpserver.c */
  applicationCore.unregisterClientHandler = &GNUNET_CORE_unregister_handler;    /* tcpserver.c */
  applicationCore.cs_exit_handler_register = &GNUNET_CORE_cs_register_exit_handler;     /* tcpserver.c */
  applicationCore.cs_exit_handler_unregister = &GNUNET_CORE_cs_exit_handler_unregister; /* tcpserver.c */
  applicationCore.cs_terminate_client_connection = &GNUNET_CORE_cs_terminate_client_connection; /* tcpserver.c */

  applicationCore.p2p_inject_message = &GNUNET_CORE_p2p_inject_message; /* handler.c */
  applicationCore.connection_compute_index_of_peer = &GNUNET_CORE_connection_compute_index_of_peer;     /* connection.c */
  applicationCore.connection_get_lock = &GNUNET_CORE_connection_get_lock;       /* connection.c */
  applicationCore.connection_get_slot_count = &GNUNET_CORE_connection_get_slot_count;   /* connection.c */
  applicationCore.connection_is_slot_used = &GNUNET_CORE_connection_is_slot_used;       /* connection.c */
  applicationCore.connection_get_last_activity_of_peer = &GNUNET_CORE_connection_get_last_activity_of_peer;     /* connection.c */
  applicationCore.connection_assert_tsession_unused = &GNUNET_CORE_connection_assert_tsession_unused;   /* connection.c */

  applicationCore.sendErrorMessageToClient = &GNUNET_CORE_cs_send_error_to_client;      /* tcpserver.c */
  applicationCore.cs_create_client_log_context = &GNUNET_CORE_cs_create_client_log_context;     /* tcpserver.c */

  identity = GNUNET_CORE_request_service ("identity");
  if (identity == NULL)
    return GNUNET_SYSERR;
  identity->getPeerIdentity (identity->getPublicPrivateKey (), &myIdentity);
  applicationCore.myIdentity = &myIdentity;     /* core.c */
  if (GNUNET_CORE_cs_init (ectx, cfg) != GNUNET_OK)
    {
      GNUNET_CORE_release_service (identity);
      return GNUNET_SYSERR;
    }
  GNUNET_CORE_p2p_init (ectx);
  return GNUNET_OK;
}

/**
 * Shutdown the CORE modules (shuts down all application modules).
 */
void
GNUNET_CORE_done ()
{
  ShutdownList *pos;
  ShutdownList *prev;
  ShutdownList *nxt;
  int change;

  GNUNET_CORE_p2p_done ();
  GNUNET_CORE_release_service (identity);
  identity = NULL;

  /* unload all modules;
     due to mutual dependencies we have
     to do a fixpoint iteration here! */
  pos = shutdownList;
  prev = NULL;
  change = 1;
  while (change)
    {
      pos = shutdownList;
      change = 0;
      while (pos != NULL)
        {
          if ((pos->applicationInitialized == GNUNET_NO)
              && (pos->serviceCount == 0))
            {
              change = 1;
              GNUNET_plugin_unload (pos->library);
              nxt = pos->next;
              if (prev == NULL)
                shutdownList = nxt;
              else
                prev->next = nxt;
              GNUNET_free (pos->dsoName);
              GNUNET_free (pos);
              pos = nxt;
            }
          else
            {
              prev = pos;
              pos = pos->next;
            }
        }
    }
  pos = shutdownList;
  while (pos != NULL)
    {
      GNUNET_GE_LOG (applicationCore.ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                     _("Could not properly unload service `%s'!\n"),
                     pos->dsoName);
      pos = pos->next;
    }
  GNUNET_CORE_cs_done ();
}

/* end of core.c */
