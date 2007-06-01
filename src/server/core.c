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

#define DEBUG_CORE NO

/**
 * Linked list of loaded protocols (for clean shutdown).
 */
typedef struct ShutdownList {
  /**
   * Pointer to the library (as returned by dlopen).
   */
  struct PluginHandle * library;

  /**
   * Textual name of the library ("libgnunet_afs_protocol").
   */
  char * dsoName;

  /**
   * YES or NO: is the application initialized at this point?
   */
  int applicationInitialized;

  /**
   * Current number of users of the service API.
   */
  unsigned int serviceCount;

  /**
   * Pointer to the service API (or NULL if service not in use).
   */
  void * servicePTR;

  /**
   * This is a linked list.
   */
  struct ShutdownList * next;
} ShutdownList;

/**
 * Global for the core API.
 */
static CoreAPIForApplication applicationCore;

/**
 * List of loaded modules and their status.
 */
static ShutdownList * shutdownList = NULL;

#define DSO_PREFIX "libgnunet"

/**
 * The identity of THIS node.
 */
static PeerIdentity myIdentity;

static Identity_ServiceAPI * identity;

/**
 * Load the application module named "pos".
 * @return OK on success, SYSERR on error
 */
static int loadApplicationModule(const char * rpos) {
  int ok;
  ShutdownList * nxt;
  ShutdownList * spos;
  ApplicationInitMethod mptr;
  struct PluginHandle * library;
  char * name;
  char * pos;

  pos = NULL;
  if (-1 == GC_get_configuration_value_string(applicationCore.cfg,
					      "MODULES",
					      rpos,
					      rpos,
					      &pos))
    return SYSERR;
  GE_ASSERT(applicationCore.ectx, pos != NULL);
  name = MALLOC(strlen(pos) + strlen("module_") + 1);
  strcpy(name, "module_");
  strcat(name, pos);
  FREE(pos);

  nxt = shutdownList;
  while (nxt != NULL) {
    if (0 == strcmp(name,
		    nxt->dsoName)) {
      if (nxt->applicationInitialized == YES) {
	GE_LOG(applicationCore.ectx,
	       GE_WARNING | GE_DEVELOPER | GE_BULK,
	       _("Application module `%s' already initialized!\n"),
	       name);
	FREE(name);
	return SYSERR;
      } else {
	mptr = os_plugin_resolve_function(nxt->library,
					  "initialize_",
					  YES);
	if (mptr == NULL) {
	  FREE(name);
	  return SYSERR;
	}
	ok = mptr(&applicationCore);
	if (ok == OK)
	  nxt->applicationInitialized = YES;
	FREE(name);
	return ok;
      }
    }
    nxt = nxt->next;
  }

  library = os_plugin_load(applicationCore.ectx,
			   DSO_PREFIX,
			   name);
  if (library == NULL) {
    FREE(name);
    return SYSERR;
  }
  mptr = os_plugin_resolve_function(library,
				    "initialize_",
				    YES);
  if (mptr == NULL) {
    os_plugin_unload(library);
    FREE(name);
    return SYSERR;
  }
  nxt = MALLOC(sizeof(ShutdownList));
  nxt->next = shutdownList;
  nxt->dsoName = name;
  nxt->library = library;
  nxt->applicationInitialized = YES;
  nxt->serviceCount = 0;
  nxt->servicePTR = NULL;
  shutdownList = nxt;
  ok = mptr(&applicationCore);
  if (OK != ok) {
    /* undo loading */
    GE_LOG(applicationCore.ectx,
	   GE_WARNING | GE_USER | GE_ADMIN | GE_BULK,
	   _("Failed to load plugin `%s' at %s:%d.  Unloading plugin.\n"),
	   name, __FILE__, __LINE__);
    /* Note: we cannot assert that shutdownList == nxt here,
       so we have to traverse the list again! */
    nxt->applicationInitialized = NO;
    if (shutdownList == nxt) {
      spos = NULL;
    } else {
      spos = shutdownList;
      while (spos->next != nxt) {
	spos = spos->next;
	if (spos == NULL) {
	  GE_BREAK(applicationCore.ectx, 0); /* should never happen! */
	  return ok;
	}
      }
    }
    if (spos == NULL)
      shutdownList = nxt->next;
    else
      spos->next = nxt->next;
    os_plugin_unload(library);
    FREE(name);
    FREE(nxt);
  }
  return ok;
}

static int unloadApplicationModule(const char * name) {
  ShutdownList * pos;
  ShutdownList * prev;
  ApplicationDoneMethod mptr;

  prev = NULL;
  pos = shutdownList;
  while ( (pos != NULL) &&
	  (0 != strcmp(name,
		       pos->dsoName) ) )
    pos = pos->next;

  if (pos == NULL) {
    GE_LOG(applicationCore.ectx,
	   GE_ERROR | GE_USER | GE_BULK | GE_DEVELOPER,
	   _("Could not shutdown `%s': application not loaded\n"),
	   name);
    return SYSERR;
  }

  if (pos->applicationInitialized != YES) {
    GE_LOG(applicationCore.ectx,
	   GE_WARNING | GE_USER | GE_BULK | GE_DEVELOPER,
	   _("Could not shutdown application `%s': not initialized\n"),
	   name);
    return SYSERR;
  }
  mptr = os_plugin_resolve_function(pos->library,
				    "done_",
				    YES);
  if (mptr == NULL) {
    GE_LOG(applicationCore.ectx,
	   GE_ERROR | GE_USER | GE_DEVELOPER | GE_BULK,
	   _("Could not find '%s%s' method in library `%s'.\n"),
	   "done_",
	   pos->dsoName,
	   pos->dsoName);
    return SYSERR;
  }
  mptr();
  pos->applicationInitialized = NO;
  if (pos->serviceCount > 0)
    return OK;

  /* compute prev! */
  if (pos == shutdownList) {
    prev = NULL;
  } else {
    prev = shutdownList;
    while (prev->next != pos)
      prev = prev->next;
  }
  os_plugin_unload(pos->library);
  if (prev == NULL)
    shutdownList = pos->next;
  else
    prev->next = pos->next;
  FREE(pos->dsoName);
  FREE(pos);
  return OK;
}

void * requestService(const char * rpos) {
  ShutdownList * nxt;
  ServiceInitMethod mptr;
  void * library;
  char * name;
  void * api;
  char * pos;

  /* subtyping, GNUnet style */
  pos = NULL;
  if (-1 == GC_get_configuration_value_string(applicationCore.cfg,
					      "MODULES",
					      rpos,
					      rpos,
					      &pos))
    return NULL;
  GE_ASSERT(applicationCore.ectx, pos != NULL);
  name = MALLOC(strlen(pos) + strlen("module_") + 1);
  strcpy(name, "module_");
  strcat(name, pos);

  nxt = shutdownList;
  while (nxt != NULL) {
    if (0 == strcmp(name,
		    nxt->dsoName)) {
      if (nxt->serviceCount > 0) {
	if (nxt->servicePTR != NULL)
	  nxt->serviceCount++;
	FREE(name);
	FREE(pos);
	return nxt->servicePTR;
      } else {
	mptr = os_plugin_resolve_function(nxt->library,
					  "provide_",
					  YES);
	if (mptr == NULL) {
	  FREE(name);
	  FREE(pos);
	  return NULL;
	}
	nxt->servicePTR = mptr(&applicationCore);
	if (nxt->servicePTR != NULL)
	  nxt->serviceCount++;
	FREE(name);
	FREE(pos);
	return nxt->servicePTR;
      }
    }
    nxt = nxt->next;
  }

  library = os_plugin_load(applicationCore.ectx,
			   DSO_PREFIX,
			   name);
  if (library == NULL) {
    FREE(name);
    FREE(pos);
    return NULL;
  }
  mptr = os_plugin_resolve_function(library,
				    "provide_",
				    YES);
  if (mptr == NULL) {
    os_plugin_unload(library);
    FREE(name);
    FREE(pos);
    return NULL;
  }
  nxt = MALLOC(sizeof(ShutdownList));
  nxt->next = shutdownList;
  nxt->dsoName = name;
  nxt->library = library;
  nxt->applicationInitialized = NO;
  nxt->serviceCount = 1;
  nxt->servicePTR = NULL;
  shutdownList = nxt;
  GE_LOG(applicationCore.ectx,
	 GE_INFO | GE_USER | GE_REQUEST,
	 "Loading service `%s'\n",
	 pos);
  api = mptr(&applicationCore);
  if (api != NULL) {
    nxt->servicePTR = api;
  } else {
    GE_LOG(applicationCore.ectx,
	   GE_WARNING | GE_ADMIN | GE_USER | GE_IMMEDIATE,
	   "Failed to load service `%s'\n",
	   pos);
    nxt->serviceCount = 0;
  }
  FREE(pos);
  return api;
}

int releaseService(void * service) {
  ShutdownList * pos;
  ShutdownList * prev;
  ApplicationDoneMethod mptr;

  if (service == NULL)
    return OK;
  prev = NULL;
  pos = shutdownList;
  while ( (pos != NULL) &&
	  (pos->servicePTR != service) )
    pos = pos->next;

  if (pos == NULL) {
    GE_LOG(applicationCore.ectx,
	   GE_BULK | GE_DEVELOPER | GE_ERROR,
	   _("Could not release %p: service not loaded\n"),
	   service);
    return SYSERR;
  }
  if (pos->serviceCount > 1) {
    pos->serviceCount--;
    return OK; /* service still in use elsewhere! */
  }
  GE_LOG(applicationCore.ectx,
	 GE_INFO | GE_USER | GE_REQUEST,
	 "Unloading service `%s'.\n",
	 pos->dsoName);
  mptr = os_plugin_resolve_function(pos->library,
				    "release_",
				    YES);
  if (mptr == NULL)
    return SYSERR;
  mptr();
  pos->serviceCount--;
  pos->servicePTR = NULL;

  if (pos->applicationInitialized == YES)
    return OK; /* protocol still in use! */
  /* compute prev */
  if (pos == shutdownList) {
    prev = NULL;
  } else {
    prev = shutdownList;
    while (prev->next != pos)
      prev = prev->next;
  }
  if (prev == NULL)
    shutdownList = pos->next;
  else
    prev->next = pos->next;
  os_plugin_unload(pos->library);
  FREE(pos->dsoName);
  FREE(pos);
  return OK;
}

int loadApplicationModules() {
  char * dso;
  char * next;
  char * pos;
  int ok;

  ok = OK;
  dso = NULL;
  if (-1 == GC_get_configuration_value_string(applicationCore.cfg,
					      "GNUNETD",
					      "APPLICATIONS",
					      "advertising fs getoption stats traffic",
					      &dso))
    return SYSERR;
  GE_ASSERT(applicationCore.ectx, dso != NULL);
  next = dso;
  do {
    while (*next == ' ')
      next++;
    pos = next;
    while ( (*next != '\0') &&
	    (*next != ' ') )
      next++;
    if (*next == '\0') {
      next = NULL; /* terminate! */
    } else {
      *next = '\0'; /* add 0-termination for pos */
      next++;
    }
    if (strlen(pos) > 0) {
      GE_LOG(applicationCore.ectx,
	     GE_INFO | GE_USER | GE_BULK,
	     "Loading application `%s'\n",
	     pos);
      if (OK != loadApplicationModule(pos))
	ok = SYSERR;
    }
  } while (next != NULL);
  FREE(dso);
  return ok;
}

int unloadApplicationModules() {
  ShutdownList * pos;
  ShutdownList * nxt;
  int ok;

  ok = OK;
  pos = shutdownList;
  while (pos != NULL) {
    nxt = pos->next;
    if ( (pos->applicationInitialized == YES) &&
	 (OK != unloadApplicationModule(pos->dsoName)) ) {
      GE_LOG(applicationCore.ectx,
	     GE_ERROR | GE_DEVELOPER | GE_BULK,
	     _("Could not properly shutdown application `%s'.\n"),
	     pos->dsoName);
      ok = SYSERR;
    }
    pos = nxt;
  }
  return OK;
}

/**
 * Initialize the CORE's globals.
 */
int initCore(struct GE_Context * ectx,
	     struct GC_Configuration * cfg,
	     struct CronManager * cron,
	     struct LoadMonitor * monitor) {
  applicationCore.ectx = ectx;
  applicationCore.cfg = cfg;
  applicationCore.load_monitor = monitor;
  applicationCore.cron = cron;
  applicationCore.version = 0;
  applicationCore.myIdentity = NULL; /* for now */
  applicationCore.loadApplicationModule = &loadApplicationModule; /* core.c */
  applicationCore.unloadApplicationModule = &unloadApplicationModule; /* core.c */
  applicationCore.requestService = &requestService; /* core.c */
  applicationCore.releaseService = &releaseService; /* core.c */

  applicationCore.sendPlaintext = &sendPlaintext; /* connection.c */
  applicationCore.unicast = &unicast; /* connection.c */
  applicationCore.unicastCallback = &unicastCallback; /* connection.c */
  applicationCore.forAllConnectedNodes = &forEachConnectedNode; /* connection.c */
  applicationCore.registerSendCallback = &registerSendCallback; /* connection.c */
  applicationCore.unregisterSendCallback = &unregisterSendCallback; /* connection.c */

  applicationCore.registerSendNotify = &registerSendNotify;
  applicationCore.unregisterSendNotify = &unregisterSendNotify;
  applicationCore.registerHandler = &registerp2pHandler; /* handler.c */
  applicationCore.unregisterHandler = &unregisterp2pHandler; /* handler.c*/
  applicationCore.registerPlaintextHandler = &registerPlaintextHandler; /* handler.c */
  applicationCore.unregisterPlaintextHandler = &unregisterPlaintextHandler; /* handler.c*/
  applicationCore.isHandlerRegistered = &isHandlerRegistered; /* handler.c*/

  applicationCore.offerTSessionFor = &considerTakeover; /* connection.c */
  applicationCore.assignSessionKey = &assignSessionKey; /* connection.c */
  applicationCore.getCurrentSessionKey = &getCurrentSessionKey; /* connection.c */
  applicationCore.confirmSessionUp = &confirmSessionUp; /* connection.c */
  applicationCore.preferTrafficFrom = &updateTrafficPreference; /* connection.c */
  applicationCore.queryPeerStatus = &getBandwidthAssignedTo; /* connection.c */
  applicationCore.disconnectFromPeer = &disconnectFromPeer; /* connection.c */

  applicationCore.sendValueToClient = &sendTCPResultToClient; /* tcpserver.c */
  applicationCore.sendToClient = &sendToClient; /* tcpserver.c */
  applicationCore.registerClientHandler = &registerCSHandler; /* tcpserver.c */
  applicationCore.unregisterClientHandler = &unregisterCSHandler; /* tcpserver.c */
  applicationCore.registerClientExitHandler = &registerClientExitHandler; /* tcpserver.c */
  applicationCore.unregisterClientExitHandler = &unregisterClientExitHandler; /* tcpserver.c */
  applicationCore.terminateClientConnection = &terminateClientConnection;  /* tcpserver.c */

  applicationCore.injectMessage = &injectMessage; /* handler.c */
  applicationCore.computeIndex = &computeIndex; /* connection.c */
  applicationCore.getConnectionModuleLock = &getConnectionModuleLock; /* connection.c */
  applicationCore.getSlotCount = &getSlotCount; /* connection.c */
  applicationCore.isSlotUsed = &isSlotUsed; /* connection.c */
  applicationCore.getLastActivityOf = &getLastActivityOf; /* connection.c */

  applicationCore.sendErrorMessageToClient = &sendTCPErrorToClient; /* tcpserver.c */
  applicationCore.createClientLogContext = &createClientLogContext; /* tcpserver.c */

  identity = requestService("identity");
  if (identity == NULL)
    return SYSERR;
  identity->getPeerIdentity(identity->getPublicPrivateKey(),
			    &myIdentity);
  applicationCore.myIdentity = &myIdentity; /* core.c */
  if (initTCPServer(ectx,
		    cfg) != OK) {
    releaseService(identity);
    return SYSERR;
  }
  initHandler(ectx);
  return OK;
}

/**
 * Shutdown the CORE modules (shuts down all application modules).
 */
void doneCore() {
  ShutdownList * pos;
  ShutdownList * prev;
  ShutdownList * nxt;
  int change;

  doneHandler();
  releaseService(identity);
  identity = NULL;

  /* unload all modules;
     due to mutual dependencies we have
     to do a fixpoint iteration here! */
  pos = shutdownList;
  prev = NULL;
  change = 1;
  while (change) {
    pos = shutdownList;
    change = 0;
    while (pos != NULL) {
      if ( (pos->applicationInitialized == NO) &&
	   (pos->serviceCount == 0) ) {
	change = 1;
	os_plugin_unload(pos->library);		
	nxt = pos->next;
	if (prev == NULL)
	  shutdownList = nxt;
	else
	  prev->next = nxt;
	FREE(pos->dsoName);
	FREE(pos);
	pos = nxt;
      } else {
	prev = pos;
	pos = pos->next;
      }
    }
  }
  pos = shutdownList;
  while (pos != NULL) {
    GE_LOG(applicationCore.ectx,
	   GE_ERROR | GE_DEVELOPER | GE_BULK,
	   _("Could not properly unload service `%s'!\n"),
	   pos->dsoName);
    pos = pos->next;
  }
  doneTCPServer();
}

/* end of core.c */
