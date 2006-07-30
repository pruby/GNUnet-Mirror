/*
     This file is part of GNUnet.
     (C) 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file server/gnunet-update.c
 * @brief tool to process changes due to version updates
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_error_loggers.h"
#include "gnunet_util_cron.h"
#include "gnunet_core.h"
#include "core.h"
#include "startup.h"
#include "version.h"

/**
 * We may want to change this at some point into
 * something like libgnunet_update if we want to
 * separate the update code from the codebase
 * used in normal operation -- but currently I
 * see no need / use for that.
 */
#define DSO_PREFIX "libgnunet"

static struct GC_Configuration * cfg;

static struct GE_Context * ectx;

static char ** processed;

static unsigned int processedCount;

static UpdateAPI uapi;

/**
 * Allow the module named "pos" to update.
 * @return OK on success, SYSERR on error
 */
static int updateModule(const char * rpos) {
  UpdateMethod mptr;
  void * library;
  char * name;
  int i;
  char * pos;

  for (i=0;i<processedCount;i++)
    if (0 == strcmp(rpos, processed[i])) {
      return OK; /* already done */
    }
  GROW(processed, processedCount, processedCount+1);
  processed[processedCount-1] = STRDUP(rpos);

  pos = getConfigurationString("MODULES",
			       rpos);
  if (pos == NULL)
    pos = STRDUP(rpos);

  name = MALLOC(strlen(pos) + strlen("module_") + 1);
  strcpy(name, "module_");
  strcat(name, pos);
  FREE(pos);
  library = loadDynamicLibrary(DSO_PREFIX,
			       name);
  if (library == NULL) {
    FREE(name);
    return SYSERR;
  }
  mptr = trybindDynamicMethod(library,
			      "update_",
			      name);
  if (mptr == NULL) {
    FREE(name);
    return OK; /* module needs no updates! */
  }
  mptr(&uapi);
  unloadDynamicLibrary(library);
  FREE(name);
  return OK;
}

/**
 * Call the update module for each of the applications
 * in the current configuration.
 */
static void updateApplicationModules() {
  char * dso;
  char * next;
  char * pos;

  dso = getConfigurationString("GNUNETD",
			       "APPLICATIONS");
  if (dso == NULL) {
    LOG(LOG_WARNING,
	_("No applications defined in configuration!\n"));
    return;
  }
  next = dso;
  do {
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
      LOG(LOG_MESSAGE,
	  _("Updating data for module `%s'\n"),
	  pos);
      if (OK != updateModule(pos))
	LOG(LOG_ERROR,
	    _("Failed to update data for module `%s'\n"),
	    pos);
    }
  } while (next != NULL);
  FREE(dso);
}

static void doGet(char * get) {
  char * sec;
  char * ent;
  char * val;

  sec = get;
  ent = get;
  while ( ( (*ent) != ':') &&
	  ( (*ent) != '\0') )
    ent++;
  if (*ent == ':') {
    *ent = '\0';
    ent++;
  }
  if (0 == GC_get_configuration_value_string(cfg,
					     sec,
					     ent,
					     NULL,
					     &val)) {
    printf("%s\n",
	   val);
    FREE(val);
  }
  FREE(get);
}

static void work() {
  int i;
  struct CronManager * cron;

  uapi.updateModule   = &updateModule;
  uapi.requestService = &requestService;
  uapi.releaseService = &releaseService;

  cron = cron_create(ectx);
  initCore(ectx, cfg, cron, NULL);

  /* force update of common modules (used by core) */
  updateModule("transport");
  updateModule("identity");
  updateModule("session");
  updateModule("fragmentation");
  updateModule("topology");
  /* then update active application modules */
  updateApplicationModules();
  /* store information about update */
  upToDate();

  for (i=0;i<processedCount;i++)
    FREE(processed[i]);
  if (be_verbose)
    printf(_("Updated data for %d applications.\n"),
	   processedCount);
  GROW(processed, processedCount, 0);
  doneCore();
  cron_destroy(cron);
}


/**
 * All gnunet-update command line options
 */
static struct CommandLineOption gnunetupdateOptions[] = {
  COMMAND_LINE_OPTION_CFG_FILE, /* -c */
  { 'g', "get", "", 
    gettext_noop("ping peers from HOSTLISTURL that match transports"), 
    0, &gnunet_getopt_configure_set_option, "GNUNET-UPDATE:GET" },
  COMMAND_LINE_OPTION_HELP(gettext_noop("Updates GNUnet datastructures after version change.")), /* -h */
  COMMAND_LINE_OPTION_HOSTNAME, /* -H */
  COMMAND_LINE_OPTION_LOGGING, /* -L */
  { 'u', "user", "LOGIN",
    gettext_noop("run as user LOGIN"),
    1, &gnunet_getopt_configure_set_option, "GNUNETD:USER" },	
  { 'U', "client", NULL,
    gettext_noop("run in client mode (for getting client configuration values)"),
    0, &gnunet_getopt_configure_set_option, "GNUNETD:_MAGIC_=NO" },	
  COMMAND_LINE_OPTION_VERSION(PACKAGE_VERSION), /* -v */
  COMMAND_LINE_OPTION_VERBOSE,
  COMMAND_LINE_OPTION_END,
};


int main(int argc,
	 const char * argv[]) {
  char * get;
  char * user;

  ectx = GE_create_context_stderr(NO, 
				  GE_WARNING | GE_ERROR | GE_FATAL |
				  GE_USER | GE_ADMIN | GE_DEVELOPER |
				  GE_IMMEDIATE | GE_BULK);
  GE_setDefaultContext(ectx);
  cfg = GC_create_C_impl();
  GE_ASSERT(ectx, cfg != NULL);

  if (-1 == gnunet_parse_options("gnunet-update",
				 ectx,
				 cfg,
				 gnunetupdateOptions,
				 (unsigned int) argc,
				 argv)) {
    GC_free(cfg);
    GE_free_context(ectx);
    return -1;  
  }
  if (OK != changeUser(ectx, cfg)) {
    GC_free(cfg);
    GE_free_context(ectx);
    return -1;
  }
  if (0 == GC_get_configuration_value_string(cfg,
					     "GNUNET-UPDATE",
					     "GET",
					     NULL,
					     &get)) {
    doGet(get);  
    FREE(get);
  } else {
    work();
  }
  GC_free(cfg);
  GE_free_context(ectx);

  return 0;
}

/* end of gnunet-update */
