/*
     This file is part of GNUnet.
     (C) 2004 Christian Grothoff (and other contributing authors)

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
#include "gnunet_core.h"
#include "core.h"
#include "version.h"

/**
 * We may want to change this at some point into
 * something like libgnunet_update if we want to
 * separate the update code from the codebase
 * used in normal operation -- but currently I
 * see no need / use for that.
 */
#define DSO_PREFIX "libgnunet"

/**
 * Print a list of the options we offer.
 */
static void printhelp() {
  static Help help[] = {
    HELP_CONFIG,
    { 'g', "get", "SECTION:ENTRY",
      gettext_noop("print a value from the configuration file to stdout") },
    HELP_HELP,
    HELP_LOGLEVEL,
    { 'u', "user", NULL,
      gettext_noop("run in user mode (for getting user configuration values)") },
    HELP_VERSION,
    HELP_VERBOSE,
    HELP_END,
  };
  formatHelp("gnunet-update [OPTIONS]",
	     _("Updates GNUnet datastructures after version change."),
	     help);
}

static int be_verbose = NO;

/**
 * Perform option parsing from the command line.
 */
static int parseCommandLine(int argc,
			    char * argv[]) {
  int c;
  int user = NO;
  int get = NO;

  /* set the 'magic' code that indicates that
     this process is 'gnunetd' (and not any of
     the user-tools).  Needed such that we use
     the right configuration file... */
  FREENONNULL(setConfigurationString("GNUNETD",
				     "_MAGIC_",
				     "YES"));
  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "get", 1, 0, 'g' },
      { "user", 0, 0, 'u' },
      { "verbose", 0, 0, 'V' },
      { 0,0,0,0 }
    };

    c = GNgetopt_long(argc,
		      argv,
		      "vhdc:g:VL:",
		      long_options,
		      &option_index);
    if (c == -1)
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'g':
      FREENONNULL(setConfigurationString("GNUNET-UPDATE",
					 "GET",
					 GNoptarg));
      get = YES;
     break;
    case 'L':
      FREENONNULL(setConfigurationString("GNUNETD",
					 "LOGLEVEL",
					 GNoptarg));
     break;
    case 'h':
      printhelp();
      return SYSERR;
    case 'u':
      FREENONNULL(setConfigurationString("GNUNETD",
					 "_MAGIC_",
					 "NO"));
      user = YES;
      break;
    case 'v':
      printf("GNUnet v%s, gnunet-update 0.0.1\n",
	     VERSION);
      return SYSERR;
    case 'V':
      be_verbose = YES;
      break;
    default:
      printf(_("Use --help to get a list of options.\n"));
      return SYSERR;
    } /* end of parsing commandline */
  }
  if (user && (! get)) {
    printf(_("Option `%s' makes no sense without option `%s'."),
	   "-u", "-g");
    return SYSERR;
  }
  if (GNoptind < argc) {
    printf(_("Invalid arguments: "));
    while (GNoptind < argc)
      printf("%s ", argv[GNoptind++]);
    printf(_("\nExiting.\n"));
    return SYSERR;
  }
  if (get == NO) {
    /* if we do not run in 'get' mode,
       make sure we send error messages
       to the console... */
    FREENONNULL(setConfigurationString("GNUNETD",
				       "LOGFILE",
				       NULL));
  }
  return OK;
}

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
  val = getConfigurationString(sec, ent);
  if (val == NULL)
    printf("%u\n",
	   getConfigurationInt(sec, ent));
  else {
    printf("%s\n",
	   val);
    FREE(val);
  }
  FREE(get);
}

static void work() {
  int i;
  uapi.updateModule = &updateModule;
  uapi.requestService = &requestService;
  uapi.releaseService = &releaseService;

  initCore();

  /* force update of common modules
     (used by core) */
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
}

int main(int argc,
	 char * argv[]) {
  char * get;

  if (SYSERR == initUtil(argc, argv, &parseCommandLine))
    return 0;
  get = getConfigurationString("GNUNET-UPDATE",
			       "GET");
  if (get != NULL)
    doGet(get);
  else
    work();
  doneUtil();
  return 0;
}

/* end of gnunet-update */
