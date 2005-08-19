/*
     This file is part of GNUnet.
     (C) 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/tools/gnunet-pseudonym.c
 * @brief create, list or delete pseudoynms
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_fsui_lib.h"

static void printhelp() {
  static Help help[] = {
    { 'a', "anonymity", "LEVEL",
      gettext_noop("set the desired LEVEL of sender-anonymity") },
    { 'A', "automate", NULL,
      gettext_noop("automate creation of a namespace by starting a collection") },
    HELP_CONFIG,
    { 'C', "create", "NICKNAME",
      gettext_noop("create a new pseudonym under the given NICKNAME") },
    { 'D', "delete", "NICKNAME",
      gettext_noop("delete the pseudonym with the given NICKNAME") },
    { 'E', "end", NULL,
      gettext_noop("end automated building of a namespace (ends collection)") },
    HELP_HELP,
    HELP_LOGLEVEL,
    { 'k', "keyword", "KEYWORD",
      gettext_noop("use the given keyword to advertise the namespace (use when creating a new pseudonym)") },
    { 'm', "mimetype", "MIMETYPE",
      gettext_noop("specify that the contents of the namespace are of the given MIMETYPE (use when creating a new pseudonym)") },
    { 'n', "no-advertisement", NULL,
      gettext_noop("do not generate an advertisement for this namespace (use when creating a new pseudonym)") },
    { 'q', "quiet", NULL,
      gettext_noop("do not list the pseudonyms from the pseudonym database") },
    { 'r', "realname", "NAME",
      gettext_noop("specify NAME to be the realname of the user controlling the namespace (use when creating a new pseudonym)") },
    { 'R', "root", "IDENTIFIER",
      gettext_noop("specify IDENTIFIER to be the address of the entrypoint to content in the namespace (use when creating a new pseudonym)") },
    { 's', "set-rating", "ID:VALUE",
      gettext_noop("set the rating of a namespace") },
    { 't', "text", "DESCRIPTION",
      gettext_noop("use DESCRIPTION to describe the content of the namespace (use when creating a new pseudonym)") },
    { 'u', "uri", "URI",
      gettext_noop("specify the given URI as an address that contains more information about the namespace (use when creating a new pseudonym)") },
    HELP_VERSION,
    HELP_END,
  };
  formatHelp("gnunet-pseudonym [OPTIONS]",
	     _("Create new pseudonyms, delete pseudonyms or list existing pseudonyms."),
	     help);
}

/**
 * Perform option parsing from the command line.
 */
static int parser(int argc,
	   char * argv[]) {
  int c;

  setConfigurationInt("FS",
		      "ANONYMITY-SEND",
		      1);
  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "anonymity",     1, 0, 'a' },
      { "automate", 0, 0, 'A' },
      { "create", 1, 0, 'C' },
      { "delete", 1, 0, 'D' },
      { "end", 0, 0, 'E' },
      { "keyword", 1, 0, 'k' },
      { "mimetype", 1, 0, 'm' },
      { "no-advertisement", 0, 0, 'n' },
      { "quiet", 0, 0, 'q' },
      { "realname", 1, 0, 'r' },
      { "root", 1, 0, 'R' },
      { "set-rating", 1, 0, 's' },
      { "text", 1, 0, 't' },
      { "uri", 1, 0, 'u' },
      { 0,0,0,0 }
    };

    c = GNgetopt_long(argc,
		      argv,
		      "a:Ac:C:D:Ehk:L:m:nqr:R:s:t:u:v",
		      long_options,
		      &option_index);

    if (c == -1)
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'a': {
      unsigned int receivePolicy;

      if (1 != sscanf(GNoptarg,
		      "%ud",
		      &receivePolicy)) {
        LOG(LOG_FAILURE,
	  _("You must pass a number to the `%s' option.\n"),
	    "-a");
        return -1;
      }
      setConfigurationInt("FS",
                          "ANONYMITY-SEND",
                          receivePolicy);
      break;
    }
    case 'A':
      FREENONNULL(setConfigurationString("PSEUDONYM",
					 "AUTOMATE",
					 "START"));
      break;
    case 'C':
      FREENONNULL(setConfigurationString("PSEUDONYM",
					 "CREATE",
					 GNoptarg));
      break;
    case 'D':
      FREENONNULL(setConfigurationString("PSEUDONYM",
					 "DELETE",
					 GNoptarg));
      break;
    case 'E':
      FREENONNULL(setConfigurationString("PSEUDONYM",
					 "AUTOMATE",
					 "STOP"));
      break;
    case 'k':
      /* TODO: support using -k multiple times! */
      FREENONNULL(setConfigurationString("PSEUDONYM",
					 "KEYWORD",
					 GNoptarg));
      break;
    case 'h':
      printhelp();
      return SYSERR;
    case 'm':
      FREENONNULL(setConfigurationString("PSEUDONYM",
					 "MIMETYPE",
					 GNoptarg));
      break;
    case 'n':
      FREENONNULL(setConfigurationString("PSEUDONYM",
					 "NO-ADVERTISEMENT",
					 "YES"));
      break;
    case 'q':
      FREENONNULL(setConfigurationString("PSEUDONYM",
					 "QUIET",
					 "YES"));
      break;
    case 'r':
      FREENONNULL(setConfigurationString("PSEUDONYM",
					 "REALNAME",
					 GNoptarg));
      break;
    case 'R': {
      EncName enc;
      HashCode512 hc;

      if (SYSERR == enc2hash(GNoptarg,
			     &hc))
	hash(GNoptarg,
	     strlen(GNoptarg),
	     &hc);
      hash2enc(&hc, &enc);
      FREENONNULL(setConfigurationString("PSEUDONYM",
					 "ROOT",
					 (char*)&enc));
      break;
    }
    case 's':
      FREENONNULL(setConfigurationString("PSEUDONYM",
					 "SET-RATING",
					 GNoptarg));
      break;
    case 't':
      FREENONNULL(setConfigurationString("PSEUDONYM",
					 "DESCRIPTION",
					 GNoptarg));
      break;
    case 'u':
      FREENONNULL(setConfigurationString("PSEUDONYM",
					 "URI",
					 GNoptarg));
      break;
    case 'v':
      printf("gnunet-pseudoynm v%s\n",
	     VERSION);
      return SYSERR;
    default:
      LOG(LOG_FAILURE,
	  _("Use --help to get a list of options.\n"));
      return SYSERR;
    } /* end of parsing commandline */
  }
  if (GNoptind < argc) {
    while (GNoptind < argc)
      LOG(LOG_WARNING,
	  _("Invalid argument: `%s'\n"), argv[GNoptind++]);
    LOG(LOG_FATAL,
	_("Invalid arguments. Exiting.\n"));
    return SYSERR;
  }
  return OK;
}

/**
 * Global context to use FSUI.
 */
static struct FSUI_Context * ctx;


static int itemPrinter(EXTRACTOR_KeywordType type,
		       const char * data,
		       void * closure) {
  printf("\t%20s: %s\n",
	 EXTRACTOR_getKeywordTypeAsString(type),
	 data);
  return OK;
}

static void printMeta(const struct ECRS_MetaData * meta) {
  ECRS_getMetaData(meta,
		   &itemPrinter,
		   NULL);
}

static int namespacePrinter(void * unused,
			    const char * namespaceName,
			    const HashCode512 * id,
			    const struct ECRS_MetaData * md,
			    int rating) {
  EncName enc;
  char * set;
  int cpos;

  set = getConfigurationString("PSEUDONYM",
			       "SET-RATING");
  hash2enc(id,
	   &enc);
  if (0 == strcmp(namespaceName, (char*)&enc))
    printf(_("Namespace `%s' has rating %d.\n"),
	   namespaceName,
	   rating);
  else
    printf(_("Namespace `%s' (%s) has rating %d.\n"),
	   namespaceName,
	   (char*) &enc,
	   rating);
  printMeta(md);

  if (set != NULL) {
    int delta;

    delta = 0;
    cpos = 0;
    while ( (set[cpos] != '\0') &&
	    (set[cpos] != ':') )
      cpos++;
    if ( ( ( ( (strlen((char*)&enc)+1 == cpos) &&
	       (0 == strncmp(set,
			     (char*)&enc,
			     cpos)) ) ) ||
	   ( (namespaceName != NULL) &&
	     (strlen(namespaceName) == cpos) &&
	     (0 == strncmp(set,
			   namespaceName,
			   cpos)) ) ) &&
	 (set[cpos] == ':') ) {
      delta = strtol(&set[cpos+1],
		     NULL, /* no error handling yet */
		     10);	
    }

    if (delta != 0) {
      rating = FSUI_rankNamespace(ctx,
				  namespaceName,
				  delta);
      printf(_("\tRating (after update): %d\n"),
	     rating);
    }
  }
  FREENONNULL(set);
  printf("\n");
  return OK;
}

static void eventCallback(void * unused,
			  const FSUI_Event * event) {
  /* we ignore all events */
}


int main(int argc, char *argv[]) {
  int cnt;
  char * pname;
  int success;
  char * description;
  char * realname;
  char * uri;
  char * mimetype;
  struct ECRS_MetaData * meta;
	
  /* startup */
  success = 0; /* no errors */
  if (OK != initUtil(argc, argv, &parser))
    return SYSERR;

  ctx = FSUI_start("gnunet-pseudonym",
		   NO,
		   &eventCallback,
		   NULL);

  /* stop collections */
  if (testConfigurationString("PSEUDONYM",
			      "AUTOMATE",
			      "STOP")) {
    if (OK == FSUI_stopCollection(ctx))
      printf(_("Collection stopped.\n"));
    else
      printf(_("Failed to stop collection (not active?).\n"));
  }

  /* delete pseudonyms */
  pname = getConfigurationString("PSEUDONYM",
				 "DELETE");
  if (pname != NULL) {
    if (OK == FSUI_deleteNamespace(pname)) {
      printf(_("Pseudonym `%s' deleted.\n"),
	     pname);
    } else {
      success += 2;
      printf(_("Error deleting pseudonym `%s' (does not exist?).\n"),
	     pname);
    }
    FREE(pname);
  }

  /* create MetaData */
  description = getConfigurationString("PSEUDONYM",
				       "DESCRIPTION");
  realname = getConfigurationString("PSEUDONYM",
				    "REALNAME");
  uri = getConfigurationString("PSEUDONYM",
			       "URI");
  mimetype = getConfigurationString("PSEUDONYM",
				    "MIMETYPE");
  meta = ECRS_createMetaData();
  if (uri != NULL)
    ECRS_addToMetaData(meta,
		       EXTRACTOR_RELATION,
		       uri);
  if (realname != NULL)
    ECRS_addToMetaData(meta,
		       EXTRACTOR_PRODUCER,
		       realname);
  if (description != NULL)
    ECRS_addToMetaData(meta,
		       EXTRACTOR_DESCRIPTION,
		       description);
  if (mimetype != NULL)
    ECRS_addToMetaData(meta,
		       EXTRACTOR_MIMETYPE,
		       mimetype);
  FREENONNULL(description);
  FREENONNULL(realname);
  FREENONNULL(uri);
  FREENONNULL(mimetype);

  /* create collections / namespace */
  pname = getConfigurationString("PSEUDONYM",
				 "CREATE");
  if (pname != NULL) {
    if (testConfigurationString("PSEUDONYM",
				"AUTOMATE",
				"START")) {
      ECRS_addToMetaData(meta,
			 EXTRACTOR_OWNER,
			 pname);
      if (OK == FSUI_startCollection(ctx,
				     getConfigurationInt("FS",
							 "ANONYMITY-SEND"),
				     ECRS_SBLOCK_UPDATE_SPORADIC, /* FIXME: allow other update policies */
				     pname,
				     meta)) {
	printf(_("Started collection `%s'.\n"),
	       pname);
      } else {
	printf(_("Failed to start collection.\n"));
	success++;
      }

      ECRS_delFromMetaData(meta,
			   EXTRACTOR_OWNER,
			   pname);
    } else { /* no collection */
      HashCode512 rootEntry;
      char * root;
      char * keyword;
      struct ECRS_URI * advertisement;
      struct ECRS_URI * rootURI;

      root = getConfigurationString("PSEUDONYM",
				    "ROOT");
      if (root == NULL) {
	memset(&rootEntry, 0, sizeof(HashCode512));
      } else {
	enc2hash(root, &rootEntry);
	FREE(root);
      }

      keyword = getConfigurationString("PSEUDONYM",
				       "KEYWORD");
      if (keyword == NULL)
	keyword = STRDUP("namespace"); /* default keyword */

      if (testConfigurationString("PSEUDONYM",
				  "NO-ADVERTISEMENT",
				  "YES")) {
	advertisement = NULL;
      } else {
	advertisement = FSUI_parseCharKeywordURI(keyword);
      }
      FREE(keyword);
      rootURI = FSUI_createNamespace(ctx,
				     getConfigurationInt("FS",
							 "ANONYMITY-SEND"),
				     pname,
				     meta,
				     advertisement,
				     &rootEntry);
      if (rootURI == NULL) {
	printf(_("Could not create namespace `%s' (exists?).\n"),
	       pname);
	success += 1;
      } else {
	root = ECRS_uriToString(rootURI);
	printf(_("Namespace `%s' created (root: %s).\n"),
	       pname,
	       root);
	FREE(root);
	ECRS_freeUri(rootURI);
      }
      if (NULL != advertisement)
	ECRS_freeUri(advertisement);
    }
    FREE(pname);
    pname = NULL;
  }
  ECRS_freeMetaData(meta);

  if (testConfigurationString("PSEUDONYM",
			      "QUIET",
			      "YES"))
    return success; /* do not print! */

  /* print information about pseudonyms */

  cnt = FSUI_listNamespaces(ctx,
			    NO,
			    &namespacePrinter,
			    NULL);
  if (cnt == -1)
    printf(_("Could not access namespace information.\n"));

  FSUI_stop(ctx);
  doneUtil();
  return success;
}

/* end of gnunet-pseudonym.c */
