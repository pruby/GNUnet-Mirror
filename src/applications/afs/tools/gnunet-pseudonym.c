/*
     This file is part of GNUnet.
     (C) 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/tools/gnunet-pseudonym.c
 * @brief create, list or delete pseudoynms
 * @author Christian Grothoff
 */

#include "gnunet_afs_esed2.h"
#include "platform.h"

static void printhelp() {
  static Help help[] = {
    { 'a', "automate", NULL,
      gettext_noop("automate creation of a namespace by starting a collection") },
    HELP_CONFIG,
    { 'C', "create", "NICKNAME",
      gettext_noop("create a new pseudonym under the given NICKNAME (with the given password if specified)") },
    { 'D', "delete", "NICKNAME",
      gettext_noop("delete the pseudonym with the given NICKNAME") },
    { 'e', "email", "EMAIL",
      gettext_noop("specify the given EMAIL address as the contact address for the pseudonym (use when creating a new pseudonym)") },
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
    { 'p', "password", "PASS",
      gettext_noop("use the given password to encrypt or decrypt pseudonyms in the pseudonym database") },
    { 'q', "quiet", NULL,
      gettext_noop("do not list the pseudonyms from the pseudonym database") },
    { 'r', "realname", "NAME",
      gettext_noop("specify NAME to be the realname of the user controlling the namespace (use when creating a new pseudonym)") },
    { 'R', "root", "IDENTIFIER",
      gettext_noop("specify IDENTIFIER to be the address of the entrypoint to content in the namespace (use when creating a new pseudonym)") },
    { 's', "set-rating", "ID:VALUE",
      gettext_noop("") },
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

  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "automate", 0, 0, 'a' },
      { "create", 1, 0, 'C' },
      { "delete", 1, 0, 'D' },
      { "email", 1, 0, 'e'  },      
      { "end", 0, 0, 'E' },
      { "keyword", 1, 0, 'k' },
      { "mimetype", 1, 0, 'm' },     
      { "no-advertisement", 0, 0, 'n' },
      { "password", 1, 0, 'p' },
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
		      "ac:C:D:e:Ehk:L:m:np:qr:R:s:t:u:v", 
		      long_options, 
		      &option_index);
    
    if (c == -1) 
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'a':
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
    case 'e':
      FREENONNULL(setConfigurationString("PSEUDONYM",
					 "EMAIL",
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
    case 'p':
      FREENONNULL(setConfigurationString("PSEUDONYM",
					 "PASSWORD",
					 GNoptarg));
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
      HashCode160 hc;

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
	  _("Invalid argument: '%s'\n"), argv[GNoptind++]);
    LOG(LOG_FATAL,
	_("Invalid arguments. Exiting.\n"));
    return SYSERR;
  }
  return OK;
}


int main(int argc, char *argv[]) {
  char ** list;
  int i;
  int cnt;
  int cpos;
  char * pass;
  char * pname;
  int success;
  PrivateKey hk;
  NBlock * info;
  HashCode160 k;
  NBlock out;
	
  success = 0; /* no errors */
  if (OK != initUtil(argc, argv, &parser))
    return SYSERR;

  if (testConfigurationString("PSEUDONYM",
			      "AUTOMATE",
			      "STOP")) {
    printf(_("Collection stopped.\n"));
    stopCollection();
  }


  pname = getConfigurationString("PSEUDONYM",
				 "DELETE");
  if (pname != NULL) {
    if (OK == deletePseudonym(pname)) {
      printf(_("Pseudonym '%s' deleted.\n"),
	     pname);
    } else {
      success += 2;
      printf(_("Error deleting pseudonym '%s' (does not exist?).\n"),
	     pname);
    }
    FREE(pname);
  }

  pass = getConfigurationString("PSEUDONYM",
				"PASSWORD");
  pname = getConfigurationString("PSEUDONYM",
				 "CREATE");
  if (pname != NULL) {
    if (testConfigurationString("PSEUDONYM",
				"AUTOMATE",
				"START")) {
      char * nickname;
      char * description;
      char * realname;
      char * uri;
      char * contact;

      printf(_("Starting collection.\n"));
      hk = NULL;
      nickname = STRDUP(pname);
      description = getConfigurationString("PSEUDONYM",
					   "DESCRIPTION");
      realname = getConfigurationString("PSEUDONYM",
					"REALNAME");
      uri = getConfigurationString("PSEUDONYM",
				   "URI");
      contact = getConfigurationString("PSEUDONYM",
				       "EMAIL");
      startCollection(nickname,
		      description,
		      realname,
		      uri,
		      contact);
      FREENONNULL(nickname);
      FREENONNULL(description);
      FREENONNULL(realname);
      FREENONNULL(uri);
      FREENONNULL(contact);      
    } else {
      if ( (pass == NULL) || (pass[0]=='\n') )
	LOG(LOG_WARNING, 
	    _("No password supplied.\n"));
      
      hk = createPseudonym(pname,
			   pass);
      if (hk == NULL) {
	printf(_("Could not create pseudonym '%s' (exists?).\n"),
	       pname);
	success += 1;
      } else {
	printf(_("Pseudonym '%s' created.\n"),
	       pname);
      }
    }
    
    if ( (hk != NULL) &&
	 (! testConfigurationString("PSEUDONYM",
				    "NO-ADVERTISEMENT",
				    "YES")) ) {
      NBlock * nblock;
      char * nickname;
      char * description;
      char * realname;
      char * mimetype;
      char * uri;
      char * contact;
      char * root;
      char * summary;
      char * keyword;
      HashCode160 rootEntry;
      GNUNET_TCP_SOCKET * sock;
      
      nickname = getConfigurationString("PSEUDONYM",
					"CREATE");
      description = getConfigurationString("PSEUDONYM",
					   "DESCRIPTION");
      realname = getConfigurationString("PSEUDONYM",
					"REALNAME");
      mimetype = getConfigurationString("PSEUDONYM",
					"MIMETYPE");
      uri = getConfigurationString("PSEUDONYM",
				   "URI");
      contact = getConfigurationString("PSEUDONYM",
				       "EMAIL");
      root = getConfigurationString("PSEUDONYM",
				    "ROOT");
      if (root == NULL)
	memset(&rootEntry, 0, sizeof(HashCode160));
      else
	enc2hash(root, &rootEntry);
      
      nblock = buildNBlock(hk,
			   nickname,
			   description,
			   realname,
			   mimetype,
			   uri,
			   contact,
			   &rootEntry);
      FREENONNULL(nickname);
      FREENONNULL(description);
      FREENONNULL(realname);
      FREENONNULL(mimetype);
      FREENONNULL(uri);
      FREENONNULL(contact);
      FREENONNULL(root);	
      GNUNET_ASSERT(nblock != NULL); /* sign failed!? */
      
      decryptNBlock(nblock);
      addNamespace(nblock);
      
      summary = rootNodeToString((const RootNode*) nblock);
      printf(_("Advertising namespace with description:\n%s\n"),
	     summary);
      FREE(summary);
      
      /* now what? 
	 a) addNamespaceMetadata(nblock) [ store locally ]
	 b) encrypt with key and send to gnunetd!
      */
      sock = getClientSocket();
      if (sock == NULL)
	errexit(_("Could not connect to gnunetd.\n"));
      
      keyword = getConfigurationString("PSEUDONYM",
				       "KEYWORD");
      if (keyword == NULL)
	keyword = STRDUP("namespace"); /* default keyword */
      if (OK != insertRootWithKeyword(sock,
				      (const RootNode*) nblock,
				      keyword,
				      getConfigurationInt("GNUNET-INSERT",
							  "CONTENT-PRIORITY")))
	printf(_("Error inserting NBlock under keyword '%s'. "
		 "Is gnunetd running and space available?\n"),
	       keyword);
      FREE(keyword);	
      
      /* also publish nblock as SBlock in namespace! */
      
      
      memset(&k,0, sizeof(HashCode160));	
      encryptSBlock(&k, 
		    (const SBlock*) nblock,
		    (SBlock*) &out);
      if (OK != insertSBlock(sock,
			     (const SBlock *) &out)) 
	printf(_("Error inserting NBlock into namespace. "
		 "Is gnunetd running and space available?\n"));
      releaseClientSocket(sock);
      FREE(nblock);
    }
    if (hk != NULL)
      freePrivateKey(hk);  
    FREE(pname);
  }

  if (testConfigurationString("PSEUDONYM",
			      "QUIET",
			      "YES"))
    return success; /* do not print! */

  /* print information about local pseudonyms */
  list = NULL;
  cnt = listPseudonyms(&list);
  if (cnt == -1) 
    printf(_("Could not access pseudonym directory.\n"));  
  for (i=0;i<cnt;i++) {
    const char * id;
    EncName enc;
    
    PrivateKey p = readPseudonym(list[i],
			      pass);
    if (p != NULL) {
      PublicKey pk;
      HashCode160 hc;
      getPublicKey(p, &pk);
      hash(&pk, sizeof(PublicKey), &hc);
      hash2enc(&hc, &enc);
      id = (char*)&enc;
    } else
      id = _("not decrypted");
    printf(_("Pseudonym with nickname '%s' has ID '%s'.\n"),
	   list[i],
	   id);
    FREE(list[i]);
  }
  FREENONNULL(list);

  /* now print information about namespaces (local and remote) */
  info = NULL;
  cnt = listNamespaces(&info);
  if (cnt == -1) 
    printf(_("Did not find any meta-information about namespaces.\n"));  

  pname = getConfigurationString("PSEUDONYM",
				 "SET-RATING");
  if (pname != NULL) {
    if (NULL == strstr(pname, ":")) {
      fprintf(stderr,
	      _("Invalid argument '%s' for option '%s', needs a '%s'.\n"),
	      pname, "-s", ":");
      FREE(pname);
      pname = NULL;
    } else {
      cpos = (strstr(pname, ":") - pname) + 1;
    }
  }
  for (i=0;i<cnt;i++) {
    int delta;

    printNBlock(stdout, &info[i]);  
    delta = 0;
    if (pname != NULL) {
      char * iname = getUniqueNickname(&info[i].namespace);
      if ( (strlen(iname)+1 == cpos) &&
	   (0 == strncmp(pname,
			 iname,
			 cnt)) ) {
	delta = strtol(&pname[cpos],
		       NULL, /* no error handling yet */
		       10);	      
      }
      FREE(iname);
    }
    if (delta != 0) {
      fprintf(stdout, 
	      _("\tRating (before): %d\n"), 
	      evaluateNamespace(&info[i].namespace,
				0));
      evaluateNamespace(&info[i].namespace,
			delta);
      fprintf(stdout, 
	      _("\tRating (after): %d\n"), 
	      evaluateNamespace(&info[i].namespace,
				0));
    } else {
      fprintf(stdout, 
	      _("\tRating: %d\n"), 
	      evaluateNamespace(&info[i].namespace,
				0));
    }
  }
  FREENONNULL(pname);
  FREENONNULL(info);

  doneUtil();
  return success;
}

/* end of gnunet-pseudonym.c */
