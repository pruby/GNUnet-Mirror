/*
     This file is part of GNUnet.
     (C) 2002, 2003 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/tools/gnunet-directory.c
 * @brief tool to list the entries stored in the database holding files for building directories,
 *        to delete all of these entries and to display the contents of
 *        directories.
 * @author Christian Grothoff
 */

#include "gnunet_afs_esed2.h"
#include "platform.h"
  
static unsigned int listMask = 0;
static unsigned int killMask = 0;
static char ** filenames;
static int filenamescnt;


static void printNode(const RootNode * root,
		      void * unused) {
  char * string;

  string = rootNodeToString(root);
  printf("%s\n", string);
  FREE(string);
}

static void printDirectory(char * filename) {
  GNUnetDirectory * dir;
  unsigned int i;

  filename = expandFileName(filename);
  printf(_("==> Directory '%s':\n"),
	 filename);
  dir = readGNUnetDirectory(filename);
  if (dir == NULL) { 
    printf(_("No such file or invalid format for GNUnet directory.\n"));
    return;
  }
  dir->description[MAX_DESC_LEN-1] = '\0';
  printf("%s\n",
	 dir->description);
  for (i=0;i<ntohl(dir->number_of_files);i++) {
    printf("%u: ", i);
    printNode(&((GNUnetDirectory_GENERIC*)dir)->contents[i], NULL);
  }     
  printf("\n");
  FREE(dir);
  FREE(filename);
}

/**
 * Print a list of the options we offer.
 */
static void printhelp() {
  static Help help[] = {
    { 'a', "list-all", NULL,
      gettext_noop("list all entries from the directory database") },
    { 'A', "kill-all", NULL,
      gettext_noop("remove all entries from the directory database") },    
    HELP_CONFIG,
    HELP_HELP,
    { 'i', "list-insert", NULL,
      gettext_noop("list all insert entries from the directory database") },
    { 'I', "kill-insert", NULL,
      gettext_noop("delete all insert entries from the directory database") },
    HELP_LOGLEVEL,
    { 'n', "list-namespace", NULL,
      gettext_noop("list all namespace entries from the directory database") },
    { 'N', "kill-namespace", NULL,
      gettext_noop("delete all namespace entries from the directory database") },
    { 's', "list-search", NULL,
      gettext_noop("list all search result entries from the directory database") },
    { 'S', "kill-search", NULL,
      gettext_noop("delete all search result entries from the directory database") },
    HELP_VERSION,
    { 'x', "list-directory", NULL,
      gettext_noop("list all directory entries from the directory database") },
    { 'X', "kill-directory", NULL,
      gettext_noop("remove all directory entries from the directory database") },
    HELP_END,
  };
  formatHelp("gnunet-directory [OPTIONS] [FILENAMES]",
	     _("Perform directory related operations."),
	     help);
}

/**
 * Perform option parsing from the command line. 
 */
static int parseCommandLine(int argc, 
			    char * argv[]) {
  int c;

  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "list-search",    0, 0, 's' },
      { "list-insert",    0, 0, 'i' },
      { "list-directory",    0, 0, 'x' },
      { "list-namespace",    0, 0, 'n' },
      { "kill-search",    0, 0, 'S' },
      { "kill-insert",    0, 0, 'I' },
      { "kill-directory",    0, 0, 'X' },
      { "kill-namespace",    0, 0, 'N' },
      { "list-all",    0, 0, 'a' },
      { "kill-all",    0, 0, 'A' },
      { 0,0,0,0 }
    };
    
    c = GNgetopt_long(argc,
		      argv, 
		      "vhdc:L:sixanSIXAN", 
		      long_options, 
		      &option_index);    
    if (c == -1) 
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;    
    switch(c) {
    case 'a':
      listMask = DIR_CONTEXT_ALL;
      break;
    case 's':
      listMask = DIR_CONTEXT_SEARCH;
      break;
    case 'i':
      listMask = DIR_CONTEXT_INSERT;
      break;
    case 'n':
      listMask = DIR_CONTEXT_INSERT_SB;
      break;
    case 'x':
      listMask = DIR_CONTEXT_DIRECTORY;
      break;
    case 'A':
      killMask = DIR_CONTEXT_ALL;
      break;
    case 'S':
      killMask = DIR_CONTEXT_SEARCH;
      break;
    case 'I':
      killMask = DIR_CONTEXT_INSERT;
      break;
    case 'N':
      killMask = DIR_CONTEXT_INSERT_SB;
      break;
    case 'X':
      killMask = DIR_CONTEXT_DIRECTORY;
      break;
    case 'v': 
      printf("GNUnet v%s, gnunet-directory v%s\n",
	     VERSION, 
	     AFS_VERSION);
      return SYSERR;
    case 'h': 
      printhelp(); 
      return SYSERR;
    default:
      printf(_("Use --help to get a list of options.\n"));
      return SYSERR;
    } /* end of parsing commandline */
  }
  filenames = &argv[GNoptind];
  filenamescnt = argc - GNoptind;
  return OK;
}

int main(int argc, 
	 char * argv[]) {
  int i;
  if (SYSERR == initUtil(argc, argv, &parseCommandLine))
    return 0;

  if (listMask != 0)
    printf(_("Listed %d matching entries.\n"),
	   iterateDirectoryDatabase(listMask,
				    &printNode,
				    NULL));
  if (killMask != 0)
    emptyDirectoryDatabase(killMask);  
  for (i=0;i<filenamescnt;i++)
    printDirectory(filenames[i]);
 
  doneUtil();
  return 0;
}

/* end of gnunet-directory.c */
