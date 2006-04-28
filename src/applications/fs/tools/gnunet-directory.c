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
 * @file applications/fs/tools/gnunet-directory.c
 * @brief tool to list the entries stored in the database holding
 *        files for building directories, to delete all of these
 *        entries and to display the contents of  directories.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_fsui_lib.h"

static char ** filenames;
static int filenamescnt;

static int do_list;
static int do_kill;
static int do_track;

static int itemPrinter(EXTRACTOR_KeywordType type,
		       const char * data,
		       void * closure) {
  printf("\t%20s: %s\n",
	 dgettext("libextractor", EXTRACTOR_getKeywordTypeAsString(type)),
	 data);
  return OK;
}

static void printMeta(const struct ECRS_MetaData * meta) {
  ECRS_getMetaData(meta,
		   &itemPrinter,
		   NULL);
}

static int printNode(const ECRS_FileInfo * fi,
		     const HashCode512 * key,
		     int isRoot,
		     void * unused) {
  char * string;

  string = ECRS_uriToString(fi->uri);
  printf("%s:\n", string);
  FREE(string);
  printMeta(fi->meta);
  return OK;
}

static void printDirectory(const char * filename) {
  unsigned long long len;
  struct ECRS_MetaData * md;
  char * data;
  int ret;
  char * name;
  int fd;

  name = expandFileName(filename);
  printf(_("==> Directory `%s':\n"),
	 name);
  if ( (OK != getFileSize(name,
			  &len)) ||
       (len == 0) ) {
    printf(_("=\tError reading directory.\n"));
    return;
  }
  md = NULL;
  fd = fileopen(name,
		O_LARGEFILE | O_RDONLY);
  if (fd == -1) {
    LOG_FILE_STRERROR(LOG_ERROR, "open", name);
    ret = -1;
  } else {
    data = MMAP(NULL,
		len,
		PROT_READ,
		MAP_SHARED,
		fd,
		0);
    if (data == MAP_FAILED) {
      LOG_FILE_STRERROR(LOG_ERROR, "mmap", name);
      ret = -1;
    } else {
      ret = ECRS_listDirectory(data,
			       len,
			       &md,
			       &printNode,
			       NULL);
      MUNMAP(data, len);
    }
    closefile(fd);
  }
  if (ret == -1)
    printf(_("File format error (not a GNUnet directory?)\n"));
  else
    printf(_("%d files found in directory.\n"),
	   ret);
  if (md != NULL) {
    printMeta(md);
    ECRS_freeMetaData(md);
  }
  printf("\n");
  FREE(name);
}

/**
 * Print a list of the options we offer.
 */
static void printhelp() {
  static Help help[] = {
    HELP_CONFIG,
    HELP_HELP,
    { 'k', "kill", NULL,
      gettext_noop("remove all entries from the directory database and stop tracking URIs") },
    { 'l', "list", NULL,
      gettext_noop("list entries from the directory database") },
    HELP_LOGLEVEL,
    { 't', "track", NULL,
      gettext_noop("start tracking entries for the directory database") },
    HELP_VERSION,
    HELP_END,
  };
  formatHelp(_("gnunet-directory [OPTIONS] [FILENAMES]"),
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
      { "kill",    0, 0, 'k' },
      { "list",    0, 0, 'l' },
      { "track",   0, 0, 't' },
      { 0,0,0,0 }
    };

    c = GNgetopt_long(argc,
		      argv,
		      "c:hklL:tv",
		      long_options,
		      &option_index);
    if (c == -1)
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'h':
      printhelp();
      return SYSERR;
    case 'k':
      do_kill = YES;
      break;
    case 'l':
      do_list = YES;
      break;
    case 't':
      do_track = YES;
      break;
    case 'v':
      printf("GNUnet v%s, gnunet-directory v%s\n",
	     VERSION,
	     AFS_VERSION);
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

  if (do_list)
    printf(_("Listed %d matching entries.\n"),
	   FSUI_listURIs(&printNode,
			 NULL));
  if (do_kill) {
    FSUI_trackURIS(NO);
    FSUI_clearTrackedURIS();
  }
  if (do_track)
    FSUI_trackURIS(YES);

  for (i=0;i<filenamescnt;i++)
    printDirectory(filenames[i]);

  doneUtil();
  return 0;
}

/* end of gnunet-directory.c */
