/*
     This file is part of GNUnet.
     (C) 2003 Christian Grothoff (and other contributing authors)

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
 * Tool to delete files that were indexed with gnunet-insert.
 *
 * @author Christian Grothoff
 * @file applications/afs/tools/gnunet-delete.c 
 */

#include "gnunet_afs_esed2.h"
#include "platform.h"

/**
 * Print progess message.
 */
static void printstatus(ProgressStats * stats,
			void * verboselevel) {
  if (*(int*)verboselevel == YES) {
    printf(_("%8u of %8u bytes deleted."),
	   (unsigned int) stats->progress,
	   (unsigned int) stats->filesize);  
    printf("\r");
  }
}

/**
 * Prints the usage information for this command if the user errs.
 * Aborts the program.
 */
static void printhelp() {
  static Help help[] = {
    HELP_CONFIG,
    { 'f', "file", "NAME",
      gettext_noop("specify the file to delete from GNUnet (obligatory, file must exist)") } ,
    HELP_HELP,
    HELP_HOSTNAME,
    HELP_LOGLEVEL,
    HELP_VERSION,
    HELP_VERBOSE,
    HELP_END,
  };
  formatHelp("gnunet-delete [OPTIONS] -f FILENAME",
	     _("Remove file from GNUnet.  The specified file is not removed\n"
	       "from the filesystem but just from the local GNUnet datastore."),
	     help);
}

static int parseOptions(int argc,
			char ** argv) {
  int c;

  FREENONNULL(setConfigurationString("GNUNET-INSERT",
				     "INDEX-CONTENT",
				     "YES"));
  while (1) {
    int option_index=0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "file",          1, 0, 'f' },
      { "verbose",       0, 0, 'V' },
      { 0,0,0,0 }
    };    
    c = GNgetopt_long(argc,
		      argv, 
		      "vhdc:L:H:Vf:", 
		      long_options, 
		      &option_index);    
    if (c == -1) 
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'V':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "VERBOSE",
					 "YES"));
      break;
    case 'f': 
      FREENONNULL(setConfigurationString("GNUNET-DELETE",
					 "FILENAME",
					 GNoptarg));
      break;    
    case 'v': 
      printf("GNUnet v%s, gnunet-delete v%s\n",
	     VERSION, 
	     AFS_VERSION);
      return SYSERR;
    case 'h': 
      printhelp(); 
      return SYSERR;
    default: 
      LOG(LOG_FAILURE,
	  _("Use --help to get a list of options.\n"));
      return SYSERR;
    } /* end of parsing commandline */
  } /* while (1) */
  return OK;
}


/**
 * The main function to delete files from GNUnet.
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return 0 for ok, -1 on error
 */   
int main(int argc, char ** argv) {
  int beVerbose;
  GNUNET_TCP_SOCKET * sock;
  int ok;
  char * filename;
  
  if (SYSERR == initUtil(argc, argv, &parseOptions)) 
    return 0;
  beVerbose = testConfigurationString("GNUNET-INSERT",
				      "VERBOSE",
				      "YES");

  filename = getFileName("GNUNET-DELETE",
			 "FILENAME",
			 _("You must specify a filename (option -f)\n"));
  sock = getClientSocket();
  if (sock == NULL)
    errexit(_("Could not connect to gnunetd.\n"));
  ok = deleteFile(sock,
		  filename,
		  &printstatus,
		  &beVerbose);
  if (ok != OK) {
    LOG(LOG_DEBUG,
	"Error deleting file '%s'.\n",
	filename);
    printf(_("Error deleting file %s.\n"
	     "Probably a few blocks were already missing from the database.\n"),
	   filename);
  }
  releaseClientSocket(sock); 
  doneUtil();
  FREE(filename);
  if (ok == OK)
    return 0;
  else 
    return -1;
}  

/* end of gnunet-delete.c */
