/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/tools/gnunet-download.c 
 * @brief Main function to download files from GNUnet.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_fsui_lib.h"

/**
 * Prints the usage information for this command if the user errs.
 * Aborts the program.
 */
static void printhelp() {
  static Help help[] = {
    { 'a', "anonymity", gettext_noop("LEVEL"),
      gettext_noop("set the desired LEVEL of receiver-anonymity") },
    HELP_CONFIG,
    HELP_HELP,
    HELP_HOSTNAME,
    HELP_LOGLEVEL,
    { 'o', "output", gettext_noop("FILENAME"),
      gettext_noop("write the file to FILENAME") },
    { 'R', "recursive", NULL,
      gettext_noop("download a GNUnet directory recursively") },
    HELP_VERSION,
    HELP_VERBOSE,
    HELP_END,
  };
  formatHelp("gnunet-download [OPTIONS] GNUNET-URI",
	     _("Download files from GNUnet."),
	     help);
}

/**
 * ParseOptions for gnunet-download.
 * @return SYSERR to abort afterwards, OK to continue
 */
static int parseOptions(int argc,
			char ** argv) {
  int c;  

  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "anonymity", 1, 0, 'a' }, 
      { "output",    1, 0, 'o' },
      { "recursive", 0, 0, 'R' },
      { "verbose",   0, 0, 'V' },
      { 0,0,0,0 }
    };    
    c = GNgetopt_long(argc,
		      argv, 
		      "a:cdh:H:L:o:RvV", 
		      long_options, 
		      &option_index);    
    if (c == -1) 
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'a': {
      unsigned int receivePolicy;
      
      if (1 != sscanf(GNoptarg, "%ud", &receivePolicy)) {
        LOG(LOG_FAILURE,
	    _("You must pass a number to the '%s' option.\n"),
	    "-a");
	return -1;
      }
      setConfigurationInt("AFS",
      			  "ANONYMITY-RECEIVE",
			  receivePolicy);
      break;
    }
    case 'h': 
      printhelp(); 
      return SYSERR;
    case 'o':
      FREENONNULL(setConfigurationString("GNUNET-DOWNLOAD",
					 "FILENAME",
					 GNoptarg));
      break;
    case 'R': 
      FREENONNULL(setConfigurationString("GNUNET-DOWNLOAD",
					 "RECURSIVE",
					 "YES"));
      break;
    case 'v': 
      printf("GNUnet v%s, gnunet-download v%s\n",
	     VERSION,
	     AFS_VERSION);
      return SYSERR;
    case 'V':
      FREENONNULL(setConfigurationString("GNUNET-DOWNLOAD",
					 "VERBOSE",
					 "YES"));
      break;
    default: 
      LOG(LOG_FAILURE,
	  _("Use --help to get a list of options.\n"));
      return SYSERR;
    } /* end of parsing commandline */
  } /* while (1) */
  if (argc - GNoptind != 1) {
    LOG(LOG_WARNING, 
	_("Not enough arguments. "
	  "You must specify a GNUnet AFS URI\n"));
    printhelp();
    return SYSERR;
  }
  FREENONNULL(setConfigurationString("GNUNET-DOWNLOAD",
				     "URI",
				     argv[GNoptind++]));
  return OK;
}

/**
 * This method is called whenever data is received.
 * The current incarnation just ensures that the main
 * method exits once the download is complete.
 */
static void progressModel(void * unused,
			  const FSUI_Event * event) {
  switch (event->type) {
  case download_progress:
    if (YES == testConfigurationString("GNUNET-DOWNLOAD",
				       "VERBOSE",
				       "YES")) {
#if 0
      printf(_("Download at %16llu out of %16llu bytes (%8.3f kbps)"),
  	     (unsigned int) stats->progress, 
	     (unsigned int) stats->filesize,
	     (stats->progress/1024.0) / 
	     (((double)(cronTime(NULL)-(data->startTime-1))) / (double)cronSECONDS) );
      printf("\r");
#endif
    }
    break;
  case download_error:
    printf(_("Error downloading: %s\n"),
	   event->data.message);
    break;
  case download_complete:
#if 0
    printf(_("\nDownload %s %s.  Speed was %8.3f kilobyte per second.\n"),
	   di->filename,
	   (ntohl(di->fid->file_length) == di->lastProgress) ?
	   _("complete") : _("incomplete"),
	   (di->lastProgress/1024.0) / 
	   (((double)(cronTime(NULL)-di->startTime)) / (double)cronSECONDS) );
#endif
    break;
  default:
    BREAK();
    break;
  }
}

static char * mimeMap[][2] = {
  { "image/jpeg", ".jpg"},
  { "image/x-xpm", ".xpm"},
  { "image/gif", ".gif"},
  { "audio/real", ".rm"},
  { "video/real", ".rm"},
  { "image/tiff", ".tiff" },
  { "application/pdf", ".pdf" },
  { "video/avi", ".avi" },
  { "audio/midi", "midi" },
  { "application/x-tar", ".tar" },
  { "application/x-rpm", ".rpm" },
  { "applixation/x-gzip", ".gz" },
  { "application/rtf", ".rtf" },
  { "application/x-dvi", ".dvi" },
  { "audio/x-wav", ".wav" },
  { "audio/mpeg", ".mpg" },
  { "application/ogg", ".ogg" },
  { "application/bz2", ".bz2" },
  { "application/gnunet-directory", ".gnd" },
  { "application/postscript", ".ps" },
  { "image/xcf", ".xcf" },
  { "application/java", ".class" },
  { "image/x-png", ".png"}, 
  { "image/x-bmp", ".bmp"},
  { NULL, NULL },
};

/**
 * Main function to download files from GNUnet.
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return value from download file: 0: ok, -1, 1: error
 */   
int main(int argc, 
	 char ** argv) {
  struct ECRS_URI * uri;
  char * fstring;
  char * filename;
  int ok;
  int try_rename;

  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return 0;

  fstring = getConfigurationString("GNUNET-DOWNLOAD",
  				   "URI");
  uri = ECRS_stringToUri(fstring);
  if ( (NULL == uri) ||
       (! (ECRS_isLocationURI(uri) ||
	   ECRS_isFileURI(uri)) ) ) {
    LOG(LOG_ERROR,
        _("URI '%s' invalid for gnunet-download.\n"),
	fstring);
    FREE(fstring);
    return -1;
  }

  try_rename = NO;
  filename = getConfigurationString("GNUNET-DOWNLOAD",
				    "FILENAME");
  if (filename == NULL) {
    GNUNET_ASSERT(strlen(fstring) > 
		  strlen(ECRS_URI_PREFIX) + 
		  strlen(ECRS_FILE_INFIX));
    filename = expandFileName(&fstring[strlen(ECRS_URI_PREFIX)+
				       strlen(ECRS_FILE_INFIX)]);
    LOG(LOG_DEBUG,
	"No filename specified, using '%s' instead (for now).\n",
	filename);
    try_rename = YES;
  }

  startCron();
  /* FIXME: actually do the download! */
#if 0
  scheduleDownload(&fid,
		   filename);
  ok = run(threadLimit);
#endif
  ok = SYSERR;

  /* FIXME:
     move this code to ECRS! */
  if ( (ok == OK) && (try_rename == YES) ) {
    EXTRACTOR_ExtractorList * l;
    EXTRACTOR_KeywordList * list;
    const char * key;
    const char * mime;
    int i;
    char * renameTo;
    
    l = EXTRACTOR_loadDefaultLibraries();
    list = EXTRACTOR_getKeywords(l, filename);
    key = EXTRACTOR_extractLast(EXTRACTOR_TITLE,
				list);
    if (key == NULL)
      key = EXTRACTOR_extractLast(EXTRACTOR_DESCRIPTION,
				  list);
    if (key == NULL)
      key = EXTRACTOR_extractLast(EXTRACTOR_COMMENT,
				  list);
    if (key == NULL)
      key = EXTRACTOR_extractLast(EXTRACTOR_SUBJECT,
				  list);
    if (key == NULL)
      key = EXTRACTOR_extractLast(EXTRACTOR_ALBUM,
				  list);
    if (key == NULL)
      key = EXTRACTOR_extractLast(EXTRACTOR_UNKNOWN,
				  list);
    mime = EXTRACTOR_extractLast(EXTRACTOR_MIMETYPE,
				 list);
    if (mime != NULL) {
      i = 0;
      while ( (mimeMap[i][0] != NULL) &&
	      (0 != strcmp(mime, mimeMap[i][0])) )
	i++;
      if (mimeMap[i][1] == NULL)
	LOG(LOG_DEBUG,
	    "Did not find mime type '%s' in extension list.\n",
	    mime);
      mime = mimeMap[i][1];
    }
    if (mime != NULL) {
      if (0 == strcmp(&key[strlen(key)-strlen(mime)],
		      mime))
	mime = NULL;
    }
    if (key == NULL)
      key = filename;
    if (mime == NULL) {
      renameTo = STRDUP(key);
    } else {
      renameTo = MALLOC(strlen(key) + strlen(mime) + 1);
      strcpy(renameTo, key);
      strcat(renameTo, mime);
    }   
    for (i=strlen(renameTo)-1;i>=0;i--)
      if (! isprint(renameTo[i]))
	renameTo[i] = '_';    
    if (0 != strcmp(renameTo, filename)) {
      struct stat filestat;
      if (0 != STAT(renameTo,
		    &filestat)) {
	if (0 != RENAME(filename, renameTo)) 	  
	  fprintf(stdout,
		  _("Renaming of file '%s' to '%s' failed: %s\n"),
		  filename, renameTo, strerror(errno));
	else
	  fprintf(stdout,
		  _("File stored as '%s'.\n"),
		  renameTo);
      } else {
	fprintf(stdout,
		_("Could not rename file '%s' to '%s': file exists\n"),
		filename, renameTo);
      }	
    }
    FREE(renameTo);  				  
    EXTRACTOR_freeKeywords(list);
    EXTRACTOR_removeAll(l);    
  }

  FREE(filename);

  stopCron(); 
  doneUtil();
  
  if (ok == OK)
    return 0;
  else
    return 1;
}

/* end of gnunet-download.c */
