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
 * @file applications/afs/module/gnunet-convert.c
 * @brief Little tool to convert content databases from format to another.
 *        Use if you change the database manager type or the bucket count.
 * @author Igor Wronsky
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_afs_esed2.h"
#include "manager.h"
#include "bloomfilter.h"
#include "manager.c"
#include "bloomfilter.c"
#include "large_file_support.c"
#include "fileindex.c"
  
static DatabaseAPI * srcHandle;
static DatabaseAPI * dstHandle;

unsigned int insertedBlocks = 0;
unsigned int failedBlocks = 0;

static int progressDot = 0;
static int be_verbose = NO;
static int be_quiet = NO;

static void addToDestination(const HashCode160 * key,
			     const ContentIndex *ce,
			     void * data,
			     unsigned int dataLen,
			     void * unused) {
  HashCode160 hc;
  int bucket;

  progressDot++;
  if ( ((progressDot & 255) == 0) &&
       (be_quiet == NO) ) {
    printf(".");
    fflush(stdout);    
  }

  switch (ntohs(ce->type)) {
  case LOOKUP_TYPE_CHK:
    addToBloomfilter(singleBloomFilter,
		     &ce->hash);		       
    break;
  case LOOKUP_TYPE_3HASH:
    hash(&ce->hash,
	 sizeof(HashCode160),
	 &hc);
    addToBloomfilter(singleBloomFilter,
		     &hc);
    break;
  case LOOKUP_TYPE_SUPER:
    addToBloomfilter(superBloomFilter,
		     &ce->hash);
    break;
  case LOOKUP_TYPE_SBLOCK:
    addToBloomfilter(singleBloomFilter,
	             &hc);		
    break;
  case LOOKUP_TYPE_CHKS:
    /* do nothing! */
    break;
  default:
    LOG(LOG_WARNING,
	_("Encountered unexpected type %d.\n"),
	ntohs(ce->type));
  }
 
  bucket = computeBucket(key,
  			 dstHandle->buckets);
  if (SYSERR == dstHandle->writeContent(dstHandle->dbHandles[bucket],
					ce,
					dataLen,
					data))
    failedBlocks++;
  else
    insertedBlocks++;  
  FREENONNULL(data);
}

/**
 * Print a list of the options we offer.
 */
static void printhelp() {
  static Help help[] = {
    HELP_CONFIG,
    HELP_HELP,
    HELP_LOGLEVEL,
    { 'q', "quiet", NULL,
      gettext_noop("be quiet") },
    HELP_VERSION,
    HELP_VERBOSE,
    HELP_END,
  };
  formatHelp("gnunet-convert [OPTIONS]",
	     _("Convert GNUnet AFS database to different QUOTA or database type.\n"
	       "Never run gnunet-convert while gnunetd is running!"),
	     help);
}

/**
 * Perform option parsing from the command line. 
 */
static int parseCommandLine(int argc, 
			    char * argv[]) {
  int c;

  FREENONNULL(setConfigurationString("GNUNETD",
				     "_MAGIC_",
				     "YES"));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "verbose",  0, 0, 'V' },
      { "quiet",    0, 0, 'q' },
      { 0,0,0,0 }
    };
    
    c = GNgetopt_long(argc,
		      argv, 
		      "vhdc:nVqL:", 
		      long_options, 
		      &option_index);    
    if (c == -1) 
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;    
    switch(c) {
    case 'q':
      be_quiet = YES;
      break;
    case 'V':
      be_verbose = YES;
      break;
    case 'v': 
      printf("GNUnet v%s, gnunet-convert v%s\n",
	     VERSION, 
	     AFS_VERSION);
      return SYSERR;
      break;
    case 'h': 
      printhelp(); 
      return SYSERR;
      break;
    default:
      printf(_("Use --help to get a list of options.\n"));
      return SYSERR;
    } /* end of parsing commandline */
  }
  if (GNoptind < argc) {
    printf(_("Invalid arguments: "));
    while (GNoptind < argc)
      printf("%s ", argv[GNoptind++]);
    printf(_("\nExiting.\n"));
    return SYSERR;
  }
  return OK;
}



int main(int argc, 
	 char * argv[]) {
  char * srcDb;
  char * dstDb;
  char * tmp;
  int entries;
  int newQuota;
  int * oldQuota;
  int ret;
  unsigned int i;

  if (SYSERR == initUtil(argc, argv, &parseCommandLine))
    return 0;

  newQuota = getConfigurationInt("AFS",
				 "DISKQUOTA");
  if (newQuota == 0)
    errexit(_("You must specify available diskspace"
	      " in the configuration under '%s' in section '%s'\n"),
	      "DISKQUOTA", "AFS"); 
  oldQuota = NULL;
  ret = stateReadContent("AFS-DISKQUOTA",
			 (void**)&oldQuota);
  if (ret != sizeof(unsigned int))
    errexit(_("No conversion possible, no old database known.\n"));
  tmp = NULL;
  ret = stateReadContent("AFS-DATABASETYPE",
			 (void**)&tmp);
  dstDb = getConfigurationString("AFS",
				 "DATABASETYPE");  
  if (dstDb == NULL)
    errexit(_("You must specify the option '%s' in the configuration in section '%s'.\n"),
	    "DATABASETYPE", "AFS");
  if ( (ret == -1) ||
       ( (strncmp(tmp, dstDb, ret) == 0) &&
	 (newQuota == *oldQuota) ) )
    errexit(_("You need to specify a different database type or quota"
	      " in the configuration in order to run gnunet-convert.\n"));
  srcDb = MALLOC(ret+1);
  memcpy(srcDb, tmp, ret);
  FREENONNULL(tmp);
  srcDb[ret] = '\0';
  /* initialize old DB with old config! */
  setConfigurationInt("AFS",
		      "DISKQUOTA",
		      *oldQuota);
  FREENONNULL(oldQuota);
  FREENONNULL(setConfigurationString("AFS",
				     "DATABASETYPE",
				     srcDb));
  srcHandle = initializeDatabaseAPI(srcDb);
  FREE(srcDb);

  /* initialize new DB with new config */
  stateWriteContent("AFS-DATABASETYPE",
		    strlen(dstDb),
		    dstDb);
  setConfigurationInt("AFS",
		      "DISKQUOTA",
		      newQuota);
  stateWriteContent("AFS-DISKQUOTA",
		    sizeof(unsigned int),
		    &newQuota);
  FREENONNULL(setConfigurationString("AFS",
				     "DATABASETYPE",
				     dstDb));

  /* FIXME: if the following call fails, we have set the new DB
     parameters in the state module but the conversion has not been
     done (and now the user is in deep shit (TM)).  We need to be able
     to prevent the state module from commiting the changes until we
     are done with everything.  The best way I can think of is to set
     a flag in state.c "don't commit", then just record all writes and
     once the flag is unset, do the writes. -- CG */

  dstHandle = initializeDatabaseAPI(dstDb);
  initBloomfilters(); /* from afs.c */
  resetBloomfilter(superBloomFilter);
  resetBloomfilter(singleBloomFilter);

  /* copy old->new */
  entries = 0;
  for (i=0;i<srcHandle->buckets;i++)
    entries += srcHandle->forEachEntryInDatabase(srcHandle->dbHandles[i],
						 &addToDestination, 
						 NULL);

  fprintf(stdout,
	  _("\nCompleted processing %d entries in index "
	  "(%d converted, %d failed).\n"),
	  entries,
	  insertedBlocks,
	  failedBlocks);

  /* close new, then delete old */
  doneBloomfilters();
  for (i=0;i<dstHandle->buckets;i++)
    dstHandle->doneContentDatabase(dstHandle->dbHandles[i]);
  for (i=0;i<srcHandle->buckets;i++) 
    srcHandle->deleteDatabase(srcHandle->dbHandles[i]);
  FREE(srcHandle->dbHandles);
  FREE(dstHandle->dbHandles);
  unloadDynamicLibrary(srcHandle->dynamicLibrary);
  unloadDynamicLibrary(dstHandle->dynamicLibrary);
  FREE(srcHandle);
  FREE(dstHandle);
  doneUtil();

  return 0;
}


/* end of gnunet-convert.c */
