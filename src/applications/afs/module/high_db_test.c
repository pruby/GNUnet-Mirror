/*
 * @file test/high_db_test.c
 * @brief Test for the high-level DB API implementations.
 * @author Christian Grothoff
 *
 * Not tested (but easily testable):
 * - deleteContent
 * - unlinkFromDB
 * - forEachEntryInDatabase (with content in it)
 * - countContentEntries (with content in it)
 */

#include "gnunet_util.h"
#include "high_backend.h"
#include "platform.h"

#ifndef MINGW
 #include <netinet/in.h>
#endif

typedef struct {
  HighDBHandle (*initContentDatabase)(unsigned int i,
				      unsigned int n);
  void (*doneContentDatabase)(HighDBHandle handle);
  int (*forEachEntryInDatabase)(HighDBHandle handle,
				EntryCallback callback,
				void * data);
  int (*countContentEntries)(HighDBHandle handle);
  int (*readContent)(HighDBHandle handle,
		     const HashCode160 * query,
		     ContentIndex * ce,
		     void ** result,
		     int prio);
  int (*writeContent)(HighDBHandle handle,
		      const ContentIndex * ce,
		      int len,
		      void * block);
  int (*unlinkFromDB)(HighDBHandle handle,
		      const HashCode160 * query);
  int (*getRandomContent)(HighDBHandle handle,
			  ContentIndex * ce);
  int (*deleteContent)(HighDBHandle handle,
		       int count,
		       EntryCallback callback,
		       void * closure);
  unsigned int (*getMinimumPriority)(HighDBHandle handle); 
  int (*estimateAvailableBlocks)(HighDBHandle handle,
				 int quota);
  void (*deleteDatabase)(HighDBHandle handle);
} HighAPI;

static void doerror(const HashCode160 * key,
		    const ContentIndex * ce,
		    void * data,
		    unsigned int dataLen,
		    void * closure) {
  *(int*)closure = SYSERR;
  FREENONNULL(data);
}

/**
 * Add testcode here!
 */
static int testTAPI(HighAPI * a) {
  HighDBHandle h;
  int error;
  void * v1;
  void * v2;
  ContentIndex ce1;
  ContentIndex ce2;
  HashCode160 hc;

  /* get into well-defined state */
  h = a->initContentDatabase(0,0); /* 0,0 is an otherwise invalid entry,
				      so this is good for testing */
  if (h == NULL) {
    fprintf(stderr, "Could not initialize database!\n");
    fprintf(stderr, "I will pass the testcase without running the code.\n");
    fprintf(stderr, "Check your database configuration.\n");
    return OK;
  }
  fprintf(stderr, ".");
  a->deleteDatabase(h);
  /* ok, now for real */
  h = a->initContentDatabase(0,0); 
  if (h == NULL)
    return SYSERR;
  fprintf(stderr, ".");
  if (0 != a->countContentEntries(h))
    return SYSERR;
  fprintf(stderr, ".");
  if (0 != a->getMinimumPriority(h))
    return SYSERR;
  fprintf(stderr, ".");
  error = OK;
  if (0 != a->forEachEntryInDatabase(h, 
				     &doerror, &error))
    return SYSERR;
  fprintf(stderr, ".");
  if (error != OK)
    return SYSERR;
  fprintf(stderr, ".");
  memset(&hc, 42, sizeof(hc));
  memset(&ce1, 44, sizeof(ce1));
  v1 = MALLOC(92);
  memset(v1, 46, 92);
  ce1.type = htons(LOOKUP_TYPE_3HASH);
  if (SYSERR == a->writeContent(h, &ce1, 92, v1))
    return SYSERR;
  fprintf(stderr, ".");
  v2 = NULL;
  if (SYSERR != a->readContent(h, &hc, &ce2, &v2, 0))
    return SYSERR;
  fprintf(stderr, ".");
  if (v2 != NULL)
    return SYSERR;
  fprintf(stderr, ".");
  hash(&ce1.hash,
       sizeof(HashCode160),
       &hc);
  if (92 != a->readContent(h, &hc, &ce2, &v2, 0))
    return SYSERR;
  fprintf(stderr, ".");
  if (0 != memcmp(v1, v2, 92))
    return SYSERR;
  fprintf(stderr, ".");
  if (0 != memcmp(&ce1, &ce2, sizeof(ce1)))
    return SYSERR;
  fprintf(stderr, ".");
  FREE(v2); v2 = NULL;
  if (OK != a->unlinkFromDB(h, &hc))
    return SYSERR;
  if (0 != a->countContentEntries(h))
    return SYSERR;
  if (SYSERR != a->readContent(h, &hc, &ce2, &v2, 0))
    return SYSERR;
  if (v2 != NULL)
    return SYSERR;
  if (SYSERR == a->writeContent(h, &ce1, 92, v1))
    return SYSERR;
  fprintf(stderr, ".");
  a->doneContentDatabase(h);
  h = a->initContentDatabase(0,0); 
  if (h == NULL)
    return SYSERR;
  if (92 != a->readContent(h, &hc, &ce2, &v2, 0))
    return SYSERR;
  fprintf(stderr, ".");
  if (0 != memcmp(v1, v2, 92))
    return SYSERR;
  fprintf(stderr, ".");
  if (0 != memcmp(&ce1, &ce2, sizeof(ce1)))
    return SYSERR;
  FREE(v2); v2 = NULL;
  a->deleteDatabase(h);
  h = a->initContentDatabase(0,0); 
  if (SYSERR != a->readContent(h, &hc, &ce2, &v2, 0))
    return SYSERR;
  if (v2 != NULL)
    return SYSERR;
  FREE(v1); v1 = NULL;
  a->deleteDatabase(h);

  h = a->initContentDatabase(0,0); 
  if (h == NULL)
    return SYSERR;
  fprintf(stderr, ".");
  if (0 != a->countContentEntries(h))
    return SYSERR;
  fprintf(stderr, ".");
  if (0 != a->getMinimumPriority(h))
    return SYSERR;
  fprintf(stderr, ".");
  error = OK;
  if (0 != a->forEachEntryInDatabase(h,
				     &doerror, &error))
    return SYSERR;
  fprintf(stderr, ".");
  if (error != OK)
    return SYSERR;
  fprintf(stderr, ".");
  memset(&hc, 42, sizeof(hc));
  memset(&ce1, 44, sizeof(ce1));
  v1 = MALLOC(92);
  memset(v1, 46, 92);
  ce1.type = htons(LOOKUP_TYPE_CHK);
  if (SYSERR == a->writeContent(h, &ce1, 92, v1))
    return SYSERR;
  fprintf(stderr, ".");
  v2 = NULL;
  if (SYSERR != a->readContent(h, &hc, &ce2, &v2, 0))
    return SYSERR;
  fprintf(stderr, ".");
  if (v2 != NULL)
    return SYSERR;
  fprintf(stderr, ".");
  memcpy(&hc,
	 &ce1.hash,
	 sizeof(HashCode160));
  if (92 != a->readContent(h, &hc, &ce2, &v2, 0))
    return SYSERR;
  fprintf(stderr, ".");
  if (0 != memcmp(v1, v2, 92))
    return SYSERR;
  fprintf(stderr, ".");
  if (0 != memcmp(&ce1, &ce2, sizeof(ce1)))
    return SYSERR;
  fprintf(stderr, ".");
  FREE(v2); v2 = NULL;
  if (OK != a->unlinkFromDB(h, &hc))
    return SYSERR;
  if (0 != a->countContentEntries(h))
    return SYSERR;
  if (SYSERR != a->readContent(h, &hc, &ce2, &v2, 0))
    return SYSERR;
  if (v2 != NULL)
    return SYSERR;
  if (SYSERR == a->writeContent(h, &ce1, 92, v1))
    return SYSERR;
  fprintf(stderr, ".");
  a->deleteDatabase(h);
  FREE(v1); v1 = NULL;

  fprintf(stderr, ".\n");
  return OK;
}

static char * tselect = DBSELECT;

/**
 * Perform option parsing from the command line. 
 */
static int parser(int argc, 
		  char * argv[]) {
  int cont = OK;
  int c;

  FREENONNULL(setConfigurationString("GNUNETD",
				     "_MAGIC_",
				     "YES"));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  FREENONNULL(setConfigurationString("",
				     "GNUNETD_HOME",
				     "/tmp/gnunet_test/"));
  FREENONNULL(setConfigurationString("FILES",
				     "gnunet.conf",
				     "/tmp/gnunet_test/gnunet.conf"));

  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      { "loglevel",1, 0, 'L' },
      { "config",  1, 0, 'c' },
      { "version", 0, 0, 'v' },
      { "help",    0, 0, 'h' },
      { 0,0,0,0 }
    };
    
    c = GNgetopt_long(argc,
		      argv, 
		      "vhc:L:", 
		      long_options, 
		      &option_index);
    
    if (c == -1) 
      break;  /* No more flags to process */
    
    switch(c) {
    case 'c':
      FREENONNULL(setConfigurationString("FILES",
					 "gnunet.conf",
					 GNoptarg));
      break;
    case 'v': 
      printf("GNUnet High-level DB API Tester v%s\n",
	     VERSION);
      cont = SYSERR;
      break;
    case 'h': 
      printf("GNUnet High-level DB API Tester. Options:"
	     " -c config, -L loglevel, -h help,"
	     " -v version\n");
      cont = SYSERR;
      break;
    case 'L':
      FREENONNULL(setConfigurationString("GNUNETD",
					 "LOGLEVEL",
					 GNoptarg));
      break;
    default:
      LOG(LOG_FAILURE, 
	  " Unknown option %c. Aborting.\n"\
	  "Use --help to get a list of options.\n",
	  c);
      cont = SYSERR;    
    } /* end of parsing commandline */
  }
  if (GNoptind < argc) {
    LOG(LOG_WARNING, 
	" Invalid arguments: ");
    while (GNoptind < argc)
      LOG(LOG_WARNING, 
	  "%s ", argv[GNoptind++]);
    LOG(LOG_FATAL,
	" Invalid arguments. Exiting.\n");
    return SYSERR;
  }
  return cont;
}

#define DSO_PREFIX "libgnunetafs_database_"
#define TEST_DB "/tmp/GNUnet_high_db_test/"

int main(int argc, char *argv[]) {
  HighAPI l;
  void * lib;
  int ok;

  if (OK != initUtil(argc, argv, &parser))
    errexit("Could not initialize libgnunetutil!\n");
  /* we may not have write-rights in the default
     directory; use /tmp! */
  FREENONNULL(setConfigurationString("AFS",
				     "AFSDIR",
				     TEST_DB));
  if (tselect == NULL)
    tselect = getConfigurationString("AFS",
				     "DATABASETYPE");
  if (tselect == NULL)
    errexit("You must specify the DB type with option -t.\n");
  
  lib = loadDynamicLibrary(DSO_PREFIX,
                           tselect);
  if (lib == NULL)
    errexit("could not load plugin %s\n",
	    tselect);
  l.initContentDatabase 
    = bindDynamicMethod(lib,
			"",
			"initContentDatabase");
  l.doneContentDatabase
    = bindDynamicMethod(lib,
			"",
			"doneContentDatabase");
  l.countContentEntries
    = bindDynamicMethod(lib,
			"",
			"countContentEntries");
  l.readContent
    = bindDynamicMethod(lib,
			"",
			"readContent");
  l.writeContent
    = bindDynamicMethod(lib,
			"",
			"writeContent");
  l.unlinkFromDB
    = bindDynamicMethod(lib,
			"",
			"unlinkFromDB");
  l.getRandomContent
    = bindDynamicMethod(lib,
			"",
			"getRandomContent");
  l.deleteContent
    = bindDynamicMethod(lib,
			"",
			"deleteContent");
  l.forEachEntryInDatabase
    = bindDynamicMethod(lib,
			"",
			"forEachEntryInDatabase");
  l.getMinimumPriority
    = bindDynamicMethod(lib,
			"",
			"getMinimumPriority");
  l.estimateAvailableBlocks
    = bindDynamicMethod(lib,
			"",
			"estimateAvailableBlocks");
  l.deleteDatabase
    = bindDynamicMethod(lib,
			"",
			"deleteDatabase");
  ok = testTAPI(&l);
  unloadDynamicLibrary(lib);  
  doneUtil();
  if (ok == SYSERR) {
    fprintf(stderr, "\nFAILED!\n");
    return 1;
  } else {
    return 0;
  }
}


