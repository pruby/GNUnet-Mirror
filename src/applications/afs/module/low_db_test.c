/*
 * @file test/low_db_test.c
 * @brief Test for the low-level DB API implementations.
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "platform.h"
#include "low_backend.h"


typedef struct {
  LowDBHandle (*lowInitContentDatabase)(char * dir);
  void (*lowDeleteContentDatabase)(LowDBHandle handle);  
  void (*lowDoneContentDatabase)(LowDBHandle handle);
  int (*lowUnlinkFromDB)(LowDBHandle handle, 
			 HashCode160 * fn);
  int (*lowCountContentEntries)(LowDBHandle handle);
  int (*lowReadContent)(LowDBHandle handle,
			HashCode160 * fn,
			void ** result);
  int (*lowWriteContent)(LowDBHandle handle,
			 HashCode160 * fn, 
			 int len,
			 void * block);
  int (*lowForEachEntryInDatabase)(LowDBHandle handle,
				   LowEntryCallback callback,
				   void * data);
  int (*lowEstimateSize)(LowDBHandle handle);  
} LowAPI;

#define TEST_DB "/tmp/GNUnet_low_db_test/"

void do_error(HashCode160 * key,
	      int * e) {
  *e = SYSERR;
}

int testTAPI(LowAPI * lapi) {
  LowDBHandle h;
  int error;
  void * v;
  void * v2;
  HashCode160 hc;
  
  /* get into well-defined state first! */
  h = lapi->lowInitContentDatabase(TEST_DB);
  if (h == NULL)
    return SYSERR;
  fprintf(stderr,".");
  lapi->lowDeleteContentDatabase(h); 
  h = lapi->lowInitContentDatabase(TEST_DB);
  error = OK;
  if (0 != lapi->lowForEachEntryInDatabase(h, 
					   (LowEntryCallback)&do_error, 
					   &error))
    return SYSERR;
  fprintf(stderr,".");
  if (error == SYSERR)
    return SYSERR;
  v = NULL;
  fprintf(stderr,".");
  memset(&hc, 0x01, sizeof(hc));
  if (SYSERR != lapi->lowReadContent(h, &hc, &v))
    return SYSERR; /* db is emtpy! */
  fprintf(stderr,".");
  if (v != NULL)
    return SYSERR; /* v may not change! */
  fprintf(stderr,".");
  if (OK != lapi->lowWriteContent(h, &hc, 1, &hc))
    return SYSERR;
  fprintf(stderr,".");
  if (1 != lapi->lowCountContentEntries(h))
    return SYSERR; /* wrong count */
  fprintf(stderr,".");
  if (1 != lapi->lowReadContent(h, &hc, &v))
    return SYSERR; /* db is emtpy! */
  FREE(v); v = NULL;
  fprintf(stderr,".");
  if (OK != lapi->lowUnlinkFromDB(h, &hc))
    return SYSERR;
  fprintf(stderr,".");
  if (0 != lapi->lowCountContentEntries(h))
    return SYSERR; /* wrong count */
  fprintf(stderr,".");
  if (SYSERR != lapi->lowReadContent(h, &hc, &v))
    return SYSERR; /* db is emtpy! */
  fprintf(stderr,".");
  v2 = MALLOC(46);
  memset(v2, 42, 46);
  if (OK != lapi->lowWriteContent(h, &hc, 46, v2))
    return SYSERR;
  fprintf(stderr,".");
  if (46 != lapi->lowReadContent(h, &hc, &v))
    return SYSERR; /* wrong size! */
  fprintf(stderr,".");
  if (0 != memcmp(v, v2, 46))
    return SYSERR; /* wrong data */
  fprintf(stderr,".");
  FREE(v); v = NULL;
  if (1 != lapi->lowCountContentEntries(h))
    return SYSERR; /* wrong count */
  fprintf(stderr,".");
  if (OK != lapi->lowWriteContent(h, &hc, 4, v2))
    return SYSERR; /* destructive, truncating write! */
  fprintf(stderr,".");
  if (4 != lapi->lowReadContent(h, &hc, &v))
    return SYSERR; /* wrong size! */
  fprintf(stderr,".");
  if (0 != memcmp(v, v2, 4))
    return SYSERR; /* wrong data */
  fprintf(stderr,".");
  FREE(v); v = NULL;
  if (OK != lapi->lowUnlinkFromDB(h, &hc))
    return SYSERR;  
  fprintf(stderr,".");
  if (0 != lapi->lowCountContentEntries(h))
    return SYSERR; /* wrong count */
  fprintf(stderr,".");
  if (OK != lapi->lowWriteContent(h, &hc, 4, v2))
    return SYSERR; /* destructive, truncating write! */
  fprintf(stderr,".");
  lapi->lowDoneContentDatabase(h);
  h = lapi->lowInitContentDatabase(TEST_DB);
  if (1 != lapi->lowCountContentEntries(h))
    return SYSERR; /* wrong count */
  fprintf(stderr,".");
  if (4 != lapi->lowReadContent(h, &hc, &v))
    return SYSERR; /* wrong size! */
  fprintf(stderr,".");
  if (0 != memcmp(v, v2, 4))
    return SYSERR; /* wrong data */
  fprintf(stderr,".");
  FREE(v); v = NULL;
  FREE(v2);
  lapi->lowDeleteContentDatabase(h); 
  h = lapi->lowInitContentDatabase(TEST_DB);
  if (0 != lapi->lowCountContentEntries(h))
    return SYSERR; /* wrong count */
  fprintf(stderr,".");
  if (SYSERR != lapi->lowReadContent(h, &hc, &v))
    return SYSERR; /* db is emtpy! */
  fprintf(stderr,".");
  lapi->lowDoneContentDatabase(h);
  fprintf(stderr,".\n");
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
      printf("GNUnet Low-level DB API Tester v%s\n",
	     VERSION);
      cont = SYSERR;
      break;
    case 'h': 
      printf("GNUnet Low-level DB API Tester. Options:"
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

int main(int argc, char *argv[]) {
  LowAPI l;
  void * lib;
  int ok;

  if (OK != initUtil(argc, argv, &parser))
    return SYSERR;
  lib = loadDynamicLibrary(DSO_PREFIX,
                           tselect);
  if (lib == NULL)
    errexit(" could not load plugin %s\n",
	    tselect);
  l.lowInitContentDatabase 
    = bindDynamicMethod(lib,
			"",
			"lowInitContentDatabase");
  l.lowDeleteContentDatabase 
    = bindDynamicMethod(lib,
			"",
			"lowDeleteContentDatabase");
  l.lowDoneContentDatabase 
    = bindDynamicMethod(lib,
			"",
			"lowDoneContentDatabase");
  l.lowCountContentEntries 
    = bindDynamicMethod(lib,
			"",
			"lowCountContentEntries");
  l.lowReadContent 
    = bindDynamicMethod(lib,
			"",
			"lowReadContent");
  l.lowUnlinkFromDB
    = bindDynamicMethod(lib,
			"",
			"lowUnlinkFromDB");
  l.lowWriteContent
    = bindDynamicMethod(lib,
			"",
			"lowWriteContent");
  l.lowForEachEntryInDatabase
    = bindDynamicMethod(lib,
			"",
			"lowForEachEntryInDatabase");
  l.lowEstimateSize
    = bindDynamicMethod(lib,
			"",
			"lowEstimateSize");  
  ok = testTAPI(&l);
  unloadDynamicLibrary(lib);  
  doneUtil();
  if (ok == SYSERR) {
    fprintf(stderr, "\nFAILED!\n");
    return 1;
  } else
    return 0;
}


