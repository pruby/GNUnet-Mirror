/** 
 * @file applications/fs/ecrs/ecrstest.c
 * @brief testcase for ecrs (upload-download)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
#include "tree.h"
#include <sys/wait.h>

#define CHECK(a) if (!(a)) { ok = NO; BREAK(); goto FAILURE; }

static int parseCommandLine(int argc, 
			    char * argv[]) {
  FREENONNULL(setConfigurationString("GNUNETD",
				     "_MAGIC_",
				     "NO"));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  FREENONNULL(setConfigurationString("GNUNET",
				     "LOGLEVEL",
				     "WARNING"));
  return OK;
}

static int testTerminate(void * unused) {
  return OK;
}

static char * makeName(unsigned int i) {
  char * name;
  char * fn;

  fn = STRDUP("/tmp/gnunet-ecrstest");
  name = expandFileName(fn);
  mkdirp(name);
  FREE(fn);
  fn = MALLOC(strlen(name) + 40);
  SNPRINTF(fn,
	   strlen(name) + 40,
	   "%s%sECRSTEST%u",
	   DIR_SEPARATOR_STR,
	   name,
	   i);
  FREE(name);
  return fn;
}

static struct ECRS_URI * uploadFile(unsigned int size) {
  int ret;
  char * name;
  int fd;
  char * buf;
  struct ECRS_URI * uri;
  int i;
  
  name = makeName(size);
  fd = OPEN(name, O_WRONLY|O_CREAT, S_IWUSR|S_IRUSR);
  buf = MALLOC(size);
  memset(buf, size + size / 253, size);
  for (i=0;i<(int) (size - 42 - sizeof(HashCode160));i+=sizeof(HashCode160)) 
    hash(&buf[i+sizeof(HashCode160)],
	 42,
	 (HashCode160*) &buf[i]);
  write(fd, buf, size);
  FREE(buf);
  CLOSE(fd);
  ret = ECRS_uploadFile(name,
			YES, /* index */
			0, /* anon */
			0, /* prio */
			cronTime(NULL) + 10 * cronMINUTES, /* expire */
			NULL, /* progress */
			NULL, 
			&testTerminate,
			NULL,
			&uri);
  if (ret != SYSERR) {
    struct ECRS_MetaData * meta;
    struct ECRS_URI * key;
    const char * keywords[2];

    keywords[0] = name;
    keywords[1] = NULL;

    meta = ECRS_createMetaData();
    key = ECRS_keywordsToUri(keywords);
    ret = ECRS_addToKeyspace(key,
			     0,
			     0,
			     cronTime(NULL) + 10 * cronMINUTES, /* expire */
			     uri,
			     meta);
    ECRS_freeMetaData(meta);
    ECRS_freeUri(uri);
    FREE(name);  
    if (ret == OK) {
      return key;
    } else {
      ECRS_freeUri(key);
      return NULL;
    }
  } else {
    FREE(name);  
    return NULL;
  }
}

static int searchCB(const ECRS_FileInfo * fi,
		    const HashCode160 * key,
		    void * closure) {
  struct ECRS_URI ** my = closure;

  GNUNET_ASSERT(NULL == *my);
  *my = ECRS_dupUri(fi->uri);
  return SYSERR; /* abort search */
}

/**
 * @param *uri In: keyword URI, out: file URI
 * @return OK on success
 */
static int searchFile(struct ECRS_URI ** uri) {
  int ret;
  struct ECRS_URI * myURI;

  myURI = NULL;
  ECRS_search(*uri,
	      0,
	      15 * cronSECONDS,
	      &searchCB,
	      &myURI,
	      &testTerminate,
	      NULL);
  ECRS_freeUri(*uri);
  *uri = myURI;
  if ( (ret != SYSERR) &&
       (myURI != NULL) )
    return OK;
  else
    return SYSERR;  
}

static int downloadFile(unsigned int size,
			struct ECRS_URI * uri) {
  /* FIXME: initiate download,
     verify file */
  ECRS_freeUri(uri);
  return OK;
}


static int unindexFile(unsigned int size) {
  int ret;
  char * name;
  
  name = makeName(size);
  ret = ECRS_unindexFile(name,
			 NULL,
			 NULL,
			 &testTerminate,
			 NULL);
  if (0 != UNLINK(name))
    ret = SYSERR;
  FREE(name);  
  return ret;
}

int main(int argc, char * argv[]){
  static unsigned int filesizes[] = {
    1,
    2,
    4,
    16,
    32,
    1024,
    DBLOCK_SIZE - 1,
    DBLOCK_SIZE,
    DBLOCK_SIZE + 1,
    DBLOCK_SIZE * CHK_PER_INODE - 1,
    DBLOCK_SIZE * CHK_PER_INODE,
    DBLOCK_SIZE * CHK_PER_INODE + 1,
    DBLOCK_SIZE * CHK_PER_INODE * CHK_PER_INODE - 1,
    DBLOCK_SIZE * CHK_PER_INODE * CHK_PER_INODE,
    DBLOCK_SIZE * CHK_PER_INODE * CHK_PER_INODE + 1,
    0
  };
  pid_t daemon;
  int status;
  int ok;
  Mutex lock;
  GNUNET_TCP_SOCKET * sock;
  struct ECRS_URI * uri;
  int i;

  daemon = fork();
  if (daemon == 0) {
    /* FIXME: would be nice to be able to tell
       gnunetd to use the check/debug DB and not
       any real DB! */
    if (0 != execlp("gnunetd", /* what binary to execute, must be in $PATH! */
		    "gnunetd", /* arg0, path to gnunet binary */
		    "-d",  /* do not daemonize so we can easily kill you */
		    "-L", "NOTHING",
		    "-c",
		    "check.conf", /* configuration file */
		    NULL)) {
      fprintf(stderr,
	      _("'%s' failed: %s\n"),
	      "execlp",
	      STRERROR(errno));
      return -1;
    }
  }
  ok = YES;
  initUtil(argc, argv, &parseCommandLine);
  startCron();
  MUTEX_CREATE(&lock);
  gnunet_util_sleep(5 * cronSECONDS); /* give gnunetd time to start */
  sock = getClientSocket();
  CHECK(sock != NULL);
  
  /* ACTUAL TEST CODE */
  i = 0;
  while (filesizes[i] != 0) {
    fprintf(stderr,
	    "Testing filesize %u",
	    filesizes[i]);
    uri = uploadFile(filesizes[i]);
    CHECK(NULL != uri);
    CHECK(OK == searchFile(&uri));
    CHECK(OK == downloadFile(filesizes[i], uri));
    CHECK(OK == unindexFile(filesizes[i]));
    fprintf(stderr,
	    " Ok.\n");
    i++;
  } 

  /* END OF TEST CODE */
 FAILURE:
  if (sock != NULL)
    releaseClientSocket(sock);
  MUTEX_DESTROY(&lock);
  stopCron();
  doneUtil();
  if (0 != kill(daemon, SIGTERM))
    DIE_STRERROR("kill");
  if (daemon != waitpid(daemon, &status, 0)) 
    DIE_STRERROR("waitpid");
  
  if ( (WEXITSTATUS(status) == 0) && 
       (ok == YES) )
    return 0;
  else
    return 1;    
}

/* end of ecrstest.c */
