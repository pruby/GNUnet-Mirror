/*
     This file is part of GNUnet.
     (C) 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/fsui/downloadtest.c
 * @brief testcase for fsui download persistence (upload-download)
 * @author Christian Grothoff
 *
 * Todo:
 * - test more features of download (recursive, multiple files
 *   in parallel, etc.)
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_fsui_lib.h"
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

static char * makeName(unsigned int i) {
  char * name;
  char * fn;

  fn = STRDUP("/tmp/gnunet-fsuidownloadtest");
  name = expandFileName(fn);
  mkdirp(name);
  FREE(fn);
  fn = MALLOC(strlen(name) + 40);
  SNPRINTF(fn,
	   strlen(name) + 40,
	   "%s%sFSUITEST%u",
	   DIR_SEPARATOR_STR,
	   name,
	   i);
  FREE(name);
  return fn;
}

static volatile enum FSUI_EventType lastEvent;
static struct FSUI_Context * ctx;

static void eventCallback(void * cls,
			  const FSUI_Event * event) {
  char * fn;

  switch(event->type) {
  case FSUI_search_result:
    printf("Received search result\n");
    break;
  case FSUI_upload_complete:
    printf("Upload complete.\n");
    break;
  case FSUI_download_complete:
    printf("Download complete.\n");
    break;
  case FSUI_unindex_complete:
    printf("Unindex complete.\n");
    break;
  default:
    break;
  }
  if (lastEvent == FSUI_download_complete)
    return; /* ignore all other events */
  lastEvent = event->type;  
  if (event->type == FSUI_search_result) {
    fn = makeName(43);
    FSUI_startDownload(ctx,
		       0,
		       event->data.SearchResult.fi.uri,
		       fn);
    FSUI_stop(ctx); /* download possibly incomplete
		       at this point, thus testing resume */
    ctx = FSUI_start("fsuidownloadtest",
		     YES,
		     &eventCallback,
		     NULL);
    FREE(fn);
  }
}


int main(int argc, char * argv[]){
  pid_t daemon;
  int status;
  int ok;
  struct ECRS_URI * uri;
  char * fn = NULL;
  char * keywords[] = { 
    "down_foo",
    "down_bar",
    NULL,
  };
  char keyword[40];
  int prog;
  struct ECRS_MetaData * meta;
  struct ECRS_URI * kuri;

  daemon = fork();
  if (daemon == 0) {
    if (0 != execlp("gnunetd", /* what binary to execute, must be in $PATH! */
		    "gnunetd", /* arg0, path to gnunet binary */
		    "-d",  /* do not daemonize so we can easily kill you */
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
  if (OK != initUtil(argc, argv, &parseCommandLine))
    return -1;
  startCron();
  gnunet_util_sleep(30 * cronSECONDS); /* give gnunetd time to start */

  /* ACTUAL TEST CODE */
  ctx = FSUI_start("fsuidownloadtest",
		   YES,
		   &eventCallback,
		   NULL);
  CHECK(ctx != NULL);
  fn = makeName(42);
  writeFile(fn,
	    "foo bar test!",
	    strlen("foo bar test!"),
	    "600");
  meta = ECRS_createMetaData();
  kuri = FSUI_parseListKeywordURI(2,
				  (const char**)keywords);
  CHECK(OK ==
	FSUI_upload(ctx,
		    fn,
		    0,
		    YES,
		    NO,
		    meta,
		    kuri));
  ECRS_freeUri(kuri);
  ECRS_freeMetaData(meta);
  prog = 0;
  while (lastEvent != FSUI_upload_complete) {
    prog++;
    CHECK(prog < 10000) 
    
    gnunet_util_sleep(50 * cronMILLIS);
  }
  SNPRINTF(keyword,
	   40,
	   "%s %s %s",
	   keywords[0],
	   _("AND"),
	   keywords[1]);
  uri = FSUI_parseCharKeywordURI(keyword);
  CHECK(OK == FSUI_startSearch(ctx,
			       0,
			       uri));
  prog = 0;
  while (lastEvent != FSUI_download_complete) {
    prog++;
    CHECK(prog < 10000);
    gnunet_util_sleep(50 * cronMILLIS);
  }
  FSUI_stopSearch(ctx,
		  uri);
  CHECK(OK == FSUI_unindex(ctx, fn));

  /* END OF TEST CODE */
 FAILURE:
  if (ctx != NULL)
    FSUI_stop(ctx);
  if (fn != NULL) {
    UNLINK(fn);
    FREE(fn);
  }
  fn = makeName(43);
  /* TODO: verify file 'fn(42)' == file 'fn(43)' */
  UNLINK(fn);
  FREE(fn);

  stopCron();
  doneUtil();
  if (daemon != -1) {
    if (0 != kill(daemon, SIGTERM))
      DIE_STRERROR("kill");
    if (daemon != waitpid(daemon, &status, 0))
      DIE_STRERROR("waitpid");

    if ( (WEXITSTATUS(status) == 0) &&
	 (ok == YES) )
      return 0;
    else
      return 1;
  } else {
    return 0;
  }
}

/* end of downloadtest.c */
