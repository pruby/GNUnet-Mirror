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
 * @file applications/fs/fsui/fsuitest.c
 * @brief testcase for fsui (upload-download)
 * @author Christian Grothoff
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
				     "NOTHING"));
  return OK;
}

static char * makeName(unsigned int i) {
  char * name;
  char * fn;

  fn = STRDUP("/tmp/gnunet-fsuitest");
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
  case search_result:
    printf("Received search result\n");
    break;
  case upload_complete:
    printf("Upload complete.\n");
    break;
  case download_complete:
    printf("Download complete.\n");
    break;
  case unindex_complete:
    printf("Unindex complete.\n");
    break;
  default:
    break;
  }
  if (lastEvent == download_complete)
    return; /* ignore all other events */
  lastEvent = event->type;  
  if (event->type == search_result) {
    fn = makeName(43);
    FSUI_startDownload(ctx,
		       0,
		       event->data.SearchResult.fi.uri,
		       fn);
    FREE(fn);
  }
}


int main(int argc, char * argv[]){
  pid_t daemon;
  int status;
  int ok;
  struct ECRS_URI * uri;
  char * fn;
  char * keywords[] = { 
    "foo",
    "bar",
    NULL,
  };
  int prog;
  struct ECRS_MetaData * meta;

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
  initUtil(argc, argv, &parseCommandLine);
  startCron();
  gnunet_util_sleep(5 * cronSECONDS); /* give gnunetd time to start */

  /* ACTUAL TEST CODE */
  ctx = FSUI_start("fsuitest",
		   NO,
		   &eventCallback,
		   NULL);
  CHECK(ctx != NULL);
  fn = makeName(42);
  writeFile(fn,
	    "foo bar test!",
	    strlen("foo bar test!"),
	    "600");
  meta = ECRS_createMetaData();
  CHECK(OK ==
	FSUI_upload(ctx,
		    fn,
		    0,
		    YES,
		    meta,
		    2,
		    (const char**) keywords));
  ECRS_freeMetaData(meta);
  prog = 0;
  while (lastEvent != upload_complete) {
    prog++;
    CHECK(prog < 10000) 
    
    gnunet_util_sleep(50 * cronMILLIS);
  }
  uri = FSUI_parseCharKeywordURI("foo AND bar");
  CHECK(OK == FSUI_startSearch(ctx,
			       0,
			       uri));
  prog = 0;
  while (lastEvent != download_complete) {
    prog++;
    CHECK(prog < 10000);
    gnunet_util_sleep(50 * cronMILLIS);
  }
  FSUI_stopSearch(ctx,
		  uri);
  // CHECK(OK == FSUI_unindex(ctx, fn));

  /* END OF TEST CODE */
 FAILURE:
  if (ctx != NULL)
    FSUI_stop(ctx);
  // UNLINK(fn);
  FREE(fn);
  fn = makeName(43);
  /* FIXME: verify file 'fn(42)' == file 'fn(43)' */
  // UNLINK(fn);
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

/* end of fsuitest.c */
