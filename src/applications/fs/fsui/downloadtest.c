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

#define DEBUG_VERBOSE NO

#define CHECK(a) if (!(a)) { ok = NO; BREAK(); goto FAILURE; }

static volatile int suspendRestart = 0;

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
				     "ERROR"));
  FREENONNULL(setConfigurationString("GNUNET",
				     "GNUNETD-CONFIG",
				     "check.conf"));
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
static volatile enum FSUI_EventType waitForEvent;
static struct FSUI_Context * ctx;
static struct ECRS_URI * upURI;

static void eventCallback(void * cls,
			  const FSUI_Event * event) {
  char * fn;

  switch(event->type) {
  case FSUI_search_result:
    printf("Received search result\n");
    break;
  case FSUI_upload_progress:
#if DEBUG_VERBOSE
    printf("Upload is progressing (%llu/%llu)...\n",
	   event->data.UploadProgress.completed,
	   event->data.UploadProgress.total);
#endif
    break;
  case FSUI_upload_complete:
    upURI = ECRS_dupUri(event->data.UploadComplete.uri);
    printf("Upload complete.\n");
    break;
  case FSUI_download_complete:
    printf("Download complete.\n");
    break;
  case FSUI_download_progress:
#if DEBUG_VERBOSE
    printf("Download is progressing (%llu/%llu)...\n",
	   event->data.DownloadProgress.completed,
	   event->data.DownloadProgress.total);
#endif
    break;
  case FSUI_unindex_progress:
#if DEBUG_VERBOSE
    printf("Unindex is progressing (%llu/%llu)...\n",
	   event->data.UnindexProgress.completed,
	   event->data.UnindexProgress.total);
#endif
    break;
  case FSUI_unindex_complete:
    printf("Unindex complete.\n");
    break;
  case FSUI_unindex_error:
  case FSUI_upload_error:
  case FSUI_download_error:
  case FSUI_search_error:
    errexit("Received ERROR: %d\n",
	    event->type);
  case FSUI_download_aborted:
#if DEBUG_VERBOSE
    printf("Received download aborted event.\n");
#endif
    break;
  case FSUI_gnunetd_connected:
  case FSUI_gnunetd_disconnected:
    break;
  default:
    printf("Unexpected event: %d\n",
	   event->type);
    break;
  }
  if (lastEvent == waitForEvent)
    return; /* ignore all other events */
  lastEvent = event->type;
  if (event->type == FSUI_search_result) {
    char * u;

    if (! ECRS_equalsUri(upURI,
			 event->data.SearchResult.fi.uri))
      return; /* ignore */
    fn = makeName(43);
    u = ECRS_uriToString(event->data.SearchResult.fi.uri);
    printf("Download started: %s.\n", u);
    FREE(u);
    if (OK !=
	FSUI_startDownload(ctx,
			   0,
			   event->data.SearchResult.fi.uri,
			   fn))
      errexit("Failed to start download.\n");
    FREE(fn);
    suspendRestart = 4;
  }
}

#define FILESIZE (1024 * 1024 * 2)


int main(int argc, char * argv[]){
  pid_t daemon;
  int ok;
  int i;
  struct ECRS_URI * uri = NULL;
  char * fn = NULL;
  char * keywords[] = {
    "down_foo",
    "down_bar",
    NULL,
  };
  char keyword[40];
  int prog;
  char * buf;
  struct ECRS_MetaData * meta;
  struct ECRS_URI * kuri = NULL;

  if (OK != initUtil(argc,
		     argv,
		     &parseCommandLine))
    return -1;
#if 1
  daemon = startGNUnetDaemon(NO);
  GNUNET_ASSERT(daemon > 0);
#else
  daemon = -1;
#endif
  ok = YES;
  startCron();
  GNUNET_ASSERT(OK == waitForGNUnetDaemonRunning(2 * cronMINUTES));
  gnunet_util_sleep(5 * cronSECONDS); /* give apps time to start */

  /* ACTUAL TEST CODE */
  ctx = FSUI_start("fsuidownloadtest",
		   YES,
		   &eventCallback,
		   NULL);
  CHECK(ctx != NULL);
  fn = makeName(42);
  buf = MALLOC(FILESIZE);
  for (i=0;i<FILESIZE;i++)
    buf[i] = weak_randomi(256);
  writeFile(fn,
	    buf,
	    FILESIZE,
	    "600");
  FREE(buf);
  meta = ECRS_createMetaData();
  kuri = FSUI_parseListKeywordURI(2,
				  (const char**)keywords);
  waitForEvent = FSUI_upload_complete;
  CHECK(OK ==
	FSUI_upload(ctx,
		    fn,
		    0,
		    YES,
		    NO,
		    meta,
		    kuri));
  ECRS_freeUri(kuri);
  kuri = NULL;
  ECRS_freeMetaData(meta);
  prog = 0;
  while (lastEvent != FSUI_upload_complete) {
    prog++;
    CHECK(prog < 1000);
    gnunet_util_sleep(50 * cronMILLIS);
  }
  SNPRINTF(keyword,
	   40,
	   "%s %s %s",
	   keywords[0],
	   _("AND"),
	   keywords[1]);
  uri = FSUI_parseCharKeywordURI(keyword);
  waitForEvent = FSUI_download_complete;
  CHECK(OK == FSUI_startSearch(ctx,
			       0,
			       uri));
  prog = 0;
  while (lastEvent != FSUI_download_complete) {
    prog++;
    CHECK(prog < 10000);
    gnunet_util_sleep(50 * cronMILLIS);
    if ( (suspendRestart > 0) &&
	 (weak_randomi(4) == 0) ) {
      suspendCron();
#if 1
#if DEBUG_VERBOSE
      printf("Testing FSUI suspend-resume\n");
#endif
      FSUI_stop(ctx); /* download possibly incomplete
			 at this point, thus testing resume */
      ctx = FSUI_start("fsuidownloadtest",
		       YES,
		       &eventCallback,
		       NULL);
#if DEBUG_VERBOSE
      printf("Resumed...\n");
#endif
#endif
      resumeCron();
      suspendRestart--;
    }
  }
  CHECK(OK == FSUI_stopSearch(ctx,
			      uri));
  waitForEvent = FSUI_unindex_complete;
  CHECK(OK == FSUI_unindex(ctx, fn));
  prog = 0;
  while (lastEvent != FSUI_unindex_complete) {
    prog++;
    CHECK(prog < 1000);
    gnunet_util_sleep(50 * cronMILLIS);
    CHECK(lastEvent != FSUI_unindex_error);
  }
  CHECK(lastEvent == FSUI_unindex_complete);
  /* END OF TEST CODE */
 FAILURE:
  if (fn != NULL) {
    UNLINK(fn);
    FREE(fn);
  }
  if (ctx != NULL) {
    FSUI_stopSearch(ctx,
		    uri);
    fn = makeName(43);
    FSUI_stopDownload(ctx,
		      uri,
		      fn);
    FREE(fn);
    FSUI_clearCompletedDownloads(ctx,
				 NULL,
				 NULL);
    FSUI_stop(ctx);
  }
  if (uri != NULL)
    ECRS_freeUri(uri);
  if (kuri != NULL)
    ECRS_freeUri(kuri);
  fn = makeName(43);
  /* TODO: verify file 'fn(42)' == file 'fn(43)' */
  UNLINK(fn);
  FREE(fn);
  if (upURI != NULL)
    ECRS_freeUri(upURI);

  stopCron();
  GNUNET_ASSERT(OK == stopGNUnetDaemon());
  GNUNET_ASSERT(OK == waitForGNUnetDaemonTermination(daemon));
  doneUtil();
  return (ok == YES) ? 0 : 1;
}

/* end of downloadtest.c */
