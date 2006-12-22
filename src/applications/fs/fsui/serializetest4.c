/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/fsui/serializetest4.c
 * @brief testcase for fsui download persistence for recursive
 *        download
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"
#include "gnunet_util_crypto.h"

#define DEBUG_VERBOSE NO

#define UPLOAD_PREFIX "/tmp/gnunet-fsui-searializetest4"

#define CHECK(a) if (!(a)) { ok = NO; GE_BREAK(ectx, 0); goto FAILURE; }

static struct GE_Context * ectx;

static char * makeName(unsigned int i) {
  char * fn;

  fn = MALLOC(strlen(UPLOAD_PREFIX "/FSUITEST") + 14);
  SNPRINTF(fn,
	   strlen(UPLOAD_PREFIX "/FSUITEST") + 14,
	   UPLOAD_PREFIX "/FSUITEST%u",
	   i);
  disk_directory_create_for_file(NULL, fn);
  return fn;
}

static struct FSUI_Context * ctx;
static struct ECRS_URI * upURI;
static struct FSUI_DownloadList * download;
static int have_error;

/**
 * Set to 1 if we are about to stop the search and
 * thus our simple tests for download event correctness
 * would not work correctly.
 */
static int no_check;

static void * eventCallback(void * cls,
			    const FSUI_Event * event) {
  if (no_check)
    return NULL;
  switch(event->type) {
  case FSUI_download_suspended:
    if (event->data.DownloadSuspended.dc.spos != NULL) {
      fprintf(stderr,
	      "Download suspended but search reference not set correctly.\n");
      have_error = 1;
    }
    if ( (event->data.DownloadSuspended.dc.pos == download) &&
	 (event->data.DownloadSuspended.dc.ppos != NULL) ) {
      fprintf(stderr,
	      "Download suspended but parent reference not set to NULL.\n");
      have_error = 1;
    }
    if ( (event->data.DownloadSuspended.dc.pos != download) &&
	 (event->data.DownloadSuspended.dc.ppos != download) ) {
      fprintf(stderr,
	      "Download suspended but parent reference not set correctly (%p instead of %p).\n",
	      event->data.DownloadSuspended.dc.ppos,
	      download);
      have_error = 1;
    }
    if (event->data.DownloadSuspended.dc.pos == download)
      download = NULL;
    break;
  case FSUI_download_resumed:
    if (download == NULL)
      download = event->data.DownloadResumed.dc.pos;
    if (event->data.DownloadResumed.dc.spos != NULL) {
      fprintf(stderr,
	      "Download resuming but search reference not set correctly.\n");
      have_error = 1;
    }
    if ( (event->data.DownloadResumed.dc.pos == download) &&
	 (event->data.DownloadResumed.dc.ppos != NULL) ) {
      fprintf(stderr,
	      "Download resuming but parent reference not set to NULL.\n");
      have_error = 1;
    }
    if ( (event->data.DownloadResumed.dc.pos != download) &&
	 (event->data.DownloadResumed.dc.ppos != download) ) {
      fprintf(stderr,
	      "Download resuming but parent reference not set correctly.\n");
      have_error = 1;
    }
#if DEBUG_VERBOSE
    printf("Download resuming\n");
#endif
    break;
  case FSUI_upload_progress:
#if DEBUG_VERBOSE
    printf("Upload is progressing (%llu/%llu)...\n",
	   event->data.UploadProgress.completed,
	   event->data.UploadProgress.total);
#endif
    break;
  case FSUI_upload_completed:
    if (upURI != NULL)
      ECRS_freeUri(upURI);
    upURI = ECRS_dupUri(event->data.UploadCompleted.uri);
#if DEBUG_VERBOSE
    printf("Upload complete.\n");
#endif
    break;
  case FSUI_download_completed:
    if (event->data.DownloadCompleted.dc.spos != NULL) {
      fprintf(stderr,
	      "Download completed but search reference not set correctly.\n");
      have_error = 1;
    }
    if ( (event->data.DownloadCompleted.dc.pos == download) &&
	 (event->data.DownloadCompleted.dc.ppos != NULL) ) {
      fprintf(stderr,
	      "Download completed but parent reference not set to NULL.\n");
      have_error = 1;
    }
    if ( (event->data.DownloadCompleted.dc.pos != download) &&
	 (event->data.DownloadCompleted.dc.ppos != download) ) {
      fprintf(stderr,
	      "Download completed but parent reference not set correctly.\n");
      have_error = 1;
    }
#if DEBUG_VERBOSE
    printf("Download complete.\n");
#endif
   break;
  case FSUI_download_progress:
    if (event->data.DownloadResumed.dc.spos != NULL) {
      fprintf(stderr,
	      "Download progressing but search reference not set correctly.\n");
      have_error = 1;
    }
    if ( (event->data.DownloadResumed.dc.pos == download) &&
	 (event->data.DownloadResumed.dc.ppos != NULL) ) {
      fprintf(stderr,
	      "Download progressing but parent reference not set to NULL.\n");
      have_error = 1;
    }
    if ( (event->data.DownloadResumed.dc.pos != download) &&
	 (event->data.DownloadResumed.dc.ppos != download) ) {
      fprintf(stderr,
	      "Download progressing but parent reference not set correctly.\n");
      have_error = 1;
    }
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
  case FSUI_unindex_completed:
#if DEBUG_VERBOSE
    printf("Unindex complete.\n");
#endif
    break;
  case FSUI_unindex_error:
  case FSUI_upload_error:
  case FSUI_download_error:
  case FSUI_search_error:
    fprintf(stderr,
	    "Received ERROR: %d\n",
	    event->type);
    GE_BREAK(ectx, 0);
    break;
  case FSUI_download_aborted:
#if DEBUG_VERBOSE
    printf("Received download aborted event.\n");
#endif
    break;
  case FSUI_unindex_suspended:
  case FSUI_upload_suspended:
#if DEBUG_VERBOSE
    fprintf(stderr,
	    "Received SUSPENDING: %d\n",
	    event->type);
#endif
    break;
  case FSUI_download_started:
    if (download == NULL)
      download = event->data.DownloadStarted.dc.pos;
    if (event->data.DownloadStarted.dc.spos != NULL) {
      fprintf(stderr,
	      "Download started but search reference not set correctly.\n");
      have_error = 1;
    }
    if ( (event->data.DownloadStarted.dc.pos == download) &&
	 (event->data.DownloadStarted.dc.ppos != NULL) ) {
      fprintf(stderr,
	      "Download started but parent reference not set to NULL.\n");
      have_error = 1;
    }
    if ( (event->data.DownloadStarted.dc.pos != download) &&
	 (event->data.DownloadStarted.dc.ppos != download) ) {
      fprintf(stderr,
	      "Download started but parent reference not set correctly.\n");
      have_error = 1;
    }
    break;
  case FSUI_download_stopped:
    if (event->data.DownloadStopped.dc.spos != NULL) {
      fprintf(stderr,
	      "Download stopped but search reference not set correctly.\n");
      have_error = 1;
    }
    if ( (event->data.DownloadStopped.dc.pos == download) &&
	 (event->data.DownloadStopped.dc.ppos != NULL) ) {
      fprintf(stderr,
	      "Download stopped but parent reference not set to NULL.\n");
      have_error = 1;
    }
    if ( (event->data.DownloadStopped.dc.pos != download) &&
	 (event->data.DownloadStopped.dc.ppos != download) ) {
      fprintf(stderr,
	      "Download stopped but parent reference not set correctly.\n");
      have_error = 1;
    }
    break;
  case FSUI_upload_started:
  case FSUI_upload_stopped:
  case FSUI_search_started:
  case FSUI_search_aborted:
  case FSUI_search_stopped:
  case FSUI_unindex_started:
  case FSUI_unindex_stopped:
    break;
  default:
    printf("Unexpected event: %d\n",
	   event->type);
    break;
  }
  return NULL;
}

#define FILESIZE (1024)

#define START_DAEMON 1

int main(int argc, char * argv[]){
#if START_DAEMON
  pid_t daemon;
#endif
  int ok;
  int i;
  int j;
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
  struct GC_Configuration * cfg;
  struct FSUI_UnindexList * unindex = NULL;
  struct FSUI_UploadList * upload = NULL;
  int suspendRestart = 0;


  ok = YES;
  cfg = GC_create_C_impl();
  if (-1 == GC_parse_configuration(cfg,
				   "check.conf")) {
    GC_free(cfg);
    return -1;
  }
#if START_DAEMON
  daemon  = os_daemon_start(NULL,
			    cfg,
			    "peer.conf",
			    NO);
  GE_ASSERT(NULL, daemon > 0);
  CHECK(OK == connection_wait_for_running(NULL,
					  cfg,
					  30 * cronSECONDS));
  PTHREAD_SLEEP(5 * cronSECONDS); /* give apps time to start */
  /* ACTUAL TEST CODE */
#endif
  ctx = FSUI_start(NULL,
		   cfg,
		   "serializetest4",
		   32,
		   YES,
		   &eventCallback,
		   NULL);
  CHECK(ctx != NULL);
  for (j=4;j<16;j+=4) {
    fn = makeName(j);
    buf = MALLOC(FILESIZE * j);
    for (i=0;i<FILESIZE;i++)
      buf[i] = weak_randomi(256);
    disk_file_write(ectx,
		    fn,
		    buf,
		    FILESIZE,
		    "600");
    FREE(buf);
    FREE(fn);
  }
  meta = ECRS_createMetaData();
  kuri = ECRS_parseListKeywordURI(ectx,
				  2,
				  (const char**)keywords);
  ECRS_addToMetaData(meta,
		     EXTRACTOR_MIMETYPE,
		     GNUNET_DIRECTORY_MIME);
  upload = FSUI_startUpload(ctx,
			    UPLOAD_PREFIX,
			    (DirectoryScanCallback) &disk_directory_scan,
			    NULL,		
			    0,
			    0,
			    YES,
			    NO,
			    NO,
			    get_time() + 5 * cronHOURS,
			    meta,
			    kuri,
			    kuri);
  CHECK(upload != NULL);
  ECRS_freeUri(kuri);
  kuri = NULL;
  FSUI_stopUpload(ctx, upload);
  SNPRINTF(keyword,
	   40,
	   "%s %s %s",
	   keywords[0],
	   _("AND"),
	   keywords[1]);
  uri = ECRS_parseCharKeywordURI(ectx,
				 keyword);
  download = FSUI_startDownload(ctx,
				0,
				YES,
				upURI,
				meta,
				UPLOAD_PREFIX "-download",
				NULL,
				NULL);
  ECRS_freeMetaData(meta);
  prog = 0;
  suspendRestart = 10;
  while (prog < 1000) {
    prog++;
    PTHREAD_SLEEP(50 * cronMILLIS);
    if ( (suspendRestart > 0) &&
	 (weak_randomi(100) == 0) ) {
#if 1
#if DEBUG_VERBOSE
      printf("Testing FSUI suspend-resume\n");
#endif
      FSUI_stop(ctx); /* download possibly incomplete
			 at this point, thus testing resume */
      CHECK(download == NULL);
      ctx = FSUI_start(NULL,
		       cfg,
		       "serializetest4",
		       32,
		       YES,
		       &eventCallback,
		       NULL);
#if DEBUG_VERBOSE
      printf("Resumed...\n");
#endif
#endif
      suspendRestart--;
    }
    if (GNUNET_SHUTDOWN_TEST() == YES)
      break;
  }
  FSUI_stopDownload(ctx,
		    download);
  for (j=4;j<16;j+=4) {
    fn = makeName(j);
    unindex = FSUI_startUnindex(ctx, fn);
    FSUI_stopUnindex(ctx,
		     unindex);
    UNLINK(fn);
    FREE(fn);
  }
  /* END OF TEST CODE */
 FAILURE:
  if (ctx != NULL)
    FSUI_stop(ctx);
  if (uri != NULL)
    ECRS_freeUri(uri);
  if (kuri != NULL)
    ECRS_freeUri(kuri);
  if (upURI != NULL)
    ECRS_freeUri(upURI);

#if START_DAEMON
  GE_BREAK(NULL, OK == os_daemon_stop(NULL, daemon));
#endif
  GC_free(cfg);
  if (have_error)
    ok = NO;
  return (ok == YES) ? 0 : 1;
}

/* end of serializetest4.c */
