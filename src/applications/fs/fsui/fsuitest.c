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
 * @file applications/fs/fsui/fsuitest.c
 * @brief testcase for fsui (upload-download)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"

#define DEBUG_VERBOSE NO

#define CHECK(a) if (!(a)) { ok = NO; GE_BREAK(NULL, 0); goto FAILURE; }

static char * makeName(unsigned int i) {
  char * fn;

  fn = MALLOC(strlen("/tmp/gnunet-fsui-serializetest/FSUITEST") + 14);
  SNPRINTF(fn,
	   strlen("/tmp/gnunet-fsui-test/FSUITEST") + 14,
	   "/tmp/gnunet-fsui-test/FSUITEST%u",
	   i);
  disk_directory_create_for_file(NULL, fn);
  return fn;
}

static volatile enum FSUI_EventType lastEvent;

static struct FSUI_Context * ctx;

static struct FSUI_DownloadList * download;

static void * eventCallback(void * cls,
			    const FSUI_Event * event) {
  static char unused;
  char * fn;

  switch(event->type) {
  case FSUI_search_resumed:
  case FSUI_download_resumed:
  case FSUI_upload_resumed:
  case FSUI_unindex_resumed:
    return &unused;
  case FSUI_search_result:
#if DEBUG_VERBOSE
    printf("Received search result\n");
#endif
    fn = makeName(43);
    download = FSUI_startDownload(ctx,
				  0,
				  NO,
				  event->data.SearchResult.fi.uri,
				  event->data.SearchResult.fi.meta,
				  fn,
				  NULL,
				  NULL);
    FREE(fn);
    break;
  case FSUI_upload_completed:
#if DEBUG_VERBOSE
    printf("Upload complete.\n");
#endif
    break;
  case FSUI_download_completed:
#if DEBUG_VERBOSE
    printf("Download complete.\n");
#endif
    break;
  case FSUI_unindex_completed:
#if DEBUG_VERBOSE
    printf("Unindex complete.\n");
#endif
    break;
  default:
    break;
  }
  lastEvent = event->type;
  return NULL;
}

#define START_DAEMON 1

int main(int argc, char * argv[]){
#if START_DAEMON
  pid_t daemon;
#endif
  int ok;
  struct ECRS_URI * uri;
  char * filename = NULL;
  char * keywords[] = {
    "fsui_foo",
    "fsui_bar",
    NULL,
  };
  char keyword[40];
  int prog;
  struct ECRS_MetaData * meta;
  struct ECRS_URI * kuri;
  struct GC_Configuration * cfg;
  struct FSUI_UploadList * upload;
  struct FSUI_SearchList * search;
  struct FSUI_UnindexList * unindex;

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
					  60 * cronSECONDS));
#endif
  PTHREAD_SLEEP(5 * cronSECONDS); /* give apps time to start */
  ok = YES;

  /* ACTUAL TEST CODE */
  ctx = FSUI_start(NULL,
		   cfg,
		   "fsuitest",
		   32, /* thread pool size */
		   NO, /* no resume */
		   &eventCallback,
		   NULL);
  CHECK(ctx != NULL);
  filename = makeName(42);
  disk_file_write(NULL,
		  filename,
		  "foo bar test!",
		  strlen("foo bar test!"),
		  "600");
  meta = ECRS_createMetaData();
  kuri = ECRS_parseListKeywordURI(NULL,
				  2,
				  (const char**)keywords);
  upload = FSUI_startUpload(ctx,
			    filename,
			    (DirectoryScanCallback) &disk_directory_scan,
			    NULL,
			    0, /* anonymity */
			    0, /* priority */
			    YES,
			    NO,
			    NO,
			    get_time() + 5 * cronHOURS,
			    meta,
			    kuri,
			    kuri);
  CHECK(upload != NULL);
  ECRS_freeUri(kuri);
  ECRS_freeMetaData(meta);
  prog = 0;
  while (lastEvent != FSUI_upload_completed) {
    prog++;
    CHECK(prog < 10000)

    PTHREAD_SLEEP(50 * cronMILLIS);
    if (GNUNET_SHUTDOWN_TEST() == YES)
      break;
  }
  SNPRINTF(keyword,
	   40,
	   "%s %s %s",
	   keywords[0],
	   _("AND"),
	   keywords[1]);
  uri = ECRS_parseCharKeywordURI(NULL,
				 keyword);
  search = FSUI_startSearch(ctx,
			    0,
			    100,
			    240 * cronSECONDS,
			    uri);
  ECRS_freeUri(uri);
  CHECK(search != NULL);
  prog = 0;
  while (lastEvent != FSUI_download_completed) {
    prog++;
    CHECK(prog < 10000);
    PTHREAD_SLEEP(50 * cronMILLIS);
    if (GNUNET_SHUTDOWN_TEST() == YES)
      break;
  }
  FSUI_abortSearch(ctx,
		   search);
  FSUI_stopSearch(ctx,
		  search);
  unindex = FSUI_startUnindex(ctx, filename);
  prog = 0;
  while (lastEvent != FSUI_unindex_completed) {
    prog++;
    CHECK(prog < 10000);
    PTHREAD_SLEEP(50 * cronMILLIS);
    if (GNUNET_SHUTDOWN_TEST() == YES)
      break;
  }
  if (lastEvent != FSUI_unindex_completed)
    FSUI_abortUnindex(ctx, unindex);
  FSUI_stopUnindex(ctx, unindex);


  /* END OF TEST CODE */
 FAILURE:
  if (ctx != NULL)
    FSUI_stop(ctx);
  if (filename != NULL) {
    UNLINK(filename);
    FREE(filename);
  }
  filename = makeName(43);
  /* TODO: verify file 'filename(42)' == file 'filename(43)' */
  UNLINK(filename);
  FREE(filename);

#if START_DAEMON
  GE_ASSERT(NULL, OK == os_daemon_stop(NULL, daemon));
#endif
  GC_free(cfg);

  return (ok == YES) ? 0 : 1;
}

/* end of fsuitest.c */
