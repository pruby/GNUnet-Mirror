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
 * @file applications/fs/fsui/searchtest.c
 * @brief testcase for fsui search persistence
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"

#define CHECK(a) if (!(a)) { ok = NO; GE_BREAK(NULL, 0); goto FAILURE; }

static char * makeName(unsigned int i) {
  const char * name;
  char * fn;

  name = "/tmp/gnunet-fsuisearchtest";
  disk_directory_create(NULL, name);
  fn = MALLOC(strlen(name) + 40);
  SNPRINTF(fn,
	   strlen(name) + 40,
	   "%s%sFSUITEST%u",
	   name,
	   DIR_SEPARATOR_STR,
	   i);
  return fn;
}

static volatile enum FSUI_EventType lastEvent;

static struct ECRS_URI * uri;

static struct FSUI_Context * ctx;

static void * eventCallback(void * cls,
			    const FSUI_Event * event) {
  static char unused;
 
  switch(event->type) {
  case FSUI_search_resumed:
  case FSUI_download_resumed:
  case FSUI_upload_resumed:
  case FSUI_unindex_resumed:
    return &unused;
  case FSUI_search_result:
    printf("Received search result\n");
    uri = ECRS_dupUri(event->data.SearchResult.fi.uri);
    break;
  case FSUI_upload_completed:
    printf("Upload complete.\n");
    break;
  case FSUI_download_completed:
    printf("Download complete.\n");
    break;
  case FSUI_unindex_completed:
    printf("Unindex complete.\n");
    break;
  case FSUI_upload_error:
    printf("Upload error.\n");
    break;
  case FSUI_download_error:
    printf("Download error.\n");
    break;
  case FSUI_unindex_error:
    printf("Unindex error.\n");
    break;
  default:
    break;
  }
  lastEvent = event->type;
  return NULL;
}


int main(int argc, char * argv[]){
  pid_t daemon;
  int ok;
  char * fn = NULL;
  char * keywords[] = {
    "search_foo",
    "search_bar",
    NULL,
  };
  char keyword[40];
  int prog;
  struct ECRS_MetaData * meta;
  struct ECRS_URI * kuri;
  struct GC_Configuration * cfg;
  struct FSUI_UploadList * upload;
  struct FSUI_UnindexList * unindex;
  struct FSUI_DownloadList * download;
  struct FSUI_SearchList * search;
  struct ECRS_URI * luri;

  ok = YES;
  cfg = GC_create_C_impl();
  if (-1 == GC_parse_configuration(cfg,
				   "check.conf")) {
    GC_free(cfg);
    return -1;  
  }
  daemon  = os_daemon_start(NULL,
			    cfg,
			    "peer.conf",
			    NO);
  GE_ASSERT(NULL, daemon > 0);
  GE_ASSERT(NULL, OK == connection_wait_for_running(NULL,
						    cfg,
						    30 * cronSECONDS));
  PTHREAD_SLEEP(5 * cronSECONDS); /* give apps time to start */
  /* ACTUAL TEST CODE */

  ctx = FSUI_start(NULL,
		   cfg,
		   "fsuisearchtest",
		   32,
		   YES,
		   &eventCallback,
		   NULL);
  CHECK(ctx != NULL);
  SNPRINTF(keyword,
	   40,
	   "%s %s %s",
	   keywords[0],
	   _("AND"),
	   keywords[1]);
  luri = ECRS_parseCharKeywordURI(NULL, keyword);
  search = FSUI_startSearch(ctx,
			    0,
			    luri);
  ECRS_freeUri(luri);
  uri = NULL;
  CHECK(NULL != search);
  FSUI_stop(ctx);
  /* resume search! */
  ctx = FSUI_start(NULL,
		   cfg,
		   "fsuisearchtest",
		   32,
		   YES,
		   &eventCallback,
		   NULL);
  fn = makeName(42);
  disk_file_write(NULL,
		  fn,
		  "foo bar test!",
		  strlen("foo bar test!"),
		  "600");
  meta = ECRS_createMetaData();
  kuri = ECRS_parseListKeywordURI(NULL,
				  2,
				  (const char**)keywords);
  upload = 
	FSUI_startUpload(ctx,
			 fn,
			 (DirectoryScanCallback) &disk_directory_scan,
			 NULL,		
			 0,
			 0,
			 YES,
			 NO,
			 NO,
			 meta,
			 kuri,
			 kuri);
  CHECK(NULL != upload);
  FREE(fn);
  fn = NULL;
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
  FSUI_stopUpload(ctx, upload);

  while (uri == NULL) {
    prog++;
    CHECK(prog < 10000)
    PTHREAD_SLEEP(500 * cronMILLIS);
  }
  FSUI_stopSearch(ctx,
		  search);
  CHECK(uri != NULL);
  fn = makeName(43);
  download = FSUI_startDownload(ctx,
				0,
				NO,
				uri,
				fn);
  FREE(fn);
  fn = NULL;
  ECRS_freeUri(uri);

  prog = 0;
  while (lastEvent != FSUI_download_completed) {
    prog++;
    CHECK(prog < 10000);
    PTHREAD_SLEEP(50 * cronMILLIS);
    if (GNUNET_SHUTDOWN_TEST() == YES)
      break;
  }
  FSUI_stopDownload(ctx, download);
  fn = makeName(42);
  unindex = FSUI_unindex(ctx, fn);
  FREE(fn);
  fn = NULL;
  CHECK(NULL != unindex);
  prog = 0;
  while (lastEvent != FSUI_unindex_completed) {
    prog++;
    CHECK(prog < 10000);
    PTHREAD_SLEEP(50 * cronMILLIS);
    if (GNUNET_SHUTDOWN_TEST() == YES)
      break;
  }
  FSUI_stopUnindex(ctx, unindex);

  /* END OF TEST CODE */
 FAILURE:
  if (ctx != NULL)
    FSUI_stop(ctx);
  FREENONNULL(fn);  
  /* TODO: verify file 'fn(42)' == file 'fn(43)' */
  fn = makeName(42);
  UNLINK(fn);
  FREE(fn);
  fn = makeName(43);
  UNLINK(fn);
  FREE(fn);

 
  GE_ASSERT(NULL, OK == os_daemon_stop(NULL, daemon));
  GC_free(cfg);
  return (ok == YES) ? 0 : 1;
}

/* end of searchtest.c */
