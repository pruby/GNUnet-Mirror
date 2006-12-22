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
 * @file applications/fs/fsui/serializetest3.c
 * @brief testcase for fsui download persistence for search
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"
#include "gnunet_util_crypto.h"

#define DEBUG_VERBOSE NO

#define UPLOAD_PREFIX "/tmp/gnunet-fsui-searializetest3"

#define CHECK(a) if (!(a)) { ok = NO; GE_BREAK(ectx, 0); goto FAILURE; }

static struct GE_Context * ectx;

static struct FSUI_Context * ctx;
static struct FSUI_SearchList * search;
static int have_error;

static void * eventCallback(void * cls,
			    const FSUI_Event * event) {
  switch(event->type) {
  case FSUI_search_suspended:
    search = NULL;
    break;
  case FSUI_search_resumed:
#if DEBUG_VERBOSE
    printf("Search resuming\n");
#endif
    search = event->data.SearchResumed.sc.pos;
    break;
  case FSUI_search_result:
#if DEBUG_VERBOSE
    printf("Received search result\n");
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
#if DEBUG_VERBOSE
    printf("Upload complete.\n");
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
  case FSUI_upload_started:
  case FSUI_upload_stopped:
  case FSUI_search_started:
  case FSUI_search_aborted:
  case FSUI_search_stopped:
  case FSUI_search_completed:
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
  struct ECRS_URI * uri = NULL;
  char * keywords[] = {
    "down_foo",
    "down_bar",
    NULL,
  };
  char keyword[40];
  int prog;
  struct GC_Configuration * cfg;
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
		   "serializetest3",
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
  uri = ECRS_parseCharKeywordURI(ectx,
				 keyword);
  search = FSUI_startSearch(ctx,
			    0,
			    100,
			    240 * cronSECONDS,
			    uri);
  CHECK(search != NULL);
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
      CHECK(search == NULL);
      ctx = FSUI_start(NULL,
		       cfg,
		       "serializetest3",
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
  FSUI_abortSearch(ctx,
		   search);
  FSUI_stopSearch(ctx,
		  search);
  search = NULL;
  /* END OF TEST CODE */
 FAILURE:
  if (ctx != NULL)
    FSUI_stop(ctx);
  if (uri != NULL)
    ECRS_freeUri(uri);

#if START_DAEMON
  GE_BREAK(NULL,
	   OK == os_daemon_stop(NULL, daemon));
#endif
  GC_free(cfg);
  if (have_error)
    ok = NO;
  return (ok == YES) ? 0 : 1;
}

/* end of serializetest3.c */
