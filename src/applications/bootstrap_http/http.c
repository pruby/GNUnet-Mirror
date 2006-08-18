/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file bootstrap_http/http.c
 * @brief HOSTLISTURL support.  Downloads hellos via http.
 * @author Christian Grothoff
 *
 * TODO:
 * make use of curls multi-API to make the http download
 * interruptable (use select & test for terminate callback
 * -- PTHREAD_STOP_SLEEP should interrupt select
 * as well! -- and if not, we can use a small timeout).
 */

#include "platform.h"
#include "gnunet_core.h"
#include "gnunet_protocols.h"
#include "gnunet_bootstrap_service.h"
#include "gnunet_stats_service.h"

#include <curl/curl.h>

/**
 * Stats service (maybe NULL!)
 */
static Stats_ServiceAPI * stats;

static CoreAPIForApplication * coreAPI;

static int stat_hellodownloaded;

static struct GE_Context * ectx;

typedef struct {
  bootstrap_hello_callback callback;
  void * arg;
  bootstrap_terminate_callback termTest;
  void * targ;
  char * buf;
  size_t bsize;
  const char * url;
} BootstrapContext;


/**
 * Process downloaded bits by calling callback on each hello.
 */
static size_t
downloadHostlistHelper(void * ptr,
		       size_t size,
		       size_t nmemb, 
		       void * stream) {
  BootstrapContext * bctx = ptr;
  size_t osize;
  size_t total;
  P2P_hello_MESSAGE * helo;
  unsigned int hs;

  if (size * nmemb == 0)
    return 0; /* ok, no data */
  osize = bctx->bsize;
  total = size * nmemb + osize; 
  GROW(bctx->buf,
       bctx->bsize,
       total);
  memcpy(&bctx->buf[osize],
	 stream,
	 size * nmemb);
  while ( (bctx->bsize > sizeof(P2P_hello_MESSAGE)) &&
	  (bctx->termTest(bctx->targ)) ) {
    helo = (P2P_hello_MESSAGE*) &bctx->buf[0];
    if (bctx->bsize < P2P_hello_MESSAGE_size(helo))
      break;
    if ( (ntohs(helo->header.type) != p2p_PROTO_hello) ||
	 (P2P_hello_MESSAGE_size(helo) >= MAX_BUFFER_SIZE) ) {
      GE_LOG(ectx,
	     GE_WARNING | GE_USER | GE_REQUEST,
	     _("Bootstrap data obtained from `%s' is invalid.\n"),
	     bctx->url);
      return 0; /* Error: invalid format! */
    }
    hs = P2P_hello_MESSAGE_size(helo);
    helo->header.size = htons(hs);
    if (stats != NULL)
      stats->change(stat_hellodownloaded,
		    1);
    bctx->callback(helo,
		   bctx->arg);
    memmove(&bctx->buf[0],
	    &bctx->buf[hs],
	    bctx->bsize - hs);
    GROW(bctx->buf,
	 bctx->bsize,
	 bctx->bsize - hs);
  }
  return size * nmemb;
}


static void downloadHostlist(bootstrap_hello_callback callback,
			     void * arg,
			     bootstrap_terminate_callback termTest,
			     void * targ) {
  BootstrapContext bctx;
  char * url;
  char * proxy;
  CURL * curl;

  bctx.callback = callback;
  bctx.arg = arg;
  bctx.termTest = termTest;
  bctx.targ = targ;
  bctx.buf = NULL;
  bctx.bsize = 0;
  if (0 != GC_get_configuration_value_string(coreAPI->cfg,
					     "GNUNETD",
					     "HOSTLISTURL",
					     NULL,
					     &url)) {
    GE_LOG(ectx,
	   GE_WARNING | GE_BULK | GE_USER,
	   _("No hostlist URL specified in configuration, will not bootstrap.\n"));
    return;
  }  
  bctx.url = url;
  proxy = NULL;
  GC_get_configuration_value_string(coreAPI->cfg,
				    "GNUNETD",
				    "HTTP-PROXY",
				    NULL,
				    &proxy);
  curl = curl_easy_init();
  curl_easy_setopt(curl, 
		   CURLOPT_WRITEFUNCTION,
		   &downloadHostlistHelper);
  curl_easy_setopt(curl, 
		   CURLOPT_WRITEDATA,
		   &bctx);
  curl_easy_setopt(curl, 
		   CURLOPT_FAILONERROR,
		   1);
  curl_easy_setopt(curl, 
		   CURLOPT_URL,
		   url);
  if (proxy != NULL)
    curl_easy_setopt(curl, 
		     CURLOPT_PROXY,
		     proxy);
  curl_easy_setopt(curl, 
		   CURLOPT_BUFFERSIZE,
		   1024); /* a bit more than one HELLO */
  if (0 == strncmp(url, "http", 4))
    curl_easy_setopt(curl, 
		     CURLOPT_USERAGENT,
		     "GNUnet");
  curl_easy_setopt(curl, 
		   CURLOPT_CONNECTTIMEOUT,
		   15L);
  curl_easy_perform(curl);
  curl_easy_cleanup(curl);
  FREE(url);
  FREE(proxy);
}


Bootstrap_ServiceAPI *
provide_module_bootstrap(CoreAPIForApplication * capi) {
  static Bootstrap_ServiceAPI api;

  if (0 != curl_global_init(CURL_GLOBAL_ALL))
    return NULL;
  coreAPI = capi;
  stats = coreAPI->requestService("stats");
  if (stats != NULL) {
    stat_hellodownloaded
      = stats->create(gettext_noop("# hellos downloaded via http"));
  }
  api.bootstrap = &downloadHostlist;
  return &api;
}

void release_module_bootstrap() {
  if (stats != NULL)
    coreAPI->releaseService(stats);
  coreAPI = NULL;
}

/* end of http.c */
