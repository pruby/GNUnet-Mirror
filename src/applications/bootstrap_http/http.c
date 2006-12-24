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
 */

#include "platform.h"
#include "gnunet_util_crypto.h"
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

  unsigned int bsize;

  const char * url;

} BootstrapContext;

#define USE_MULTI YES

/**
 * Process downloaded bits by calling callback on each hello.
 */
static size_t
downloadHostlistHelper(void * ptr,
		       size_t size,
		       size_t nmemb,
		       void * ctx) {
  BootstrapContext * bctx = ctx;
  size_t osize;
  unsigned int total;
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
	 ptr,
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

#define CURL_EASY_SETOPT(c, a, b) do { ret = curl_easy_setopt(c, a, b); if (ret != CURLE_OK) GE_LOG(ectx, GE_WARNING | GE_USER | GE_BULK, _("%s failed at %s:%d: `%s'\n"), "curl_easy_setopt", __FILE__, __LINE__, curl_easy_strerror(ret)); } while (0);


static void downloadHostlist(bootstrap_hello_callback callback,
			     void * arg,
			     bootstrap_terminate_callback termTest,
			     void * targ) {
  BootstrapContext bctx;
  char * url;
  char * proxy;
  CURL * curl;
  CURLcode ret;
#if USE_MULTI
  CURLM * multi;
  CURLMcode mret;
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  struct timeval tv;
  int running;
  struct CURLMsg * msg;
#endif
  unsigned int urls;
  size_t pos;

  if (0 != curl_global_init(CURL_GLOBAL_WIN32)) {
    GE_BREAK(ectx, 0);
    return;
  }
  bctx.callback = callback;
  bctx.arg = arg;
  bctx.termTest = termTest;
  bctx.targ = targ;
  bctx.buf = NULL;
  bctx.bsize = 0;
  curl = curl_easy_init();
#if USE_MULTI
  multi = NULL;
#endif
  if (curl == NULL) {
    GE_BREAK(ectx, 0);
    return;
  }
  url = NULL;
  if (0 != GC_get_configuration_value_string(coreAPI->cfg,
					     "GNUNETD",
					     "HOSTLISTURL",
					     "",
					     &url)) {
    GE_LOG(ectx,
	   GE_WARNING | GE_BULK | GE_USER,
	   _("No hostlist URL specified in configuration, will not bootstrap.\n"));
    FREE(url);
    curl_easy_cleanup(curl);
    return;
  }
  urls = 0;
  if (strlen(url) > 0) {
    urls++;
    pos = strlen(url) - 1;
    while (pos > 0) {
      if (url[pos] == ' ')
	urls++;
      pos--;
    }
  }
  if (urls == 0) {
    FREE(url);
    curl_easy_cleanup(curl);
    return;
  }
  urls = weak_randomi(urls) + 1;
  pos = strlen(url) - 1;
  while (pos > 0) {
    if (url[pos] == ' ') {
      urls--;
      url[pos] = '\0';
    }
    if (urls == 0) {
      pos++;
      break;
    }
    pos--;
  }
  bctx.url = url;
  proxy = NULL;
  GC_get_configuration_value_string(coreAPI->cfg,
				    "GNUNETD",
				    "HTTP-PROXY",
				    "",
				    &proxy);
  CURL_EASY_SETOPT(curl,
		   CURLOPT_WRITEFUNCTION,
		   &downloadHostlistHelper);
  CURL_EASY_SETOPT(curl,
		   CURLOPT_WRITEDATA,
		   &bctx);
  if (ret != CURLE_OK)
    goto cleanup;
  CURL_EASY_SETOPT(curl,
		   CURLOPT_FAILONERROR,
		   1);
  CURL_EASY_SETOPT(curl,
		   CURLOPT_URL,
		   &url[pos]);
  GE_LOG(ectx,
	 GE_INFO | GE_USER | GE_BULK,
	 _("Trying to download hostlist from `%s'\n"),
	 &url[pos]);
  if (strlen(proxy) > 0)
    CURL_EASY_SETOPT(curl,
		     CURLOPT_PROXY,
		     proxy);
  CURL_EASY_SETOPT(curl,
		   CURLOPT_BUFFERSIZE,
		   1024); /* a bit more than one HELLO */
  if (0 == strncmp(&url[pos], "http", 4))
    CURL_EASY_SETOPT(curl,
		     CURLOPT_USERAGENT,
		     "GNUnet");
  CURL_EASY_SETOPT(curl,
		   CURLOPT_CONNECTTIMEOUT,
		   150L);
  /* NOTE: use of CONNECTTIMEOUT without also
     setting NOSIGNAL results in really weird
     crashes on my system! */
  CURL_EASY_SETOPT(curl,
		   CURLOPT_NOSIGNAL,
		   1);
#if USE_MULTI
  multi = curl_multi_init();
  if (multi == NULL) {
    GE_BREAK(ectx, 0);
    goto cleanup;
  }
  mret = curl_multi_add_handle(multi, curl);
  if (mret != CURLM_OK) {
    GE_LOG(ectx,
	   GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
	   _("%s failed at %s:%d: `%s'\n"),
	   "curl_multi_add_handle",
	   __FILE__,
	   __LINE__,
	   curl_multi_strerror(mret));
    goto cleanup;
  }
  while ( (YES == termTest(targ)) &&
	  (GNUNET_SHUTDOWN_TEST() == NO) ) {
    max = 0;
    FD_ZERO(&rs);
    FD_ZERO(&ws);
    FD_ZERO(&es);
    mret = curl_multi_fdset(multi,
			    &rs,
			    &ws,
			    &es,
			    &max);
    if (mret != CURLM_OK) {
      GE_LOG(ectx,
	     GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
	     _("%s failed at %s:%d: `%s'\n"),
	     "curl_multi_fdset",
	     __FILE__,
	     __LINE__,
	     curl_multi_strerror(mret));
      goto cleanup;
    }
    /* use timeout of 1s in case that SELECT is not interrupted by
       signal (just to increase portability a bit) -- better a 1s
       delay in the reaction than hanging... */
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    SELECT(max + 1,
	   &rs,
	   &ws,
	   &es,
	   &tv);
    if (YES != termTest(targ))
      break;
    do {
      running = 0;
      mret = curl_multi_perform(multi, &running);
      if (running == 0) {
	do {
	  msg = curl_multi_info_read(multi,
				     &running);
	  GE_BREAK(ectx, msg != NULL);
	  if (msg == NULL)
	    break;
	  switch (msg->msg) {
	  case CURLMSG_DONE:
	    if (msg->data.result != CURLE_OK)
	      GE_LOG(ectx,
		     GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
		     _("%s failed at %s:%d: `%s'\n"),
		     "curl_multi_perform",
		     __FILE__,
		     __LINE__,
		   curl_easy_strerror(msg->data.result));
	    break;
	  default:
	    break;
	  }	
	} while (running > 0);
	break;
      }
    } while ( (mret == CURLM_CALL_MULTI_PERFORM) &&
	      (YES == termTest(targ)) );
    if ( (mret != CURLM_OK) &&
	 (mret != CURLM_CALL_MULTI_PERFORM) ) {
      GE_LOG(ectx,
	     GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
	     _("%s failed at %s:%d: `%s'\n"),
	     "curl_multi_perform",
	     __FILE__,
	     __LINE__,
	     curl_multi_strerror(mret));
      goto cleanup;
    }
    if (running == 0)
      break;
  }
  mret = curl_multi_remove_handle(multi, curl);
  if (mret != CURLM_OK) {
    GE_LOG(ectx,
	   GE_ERROR | GE_ADMIN | GE_DEVELOPER | GE_BULK,
	   _("%s failed at %s:%d: `%s'\n"),
	   "curl_multi_remove_handle",
	   __FILE__,
	   __LINE__,
	   curl_multi_strerror(mret));
    goto cleanup;
  }
#else
  ret = curl_easy_perform(curl);
  if (ret != CURLE_OK)
    GE_LOG(ectx,
	   GE_ERROR | GE_ADMIN | GE_DEVELOPER | GE_BULK,
	   _("%s failed at %s:%d: `%s'\n"),
	   "curl_easy_perform",
	   __FILE__,
	   __LINE__,
	   curl_easy_strerror(ret));
#endif
  curl_easy_cleanup(curl);
#if USE_MULTI
  mret = curl_multi_cleanup(multi);
  if (mret != CURLM_OK)
    GE_LOG(ectx,
	   GE_ERROR | GE_ADMIN | GE_DEVELOPER | GE_BULK,
	   _("%s failed at %s:%d: `%s'\n"),
	   "curl_multi_cleanup",
	   __FILE__,
	   __LINE__,
	   curl_multi_strerror(mret));
#endif
  FREE(url);
  FREE(proxy);
  curl_global_cleanup();
  return;
cleanup:
  GE_BREAK(ectx, ret != CURLE_OK);
#if USE_MULTI
  if (multi != NULL)
    curl_multi_remove_handle(multi, curl);
#endif
  curl_easy_cleanup(curl);
#if USE_MULTI
  if (multi != NULL)
    curl_multi_cleanup(multi);
#endif
  FREE(url);
  FREE(proxy);
  curl_global_cleanup();
}


Bootstrap_ServiceAPI *
provide_module_bootstrap(CoreAPIForApplication * capi) {
  static Bootstrap_ServiceAPI api;

  coreAPI = capi;
  ectx = capi->ectx;
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
