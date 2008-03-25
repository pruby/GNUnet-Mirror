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
#include "gnunet_util.h"
#include "gnunet_core.h"
#include "gnunet_protocols.h"
#include "gnunet_bootstrap_service.h"
#include "gnunet_stats_service.h"
#include "gnunet_transport_service.h"

#include <curl/curl.h>

/**
 * Stats service (maybe NULL!)
 */
static GNUNET_Stats_ServiceAPI *stats;

static GNUNET_Transport_ServiceAPI *transport;

static GNUNET_CoreAPIForPlugins *coreAPI;

static int stat_hellodownloaded;

static struct GNUNET_GE_Context *ectx;

typedef struct
{

  GNUNET_BootstrapHelloCallback callback;

  void *arg;

  GNUNET_BootstrapTerminateCallback termTest;

  void *targ;

  char *buf;

  unsigned int bsize;

  const char *url;

  unsigned long long total;

} BootstrapContext;

#ifndef MINGW
#define USE_MULTI GNUNET_YES
#else
  /* FIXME: plibc needs to know about handle types in SELECT(),
     figure out whether curl only returns sockets from
     curl_multi_fdset() */
#define USE_MULTI GNUNET_NO
#endif

/**
 * Process downloaded bits by calling callback on each hello.
 */
static size_t
downloadHostlistHelper (void *ptr, size_t size, size_t nmemb, void *ctx)
{
  BootstrapContext *bctx = ctx;
  size_t osize;
  unsigned int total;
  const GNUNET_MessageHello *hello;
  unsigned int hs;

  bctx->total += size * nmemb;
  if (size * nmemb == 0)
    return 0;                   /* ok, no data */
  osize = bctx->bsize;
  total = size * nmemb + osize;
  GNUNET_array_grow (bctx->buf, bctx->bsize, total);
  memcpy (&bctx->buf[osize], ptr, size * nmemb);
  while ((bctx->bsize >= sizeof (GNUNET_MessageHello)) &&
         (bctx->termTest (bctx->targ)))
    {
      hello = (const GNUNET_MessageHello *) &bctx->buf[0];
      hs = ntohs (hello->header.size);
      if (bctx->bsize < hs)
        break;                  /* incomplete */
      if ((ntohs (hello->header.type) != GNUNET_P2P_PROTO_HELLO) ||
          (ntohs (hello->header.size) != GNUNET_sizeof_hello (hello)) ||
          (GNUNET_sizeof_hello (hello) >= GNUNET_MAX_BUFFER_SIZE))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_USER |
                         GNUNET_GE_IMMEDIATE,
                         _("Bootstrap data obtained from `%s' is invalid.\n"),
                         bctx->url);
          return 0;             /* Error: invalid format! */
        }
      if (stats != NULL)
        stats->change (stat_hellodownloaded, 1);
      bctx->callback (hello, bctx->arg);
      memmove (&bctx->buf[0], &bctx->buf[hs], bctx->bsize - hs);
      GNUNET_array_grow (bctx->buf, bctx->bsize, bctx->bsize - hs);
    }
  return size * nmemb;
}

#define CURL_EASY_SETOPT(c, a, b) do { ret = curl_easy_setopt(c, a, b); if (ret != CURLE_OK) GNUNET_GE_LOG(ectx, GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK, _("%s failed at %s:%d: `%s'\n"), "curl_easy_setopt", __FILE__, __LINE__, curl_easy_strerror(ret)); } while (0);


static void
downloadHostlist (GNUNET_BootstrapHelloCallback callback,
                  void *arg,
                  GNUNET_BootstrapTerminateCallback termTest, void *targ)
{
  BootstrapContext bctx;
  unsigned long long protocols;
  char *url;
  char *purl;
  char *proxy;
  CURL *curl;
  CURLcode ret;
#if USE_MULTI
  CURLM *multi;
  CURLMcode mret;
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  int sret;
  struct timeval tv;
  int running;
  struct CURLMsg *msg;
#endif
  unsigned int urls;
  size_t pos;
  int i;

  if (0 != curl_global_init (CURL_GLOBAL_WIN32))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return;
    }
  bctx.callback = callback;
  bctx.arg = arg;
  bctx.termTest = termTest;
  bctx.targ = targ;
  bctx.buf = NULL;
  bctx.bsize = 0;
  curl = curl_easy_init ();
#if USE_MULTI
  multi = NULL;
#endif
  if (curl == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return;
    }
  url = NULL;
  if (0 != GNUNET_GC_get_configuration_value_string (coreAPI->cfg,
                                                     "GNUNETD",
                                                     "HOSTLISTURL", "", &url))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("No hostlist URL specified in configuration, will not bootstrap.\n"));
      GNUNET_free (url);
      curl_easy_cleanup (curl);
      return;
    }
  urls = 0;
  if (strlen (url) > 0)
    {
      urls++;
      pos = strlen (url) - 1;
      while (pos > 0)
        {
          if (url[pos] == ' ')
            urls++;
          pos--;
        }
    }
  if (urls == 0)
    {
      GNUNET_free (url);
      curl_easy_cleanup (curl);
      return;
    }
  urls = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, urls) + 1;
  pos = strlen (url) - 1;
  while (pos > 0)
    {
      if (url[pos] == ' ')
        {
          urls--;
          url[pos] = '\0';
        }
      if (urls == 0)
        {
          pos++;
          break;
        }
      pos--;
    }
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_INFO | GNUNET_GE_BULK | GNUNET_GE_USER,
                 _("Bootstrapping using `%s'.\n"), url);
  purl = GNUNET_malloc (strlen (url) + 40);
  protocols = 0;
  for (i = GNUNET_TRANSPORT_PROTOCOL_NUMBER_MAX;
       i > GNUNET_TRANSPORT_PROTOCOL_NUMBER_NAT; i--)
    {
      if (transport == NULL)
        protocols |= (1LL << i);
      else if (transport->test_available ((unsigned short) i))
        protocols |= (1LL << i);
    }
  sprintf (purl, "%s?p=%llu", url, protocols);
  GNUNET_free (url);
  url = purl;
  bctx.url = url;
  bctx.total = 0;
  proxy = NULL;
  GNUNET_GC_get_configuration_value_string (coreAPI->cfg,
                                            "GNUNETD", "HTTP-PROXY", "",
                                            &proxy);
  CURL_EASY_SETOPT (curl, CURLOPT_WRITEFUNCTION, &downloadHostlistHelper);
  CURL_EASY_SETOPT (curl, CURLOPT_WRITEDATA, &bctx);
  if (ret != CURLE_OK)
    goto cleanup;
  CURL_EASY_SETOPT (curl, CURLOPT_FAILONERROR, 1);
  CURL_EASY_SETOPT (curl, CURLOPT_URL, &url[pos]);
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_BULK,
                 _("Trying to download hostlist from `%s'\n"), &url[pos]);
  if (strlen (proxy) > 0)
    CURL_EASY_SETOPT (curl, CURLOPT_PROXY, proxy);
  CURL_EASY_SETOPT (curl, CURLOPT_BUFFERSIZE, 1024);    /* a bit more than one HELLO */
  if (0 == strncmp (&url[pos], "http", 4))
    CURL_EASY_SETOPT (curl, CURLOPT_USERAGENT, "GNUnet");
  CURL_EASY_SETOPT (curl, CURLOPT_CONNECTTIMEOUT, 150L);
  /* NOTE: use of CONNECTTIMEOUT without also
     setting NOSIGNAL results in really weird
     crashes on my system! */
  CURL_EASY_SETOPT (curl, CURLOPT_NOSIGNAL, 1);
#if USE_MULTI
  multi = curl_multi_init ();
  if (multi == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      goto cleanup;
    }
  mret = curl_multi_add_handle (multi, curl);
  if (mret != CURLM_OK)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK, _("%s failed at %s:%d: `%s'\n"),
                     "curl_multi_add_handle", __FILE__, __LINE__,
                     curl_multi_strerror (mret));
      goto cleanup;
    }
  while ((GNUNET_YES == termTest (targ))
         && (GNUNET_shutdown_test () == GNUNET_NO))
    {
      max = 0;
      FD_ZERO (&rs);
      FD_ZERO (&ws);
      FD_ZERO (&es);
      mret = curl_multi_fdset (multi, &rs, &ws, &es, &max);
      if (mret != CURLM_OK)
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                         GNUNET_GE_BULK, _("%s failed at %s:%d: `%s'\n"),
                         "curl_multi_fdset", __FILE__, __LINE__,
                         curl_multi_strerror (mret));
          goto cleanup;
        }
      /* use timeout of 1s in case that SELECT is not interrupted by
         signal (just to increase portability a bit) -- better a 1s
         delay in the reaction than hanging... */
      tv.tv_sec = 0;
      tv.tv_usec = 1000;
      sret = SELECT (max + 1, &rs, &ws, &es, &tv);
      if (sret == -1)
        {
          GNUNET_GE_LOG_STRERROR (ectx,
                                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                  GNUNET_GE_USER | GNUNET_GE_BULK, "select");
          goto cleanup;
        }
      if (GNUNET_YES != termTest (targ))
        break;
      do
        {
          running = 0;
          mret = curl_multi_perform (multi, &running);
          if (running == 0)
            {
              do
                {
                  msg = curl_multi_info_read (multi, &running);
                  GNUNET_GE_BREAK (ectx, msg != NULL);
                  if (msg == NULL)
                    break;
                  switch (msg->msg)
                    {
                    case CURLMSG_DONE:
                      if (msg->data.result != CURLE_OK)
                        GNUNET_GE_LOG (ectx,
                                       GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                       GNUNET_GE_USER | GNUNET_GE_BULK,
                                       _("%s failed at %s:%d: `%s'\n"),
                                       "curl_multi_perform", __FILE__,
                                       __LINE__,
                                       curl_easy_strerror (msg->data.result));
                      break;
                    default:
                      break;
                    }
                }
              while (running > 0);
              break;
            }
        }
      while ((mret == CURLM_CALL_MULTI_PERFORM)
             && (GNUNET_YES == termTest (targ)));
      if ((mret != CURLM_OK) && (mret != CURLM_CALL_MULTI_PERFORM))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                         GNUNET_GE_BULK, _("%s failed at %s:%d: `%s'\n"),
                         "curl_multi_perform", __FILE__, __LINE__,
                         curl_multi_strerror (mret));
          goto cleanup;
        }
      if (running == 0)
        break;
    }
  mret = curl_multi_remove_handle (multi, curl);
  if (mret != CURLM_OK)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_DEVELOPER |
                     GNUNET_GE_BULK, _("%s failed at %s:%d: `%s'\n"),
                     "curl_multi_remove_handle", __FILE__, __LINE__,
                     curl_multi_strerror (mret));
      goto cleanup;
    }
#else
  ret = curl_easy_perform (curl);
  if (ret != CURLE_OK)
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_DEVELOPER |
                   GNUNET_GE_BULK, _("%s failed at %s:%d: `%s'\n"),
                   "curl_easy_perform", __FILE__, __LINE__,
                   curl_easy_strerror (ret));
#endif
  curl_easy_cleanup (curl);
#if USE_MULTI
  mret = curl_multi_cleanup (multi);
  if (mret != CURLM_OK)
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_DEVELOPER |
                   GNUNET_GE_BULK, _("%s failed at %s:%d: `%s'\n"),
                   "curl_multi_cleanup", __FILE__, __LINE__,
                   curl_multi_strerror (mret));
#endif
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_INFO | GNUNET_GE_BULK | GNUNET_GE_USER,
                 _("Downloaded %llu bytes from `%s'.\n"), bctx.total, url);
  GNUNET_free (url);
  GNUNET_free (proxy);
  curl_global_cleanup ();
  return;
cleanup:
  GNUNET_GE_BREAK (ectx, ret != CURLE_OK);
#if USE_MULTI
  if (multi != NULL)
    curl_multi_remove_handle (multi, curl);
#endif
  curl_easy_cleanup (curl);
#if USE_MULTI
  if (multi != NULL)
    curl_multi_cleanup (multi);
#endif
  GNUNET_free (url);
  GNUNET_free (proxy);
  curl_global_cleanup ();
}


GNUNET_Bootstrap_ServiceAPI *
provide_module_bootstrap (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_Bootstrap_ServiceAPI api;

  coreAPI = capi;
  ectx = capi->ectx;
  transport = coreAPI->service_request ("transport");
  stats = coreAPI->service_request ("stats");
  if (stats != NULL)
    {
      stat_hellodownloaded
        = stats->create (gettext_noop ("# HELLOs downloaded via http"));
    }
  api.bootstrap = &downloadHostlist;
  return &api;
}

void
release_module_bootstrap ()
{
  if (stats != NULL)
    coreAPI->service_release (stats);
  if (transport != NULL)
    coreAPI->service_release (transport);
  transport = NULL;
  coreAPI = NULL;
}

/* end of http.c */
