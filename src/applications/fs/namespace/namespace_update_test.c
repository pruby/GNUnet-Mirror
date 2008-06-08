/*
     This file is part of GNUnet.
     (C) 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/fsui/namespace_infotest.c
 * @brief testcase for namespace_info.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_namespace_lib.h"

#define CHECK(a) if (!(a)) { ok = GNUNET_NO; GNUNET_GE_BREAK(ectx, 0); goto FAILURE; }

static struct GNUNET_GE_Context *ectx;

static char *root;

static int
iter (void *cls,
      const GNUNET_ECRS_FileInfo * uri,
      const char *lastId, const char *nextId)
{
  char **res = cls;
  if (0 == strcmp (lastId, root))
    (*res) = GNUNET_strdup (nextId);
  return GNUNET_OK;
}

static struct GNUNET_ECRS_URI *want;

static void *
eventProc (void *unused, const GNUNET_FSUI_Event * event)
{
  if (event->type != GNUNET_FSUI_search_result)
    return NULL;
  if ((want != NULL) &&
      (GNUNET_ECRS_uri_test_equal (event->data.SearchResult.fi.uri, want)))
    want = NULL;                /* got the desired result! */
  return NULL;
}

int
main (int argc, char *argv[])
{
  pid_t daemon;
  int ok;
  int tries;
  struct GNUNET_ECRS_URI *uri = NULL;
  struct GNUNET_ECRS_URI *euri = NULL;
  struct GNUNET_ECRS_URI *furi = NULL;
  struct GNUNET_MetaData *meta = NULL;
  GNUNET_HashCode nsid;
  char *thisId;
  struct GNUNET_FSUI_Context *ctx = NULL;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_FSUI_SearchList *sl = NULL;

  if (1)
    return 0;                   /* test disabled for now */
  GNUNET_disable_entropy_gathering ();
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  daemon = GNUNET_daemon_start (NULL, cfg, "peer.conf", GNUNET_NO);
  GNUNET_GE_ASSERT (NULL, daemon > 0);
  CHECK (GNUNET_OK ==
         GNUNET_wait_for_daemon_running (NULL, cfg,
                                         30 * GNUNET_CRON_SECONDS));
  ok = GNUNET_YES;
  GNUNET_thread_sleep (5 * GNUNET_CRON_SECONDS);        /* give apps time to start */

  /* ACTUAL TEST CODE */
  meta = GNUNET_meta_data_create ();
  GNUNET_meta_data_insert (meta, 0, "test");
  uri = GNUNET_NS_namespace_create (ectx,
                                    cfg,
                                    1,
                                    1,
                                    GNUNET_get_time () +
                                    10 * GNUNET_CRON_MINUTES, meta,
                                    NULL, "root");
  CHECK (uri != NULL);
  GNUNET_ECRS_uri_get_namespace_from_sks (uri, &nsid);
  /* publish original file */
  euri = GNUNET_NS_add_to_namespace (ectx,
                                     cfg,
                                     1,
                                     1,
                                     GNUNET_get_time () +
                                     10 * GNUNET_CRON_MINUTES, &nsid,
                                     "this", "next", uri, meta);
  CHECK (euri != NULL);
  /* get automatically selected "nextID" of original publication */
  thisId = NULL;
  GNUNET_NS_namespace_list_contents (ectx, cfg, &nsid, &iter, &thisId);
  CHECK (0 != strcmp ("next", thisId));
  GNUNET_free (thisId);
  /* publish update */
  furi = GNUNET_NS_add_to_namespace (ectx,
                                     cfg,
                                     1,
                                     1,
                                     GNUNET_get_time () +
                                     10 * GNUNET_CRON_MINUTES, &nsid,
                                     "next", "future", euri, meta);
  CHECK (furi != NULL);
  /* do namespace search for *original*
     content; hope to find update! */
  ctx =
    GNUNET_FSUI_start (ectx, cfg, "namespace-update-test", 16, GNUNET_NO,
                       &eventProc, NULL);
  CHECK (ctx != NULL);
  want = euri;
  sl = GNUNET_FSUI_search_start (ctx, 0, euri);
  /* will find "uri" under euri; then will look for
     "update" which should be "euri" */
  CHECK (sl != NULL);
  /* wait for results... */
  tries = 5;
  while (--tries > 0)
    {
      if (want == NULL)
        break;
      GNUNET_thread_sleep (GNUNET_CRON_MILLISECONDS * 150);
    }
  CHECK (want == NULL);
  CHECK (GNUNET_OK == GNUNET_NS_namespace_delete (ectx, cfg, &nsid));
  /* END OF TEST CODE */
FAILURE:
  if (uri != NULL)
    GNUNET_ECRS_uri_destroy (uri);
  if (euri != NULL)
    GNUNET_ECRS_uri_destroy (euri);
  if (furi != NULL)
    GNUNET_ECRS_uri_destroy (furi);
  if (meta != NULL)
    GNUNET_meta_data_destroy (meta);
  if (sl != NULL)
    GNUNET_FSUI_search_stop (sl);
  if (ctx != NULL)
    GNUNET_FSUI_stop (ctx);
  GNUNET_ECRS_namespace_delete (ectx, cfg, &nsid);

  GNUNET_GE_ASSERT (NULL, GNUNET_OK == GNUNET_daemon_stop (NULL, daemon));
  GNUNET_GC_free (cfg);
  return (ok == GNUNET_YES) ? 0 : 1;
}

/* end of namespace_infotest.c */
