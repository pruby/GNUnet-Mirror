/*
     This file is part of GNUnet.
     (C) 2005, 2006 Christian Grothoff (and other contributing authors)

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
 *
 * TODO:
 * - more comprehensive testcase!
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_namespace_lib.h"
#include "gnunet_namespace_lib.h"

#define CHECK(a) if (!(a)) { ok = GNUNET_NO; GNUNET_GE_BREAK(ectx, 0); goto FAILURE; }

static struct GNUNET_GE_Context *ectx;

int
main (int argc, char *argv[])
{
  pid_t daemon;
  int ok;
  struct GNUNET_ECRS_URI *uri = NULL;
  struct GNUNET_ECRS_URI *euri = NULL;
  struct GNUNET_ECRS_MetaData *meta = NULL;
  GNUNET_HashCode root;
  GNUNET_HashCode nsid;
  int old;
  int newVal;
  struct GNUNET_GC_Configuration *cfg;

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
  meta = GNUNET_ECRS_meta_data_create ();
  GNUNET_ECRS_meta_data_insert (meta, 0, "test");
  GNUNET_create_random_hash (&root);
  uri = GNUNET_NS_namespace_create (ectx,
                                    cfg,
                                    1,
                                    1,
                                    GNUNET_get_time () +
                                    10 * GNUNET_CRON_MINUTES, meta,
                                    NULL, &root);
  CHECK (uri != NULL);
  GNUNET_ECRS_uri_get_namespace_from_sks (uri, &nsid);
  old = GNUNET_NS_namespace_list_contents (ectx, cfg, &nsid, NULL, NULL);
  euri = GNUNET_NS_add_to_namespace (ectx,
                                     cfg,
                                     1,
                                     1,
                                     GNUNET_get_time () +
                                     10 * GNUNET_CRON_MINUTES, &nsid, 42,
                                     NULL, &root, NULL, uri, meta);
  CHECK (euri != NULL);
  newVal = GNUNET_NS_namespace_list_contents (ectx, cfg, &nsid, NULL, NULL);
  CHECK (old < newVal);
  CHECK (GNUNET_OK == GNUNET_NS_namespace_delete (ectx, cfg, &nsid));
  /* END OF TEST CODE */
FAILURE:
  if (uri != NULL)
    GNUNET_ECRS_uri_destroy (uri);
  if (euri != NULL)
    GNUNET_ECRS_uri_destroy (euri);
  if (meta != NULL)
    GNUNET_ECRS_meta_data_destroy (meta);
  GNUNET_ECRS_namespace_delete (ectx, cfg, &nsid);

  GNUNET_GE_ASSERT (NULL, GNUNET_OK == GNUNET_daemon_stop (NULL, daemon));
  GNUNET_GC_free (cfg);
  return (ok == GNUNET_YES) ? 0 : 1;
}

/* end of namespace_infotest.c */
