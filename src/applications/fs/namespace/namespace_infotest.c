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
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_namespace_lib.h"
#include "gnunet_namespace_lib.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_crypto.h"
#include "gnunet_util_network_client.h"

#define CHECK(a) if (!(a)) { ok = NO; GE_BREAK(ectx, 0); goto FAILURE; }

static struct GE_Context *ectx;

int
main (int argc, char *argv[])
{
  pid_t daemon;
  int ok;
  struct ECRS_URI *uri = NULL;
  struct ECRS_URI *euri = NULL;
  struct ECRS_MetaData *meta = NULL;
  HashCode512 root;
  int old;
  int newVal;
  struct GC_Configuration *cfg;

  cfg = GC_create_C_impl ();
  if (-1 == GC_parse_configuration (cfg, "check.conf"))
    {
      GC_free (cfg);
      return -1;
    }
  daemon = os_daemon_start (NULL, cfg, "peer.conf", NO);
  GE_ASSERT (NULL, daemon > 0);
  CHECK (OK == connection_wait_for_running (NULL, cfg, 30 * cronSECONDS));
  ok = YES;
  NS_deleteNamespace (ectx, cfg, "test");
  PTHREAD_SLEEP (5 * cronSECONDS);      /* give apps time to start */

  /* ACTUAL TEST CODE */
  old = NS_listNamespaces (ectx, cfg, NULL, NULL);

  meta = ECRS_createMetaData ();
  ECRS_addToMetaData (meta, 0, "test");
  makeRandomId (&root);
  uri = NS_createNamespace (ectx,
                            cfg,
                            1,
                            1,
                            get_time () + 10 * cronMINUTES,
                            "test", meta, NULL, &root);
  CHECK (uri != NULL);
  newVal = NS_listNamespaces (ectx, cfg, NULL, NULL);
  CHECK (old < newVal);
  old = NS_listNamespaceContent (ectx, cfg, "test", NULL, NULL);
  euri = NS_addToNamespace (ectx,
                            cfg,
                            1,
                            1,
                            get_time () + 10 * cronMINUTES,
                            "test", 42, NULL, &root, NULL, uri, meta);
  CHECK (euri != NULL);
  newVal = NS_listNamespaceContent (ectx, cfg, "test", NULL, NULL);
  CHECK (old < newVal);
  CHECK (OK == NS_deleteNamespace (ectx, cfg, "test"));
  /* END OF TEST CODE */
FAILURE:
  if (uri != NULL)
    ECRS_freeUri (uri);
  if (euri != NULL)
    ECRS_freeUri (euri);
  if (meta != NULL)
    ECRS_freeMetaData (meta);
  ECRS_deleteNamespace (ectx, cfg, "test");

  GE_ASSERT (NULL, OK == os_daemon_stop (NULL, daemon));
  GC_free (cfg);
  return (ok == YES) ? 0 : 1;
}

/* end of namespace_infotest.c */
