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
 * @file applications/fs/ecrs/namespacetest.c
 * @brief Test for namespace.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"
#include "gnunet_ecrs_lib.h"
#include "ecrs.h"

#define ABORT() { fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); return 1; }
#define CHECK(c) { do { if (!(c)) ABORT(); } while(0); }

#define CHECKNAME "gnunet-namespace-test"

static struct GC_Configuration *cfg;

static int match;

static int
spcb (const ECRS_FileInfo * fi,
      const HashCode512 * key, int isRoot, void *closure)
{
  struct ECRS_URI *want = closure;

  if (ECRS_equalsUri (want, fi->uri))
    match = 1;
  else
    fprintf (stderr,
             "Namespace search returned unexpected result: \nHAVE: %s\nWANT: %s...\n",
             ECRS_uriToString (fi->uri), ECRS_uriToString (want));
  return OK;
}

static int
testNamespace ()
{
  HashCode512 root;
  HashCode512 thisId;
  HashCode512 nextId;
  struct ECRS_URI *adv;
  struct ECRS_URI *uri;
  struct ECRS_URI *advURI;
  struct ECRS_URI *rootURI;
  struct ECRS_MetaData *meta;
  const char *keys[] = {
    "testNamespace",
    NULL,
  };


  ECRS_deleteNamespace (NULL, cfg, CHECKNAME);  /* make sure old one is deleted */
  meta = ECRS_createMetaData ();
  adv = ECRS_keywordsToUri (keys);
  hash ("root", 4, &root);
  rootURI =
    ECRS_createNamespace (NULL,
                          cfg,
                          CHECKNAME,
                          meta,
                          0, 0, get_time () + 15 * cronMINUTES, adv, &root);
  CHECK (NULL != rootURI);
  hash ("this", 4, &thisId);
  hash ("next", 4, &nextId);
  uri = rootURI;                /* just for fun: NS::this advertises NS::root */
  advURI = ECRS_addToNamespace (NULL, cfg, CHECKNAME, 1,        /* anonymity */
                                1000,   /* priority */
                                5 * cronMINUTES + get_time (),
                                TIME (NULL) + 300,
                                0, &thisId, &nextId, uri, meta);
  CHECK (NULL != advURI);
  fprintf (stderr, "Starting namespace search...\n");
  CHECK (OK == ECRS_search (NULL,
                            cfg,
                            advURI,
                            1, 60 * cronSECONDS, &spcb, uri, NULL, NULL));
  fprintf (stderr, "Completed namespace search...\n");
  CHECK (OK == ECRS_deleteNamespace (NULL, cfg, CHECKNAME));
  CHECK (SYSERR == ECRS_deleteNamespace (NULL, cfg, CHECKNAME));
  ECRS_freeMetaData (meta);
  ECRS_freeUri (rootURI);
  ECRS_freeUri (advURI);
  CHECK (match == 1);
  return 0;
}

int
main (int argc, char *argv[])
{
  pid_t daemon;
  int failureCount = 0;

  cfg = GC_create_C_impl ();
  if (-1 == GC_parse_configuration (cfg, "check.conf"))
    {
      GC_free (cfg);
      return -1;
    }
  daemon = os_daemon_start (NULL, cfg, "peer.conf", NO);
  GE_ASSERT (NULL, daemon > 0);
  if (OK != connection_wait_for_running (NULL, cfg, 60 * cronSECONDS))
    {
      failureCount++;
    }
  else
    {
      PTHREAD_SLEEP (5 * cronSECONDS);
      failureCount += testNamespace ();
    }
  GE_ASSERT (NULL, OK == os_daemon_stop (NULL, daemon));

  return (failureCount == 0) ? 0 : 1;
}

/* end of namespacetest.c */
