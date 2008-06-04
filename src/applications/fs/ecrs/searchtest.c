/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/searchtest.c
 * @brief testcase for search
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
#include "tree.h"

#define CHECK(a) if (!(a)) { ok = GNUNET_NO; GNUNET_GE_BREAK(NULL, 0); goto FAILURE; }

static unsigned int app_killer;

static int
testTerminate (void *unused)
{
  if (app_killer++ > 10000)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

static struct GNUNET_GC_Configuration *cfg;

static int
searchCB (const GNUNET_ECRS_FileInfo * fi,
          const GNUNET_HashCode * key, int isRoot, void *closure)
{
  int *cnt = closure;
#if 0
  char *st;

  st = GNUNET_ECRS_uri_to_string (fi->uri);
  printf ("Got result `%.*s...'\n", 40, st);
  GNUNET_free (st);
#endif
  (*cnt)--;
  if (0 == *cnt)
    return GNUNET_SYSERR;       /* abort search */
  return GNUNET_OK;
}

/**
 * @param *uri In: keyword URI
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
searchFile (const struct GNUNET_ECRS_URI *uri, int resultCount)
{
  GNUNET_ECRS_search (NULL,
                      cfg,
                      uri, 0, &searchCB, &resultCount, &testTerminate, NULL);
  if (resultCount > 0)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

int
main (int argc, char *argv[])
{
  pid_t daemon;
  int ok;
  struct GNUNET_ClientServerConnection *sock;
  struct GNUNET_ECRS_URI *uri;
  struct GNUNET_MetaData *meta;
  struct GNUNET_ECRS_URI *key;

  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  sock = NULL;
  daemon = GNUNET_daemon_start (NULL, cfg, "peer.conf", GNUNET_NO);
  GNUNET_GE_ASSERT (NULL, daemon > 0);
  CHECK (GNUNET_OK ==
         GNUNET_wait_for_daemon_running (NULL, cfg,
                                         30 * GNUNET_CRON_SECONDS));
  ok = GNUNET_YES;
  GNUNET_thread_sleep (5 * GNUNET_CRON_SECONDS);        /* give apps time to start */
  sock = GNUNET_client_connection_create (NULL, cfg);
  CHECK (sock != NULL);
  /* ACTUAL TEST CODE */
  /* first, simple insertion => one result */
#if 0
  printf ("Testing search for 'XXtest' with one result.\n");
#endif
  uri = GNUNET_ECRS_string_to_uri (NULL,
                                   "gnunet://ecrs/sks/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820/test");
  CHECK (uri != NULL);
  meta = GNUNET_meta_data_create ();

  key = GNUNET_ECRS_keyword_string_to_uri (NULL, "XXtest");
  CHECK (GNUNET_OK == GNUNET_ECRS_publish_under_keyword (NULL, cfg, key, 0, 0, GNUNET_get_time () + 10 * GNUNET_CRON_MINUTES,   /* expire */
                                                         uri, meta));
  CHECK (GNUNET_OK == searchFile (key, 1));
  GNUNET_ECRS_uri_destroy (uri);

  uri = GNUNET_ECRS_string_to_uri (NULL,
                                   "gnunet://ecrs/sks/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820/test-different");
  CHECK (GNUNET_OK == GNUNET_ECRS_publish_under_keyword (NULL, cfg, key, 0, 0, GNUNET_get_time () + 10 * GNUNET_CRON_MINUTES,   /* expire */
                                                         uri, meta));
  GNUNET_ECRS_uri_destroy (key);
  key = GNUNET_ECRS_keyword_string_to_uri (NULL, "binary");
  CHECK (GNUNET_OK == GNUNET_ECRS_publish_under_keyword (NULL, cfg, key, 0, 0, GNUNET_get_time () + 10 * GNUNET_CRON_MINUTES,   /* expire */
                                                         uri, meta));
  CHECK (GNUNET_OK == searchFile (key, 1));
  GNUNET_ECRS_uri_destroy (key);
  GNUNET_ECRS_uri_destroy (uri);
  GNUNET_meta_data_destroy (meta);

  /* now searching just for 'XXtest' should again give 2 results! */
#if 0
  printf ("Testing search for 'XXtest' with two results.\n");
#endif
  key = GNUNET_ECRS_keyword_string_to_uri (NULL, "XXtest");
  CHECK (GNUNET_OK == searchFile (key, 2));
  GNUNET_ECRS_uri_destroy (key);

  /* END OF TEST CODE */
FAILURE:
  if (sock != NULL)
    GNUNET_client_connection_destroy (sock);
  GNUNET_GE_ASSERT (NULL, GNUNET_OK == GNUNET_daemon_stop (NULL, daemon));
  GNUNET_GC_free (cfg);
  return (ok == GNUNET_YES) ? 0 : 1;
}

/* end of searchtest.c */
