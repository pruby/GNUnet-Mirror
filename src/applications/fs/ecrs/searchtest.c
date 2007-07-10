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
 * @file applications/fs/ecrs/searchtest.c
 * @brief testcase for search
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"
#include "tree.h"

#define CHECK(a) if (!(a)) { ok = NO; GE_BREAK(NULL, 0); goto FAILURE; }

static int
testTerminate (void *unused)
{
  return OK;
}

static struct GC_Configuration *cfg;

static int
searchCB (const ECRS_FileInfo * fi,
          const HashCode512 * key, int isRoot, void *closure)
{
  int *cnt = closure;
#if 1
  char *st;

  st = ECRS_uriToString (fi->uri);
  printf ("Got result `%s'\n", st);
  FREE (st);
#endif
  (*cnt)--;
  if (0 == *cnt)
    return SYSERR;              /* abort search */
  return OK;
}

/**
 * @param *uri In: keyword URI
 * @return OK on success, SYSERR on error
 */
static int
searchFile (const struct ECRS_URI *uri, int resultCount)
{
  ECRS_search (NULL,
               cfg,
               uri,
               0,
               60 * 15 * cronSECONDS,
               &searchCB, &resultCount, &testTerminate, NULL);
  if (resultCount > 0)
    return SYSERR;
  return OK;
}

int
main (int argc, char *argv[])
{
  pid_t daemon;
  int ok;
  struct ClientServerConnection *sock;
  struct ECRS_URI *uri;
  struct ECRS_MetaData *meta;
  struct ECRS_URI *key;
  const char *keywords[6];


  cfg = GC_create_C_impl ();
  if (-1 == GC_parse_configuration (cfg, "check.conf"))
    {
      GC_free (cfg);
      return -1;
    }
  sock = NULL;
  daemon = os_daemon_start (NULL, cfg, "peer.conf", NO);
  GE_ASSERT (NULL, daemon > 0);
  CHECK (OK == connection_wait_for_running (NULL, cfg, 30 * cronSECONDS));
  ok = YES;
  PTHREAD_SLEEP (5 * cronSECONDS);      /* give apps time to start */
  sock = client_connection_create (NULL, cfg);
  CHECK (sock != NULL);
  /* ACTUAL TEST CODE */
  /* first, simple insertion => one result */
#if 1
  printf ("Testing search for 'XXtest' with one result.\n");
#endif
  uri = ECRS_stringToUri (NULL,
                          "gnunet://ecrs/sks/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820/test");
  meta = ECRS_createMetaData ();
  keywords[0] = "XXtest";
  keywords[1] = NULL;

  key = ECRS_keywordsToUri (keywords);
  CHECK (OK == ECRS_addToKeyspace (NULL, cfg, key, 0, 0, get_time () + 10 * cronMINUTES,        /* expire */
                                   uri, meta));
  CHECK (OK == searchFile (key, 1));
  ECRS_freeUri (key);
  ECRS_freeUri (uri);

  /* inserting another URI under the 'XXtest' keyword and under 'binary'
     should give both URIs since ECRS knows nothing about 'AND'ing: */
#if 1
  printf ("Testing search for 'XXtest AND binary' with two results.\n");
#endif
  uri = ECRS_stringToUri (NULL,
                          "gnunet://ecrs/sks/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820/test-different");
  keywords[1] = "binary";
  keywords[2] = NULL;
  key = ECRS_keywordsToUri (keywords);
  CHECK (OK == ECRS_addToKeyspace (NULL, cfg, key, 0, 0, get_time () + 10 * cronMINUTES,        /* expire */
                                   uri, meta));
  CHECK (OK == searchFile (key, 2));
  ECRS_freeUri (key);
  ECRS_freeUri (uri);
  ECRS_freeMetaData (meta);

  /* now searching just for 'XXtest' should again give 2 results! */
#if 0
  printf ("Testing search for 'XXtest' with two results.\n");
#endif
  keywords[1] = NULL;
  key = ECRS_keywordsToUri (keywords);
  CHECK (OK == searchFile (key, 2));
  ECRS_freeUri (key);

  /* END OF TEST CODE */
FAILURE:
  if (sock != NULL)
    connection_destroy (sock);
  GE_ASSERT (NULL, OK == os_daemon_stop (NULL, daemon));
  return (ok == YES) ? 0 : 1;
}

/* end of searchtest.c */
