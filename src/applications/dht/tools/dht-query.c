/*
      This file is part of GNUnet
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
 * @file dht-query.c
 * @brief perform DHT operations (insert, lookup)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_protocols.h"
#include "gnunet_util.h"
#include "gnunet_dht_lib.h"

#define DEBUG_DHT_QUERY GNUNET_NO

/**
 * How long should a "GET" run (or how long should
 * content last on the network).
 */
static GNUNET_CronTime timeout;

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_GC_Configuration *cfg;

static char *cfgFilename = GNUNET_DEFAULT_CLIENT_CONFIG_FILE;

struct GNUNET_DHT_Context *ctx;

/**
 * All gnunet-dht-query command line options
 */
static struct GNUNET_CommandLineOption gnunetqueryOptions[] = {
  GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),   /* -c */
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Query (get KEY, put KEY VALUE) DHT table.")), /* -h */
  GNUNET_COMMAND_LINE_OPTION_HOSTNAME,  /* -H */
  GNUNET_COMMAND_LINE_OPTION_LOGGING,   /* -L */
  {'T', "timeout", "TIME",
   gettext_noop ("allow TIME ms to process a GET command"),
   1, &GNUNET_getopt_configure_set_ulong, &timeout},
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION), /* -v */
  GNUNET_COMMAND_LINE_OPTION_VERBOSE,
  GNUNET_COMMAND_LINE_OPTION_END,
};

static int
printCallback (const GNUNET_HashCode * hash,
               unsigned int type,
               unsigned int size, const char *data, void *cls)
{
  char *key = cls;
  printf ("%s(%s): '%.*s'\n", "get", key, size, data);
  return GNUNET_OK;
}

static void
do_get (struct GNUNET_ClientServerConnection *sock, const char *key)
{
  int ret;
  GNUNET_HashCode hc;

  GNUNET_hash (key, strlen (key), &hc);
#if DEBUG_DHT_QUERY
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Issuing '%s(%s)' command.\n", "get", key);
#endif
  if (timeout == 0)
    timeout = 30 * GNUNET_CRON_SECONDS;
  ret = GNUNET_DHT_get_start (ctx, GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING,
                              (void *) key);
  if (ret == 0)
    printf (_("%s(%s) operation returned no results.\n"), "get", key);
}

static void
do_put (struct GNUNET_ClientServerConnection *sock,
        const char *key, const char *value)
{
  GNUNET_HashCode hc;

  GNUNET_hash (key, strlen (key), &hc);
#if DEBUG_DHT_QUERY
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _("Issuing '%s(%s,%s)' command.\n"), "put", key, value);
#endif
  if (timeout == 0)
    timeout = 30 * GNUNET_CRON_MINUTES;
  if (GNUNET_OK ==
      GNUNET_DHT_put (cfg, ectx, &hc, GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING,
                      strlen (value), value))
    {
      printf (_("'%s(%s,%s)' succeeded\n"), "put", key, value);
    }
  else
    {
      printf (_("'%s(%s,%s)' failed.\n"), "put", key, value);
    }
}

int
main (int argc, char *const *argv)
{
  int i;
  struct GNUNET_ClientServerConnection *handle;
  void *unused;
  i = GNUNET_init (argc,
                   argv,
                   "gnunet-dht-query",
                   &cfgFilename, gnunetqueryOptions, &ectx, &cfg);
  if (i == -1)
    {
      GNUNET_fini (ectx, cfg);
      return -1;
    }

  handle = GNUNET_client_connection_create (ectx, cfg);

  ctx = GNUNET_DHT_context_create (cfg, ectx, &printCallback, unused);
  if (handle == NULL)
    {
      fprintf (stderr, _("Failed to connect to gnunetd.\n"));
      GNUNET_GC_free (cfg);
      GNUNET_GE_free_context (ectx);
      return 1;
    }

  while (i < argc)
    {
      if (0 == strcmp ("get", argv[i]))
        {
          if (i + 2 > argc)
            {
              fprintf (stderr,
                       _("Command `%s' requires an argument (`%s').\n"),
                       "get", "key");
              break;
            }
          else
            {
              do_get (handle, argv[i + 1]);
              i += 2;
            }
          continue;
        }
      if (0 == strcmp ("put", argv[i]))
        {
          if (i + 3 > argc)
            {
              fprintf (stderr,
                       _
                       ("Command `%s' requires two arguments (`%s' and `%s').\n"),
                       "put", "key", "value");
              break;
            }
          else
            {
              do_put (handle, argv[i + 1], argv[i + 2]);
              i += 3;
            }
          continue;
        }
      fprintf (stderr, _("Unsupported command `%s'.  Aborting.\n"), argv[i]);
      break;
    }
  GNUNET_client_connection_destroy (handle);
  GNUNET_fini (ectx, cfg);
  return 0;
}

/* end of dht-query.c */
