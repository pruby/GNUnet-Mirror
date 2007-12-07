/*
     This file is part of GNUnet.
     (C) 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/tools/gnunet-pseudonym.c
 * @brief create, list or delete pseudoynms
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_collection_lib.h"
#include "gnunet_namespace_lib.h"
#include "gnunet_util.h"

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_GC_Configuration *cfg;

static int start_collection;

static int stop_collection;

static int be_quiet;

static int no_advertisement;

static char *delete_name;

static char *create_name;

static char *set_rating;

static char *root_name;

static unsigned int anonymity;

static unsigned int priority;

static GNUNET_CronTime expiration = 2 * GNUNET_CRON_YEARS;

static char *cfgFilename = GNUNET_DEFAULT_CLIENT_CONFIG_FILE;

static struct GNUNET_ECRS_MetaData *meta;

static struct GNUNET_ECRS_URI *advertisement;

/**
 * All gnunet-pseudonym command line options
 */
static struct GNUNET_CommandLineOption gnunetpseudonymOptions[] = {
  {'a', "anonymity", "LEVEL",
   gettext_noop ("set the desired LEVEL of sender-anonymity"),
   1, &GNUNET_getopt_configure_set_uint, &anonymity},
  {'A', "automate", NULL,
   gettext_noop ("automate creation of a namespace by starting a collection"),
   0, &GNUNET_getopt_configure_set_one, &start_collection},
  GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),   /* -c */
  {'C', "create", "NICKNAME",
   gettext_noop ("create a new pseudonym under the given NICKNAME"),
   1, &GNUNET_getopt_configure_set_string, &create_name},
  {'D', "delete", "NICKNAME",
   gettext_noop ("delete the pseudonym with the given NICKNAME"),
   1, &GNUNET_getopt_configure_set_string, &delete_name},
  {'E', "end", NULL,
   gettext_noop ("end automated building of a namespace (ends collection)"),
   0, &GNUNET_getopt_configure_set_one, &stop_collection},
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Create new pseudonyms, delete pseudonyms or list existing pseudonyms.")),     /* -h */
  GNUNET_COMMAND_LINE_OPTION_LOGGING,   /* -L */
  {'k', "keyword", "KEYWORD",
   gettext_noop
   ("use the given keyword to advertise the namespace (use when creating a new pseudonym)"),
   1, &GNUNET_ECRS_getopt_configure_set_keywords, &advertisement},
  {'m', "meta", "TYPE=VALUE",
   gettext_noop ("specify metadata describing the namespace or collection"),
   1, &GNUNET_ECRS_getopt_configure_set_metadata, &meta},
  {'n', "no-advertisement", NULL,
   gettext_noop
   ("do not generate an advertisement for this namespace (use when creating a new pseudonym)"),
   0, &GNUNET_getopt_configure_set_one, &no_advertisement},
  {'q', "quiet", NULL,
   gettext_noop ("do not list the pseudonyms from the pseudonym database"),
   0, &GNUNET_getopt_configure_set_one, &be_quiet},
  {'R', "root", "IDENTIFIER",
   gettext_noop
   ("specify IDENTIFIER to be the address of the entrypoint to content in the namespace (use when creating a new pseudonym)"),
   1, &GNUNET_getopt_configure_set_string, &root_name},
  {'s', "set-rating", "ID:VALUE",
   gettext_noop ("set the rating of a namespace"),
   0, &GNUNET_getopt_configure_set_string, &set_rating},
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION), /* -v */
  GNUNET_COMMAND_LINE_OPTION_VERBOSE,
  GNUNET_COMMAND_LINE_OPTION_END,
};

static int
itemPrinter (EXTRACTOR_KeywordType type, const char *data, void *closure)
{
  printf ("\t%20s: %s\n",
          dgettext ("libextractor",
                    EXTRACTOR_getKeywordTypeAsString (type)), data);
  return GNUNET_OK;
}

static void
printMeta (const struct GNUNET_ECRS_MetaData *m)
{
  GNUNET_ECRS_meta_data_get_contents (m, &itemPrinter, NULL);
}

static int
namespacePrinter (void *unused,
                  const char *namespaceName,
                  const GNUNET_HashCode * id,
                  const struct GNUNET_ECRS_MetaData *md, int rating)
{
  GNUNET_EncName enc;
  int cpos;

  GNUNET_hash_to_enc (id, &enc);
  if (0 == strcmp (namespaceName, (char *) &enc))
    printf (_("Namespace `%s' has rating %d.\n"), namespaceName, rating);
  else
    printf (_("Namespace `%s' (%s) has rating %d.\n"),
            namespaceName, (char *) &enc, rating);
  printMeta (md);

  if (set_rating != NULL)
    {
      int delta;
      char *set;

      set = set_rating;
      delta = 0;
      cpos = 0;
      while ((set[cpos] != '\0') && (set[cpos] != ':'))
        cpos++;
      if (((((strlen ((char *) &enc) + 1 == cpos) &&
             (0 == strncmp (set,
                            (char *) &enc,
                            cpos)))) ||
           ((namespaceName != NULL) &&
            (strlen (namespaceName) == cpos) &&
            (0 == strncmp (set, namespaceName, cpos)))) && (set[cpos] == ':'))
        {
          delta = strtol (&set[cpos + 1], NULL, /* no error handling yet */
                          10);
        }

      if (delta != 0)
        {
          rating = GNUNET_NS_namespace_rank (ectx, cfg, namespaceName, delta);
          printf (_("\tRating (after update): %d\n"), rating);
        }
    }
  printf ("\n");
  return GNUNET_OK;
}

int
main (int argc, char *const *argv)
{
  int cnt;
  int success;
  int i;
  GNUNET_HashCode hc;

  meta = GNUNET_ECRS_meta_data_create ();
  i = GNUNET_init (argc,
                   argv,
                   "gnunet-pseudonym [OPTIONS]",
                   &cfgFilename, gnunetpseudonymOptions, &ectx, &cfg);
  if (i == -1)
    {
      GNUNET_ECRS_meta_data_destroy (meta);
      GNUNET_fini (ectx, cfg);
      return -1;
    }
  success = 0;                  /* no errors */
  GNUNET_CO_init (ectx, cfg);

  /* stop collections */
  if (stop_collection && (!start_collection))
    {
      if (GNUNET_OK == GNUNET_CO_collection_stop ())
        printf (_("Collection stopped.\n"));
      else
        printf (_("Failed to stop collection (not active?).\n"));
    }

  /* delete pseudonyms */
  if (delete_name != NULL)
    {
      if (GNUNET_OK == GNUNET_NS_namespace_delete (ectx, cfg, delete_name))
        {
          printf (_("Pseudonym `%s' deleted.\n"), delete_name);
        }
      else
        {
          success += 2;
          printf (_("Error deleting pseudonym `%s' (does not exist?).\n"),
                  delete_name);
        }
      GNUNET_free (delete_name);
    }

  /* create collections / namespace */
  if (create_name != NULL)
    {
      if (start_collection)
        {
          GNUNET_ECRS_meta_data_insert (meta, EXTRACTOR_OWNER, create_name);
          if (GNUNET_OK == GNUNET_CO_collection_start (anonymity, priority, GNUNET_ECRS_SBLOCK_UPDATE_SPORADIC, /* FIXME: allow other update policies */
                                                       create_name, meta))
            {
              printf (_("Started collection `%s'.\n"), create_name);
            }
          else
            {
              printf (_("Failed to start collection.\n"));
              success++;
            }

          GNUNET_ECRS_meta_data_delete (meta, EXTRACTOR_OWNER, create_name);
        }
      else
        {                       /* no collection */
          GNUNET_HashCode rootEntry;
          struct GNUNET_ECRS_URI *rootURI;
          char *root;

          if (root_name == NULL)
            {
              memset (&rootEntry, 0, sizeof (GNUNET_HashCode));
            }
          else
            {
              if (GNUNET_SYSERR == GNUNET_enc_to_hash (root_name, &hc))
                GNUNET_hash (root_name, strlen (root_name), &hc);
            }
          if (no_advertisement)
            {
              if (advertisement != NULL)
                GNUNET_ECRS_uri_destroy (advertisement);
              advertisement = NULL;
            }
          else
            {
              if (advertisement == NULL)
                advertisement =
                  GNUNET_ECRS_keyword_string_to_uri (ectx, "namespace");
            }
          rootURI = GNUNET_NS_namespace_create (ectx,
                                                cfg,
                                                anonymity,
                                                priority,
                                                expiration +
                                                GNUNET_get_time (),
                                                create_name, meta,
                                                advertisement, &rootEntry);
          if (rootURI == NULL)
            {
              printf (_("Could not create namespace `%s' (exists?).\n"),
                      create_name);
              success += 1;
            }
          else
            {
              root = GNUNET_ECRS_uri_to_string (rootURI);
              printf (_("Namespace `%s' created (root: %s).\n"),
                      create_name, root);
              GNUNET_free (root);
              GNUNET_ECRS_uri_destroy (rootURI);
            }
          if (NULL != advertisement)
            GNUNET_ECRS_uri_destroy (advertisement);
        }
      GNUNET_free (create_name);
      create_name = NULL;
    }
  else
    {
      if (start_collection)
        printf (_
                ("You must specify a name for the collection (`%s' option).\n"),
                "-C");
    }
  if (0 == be_quiet)
    {
      /* print information about pseudonyms */
      cnt = GNUNET_NS_namespace_list_all (ectx, cfg, &namespacePrinter, NULL);
      if (cnt == -1)
        printf (_("Could not access namespace information.\n"));
    }
  GNUNET_ECRS_meta_data_destroy (meta);
  GNUNET_CO_done ();
  GNUNET_fini (ectx, cfg);
  return success;
}

/* end of gnunet-pseudonym.c */
