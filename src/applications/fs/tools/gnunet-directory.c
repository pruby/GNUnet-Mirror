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
 * @file applications/fs/tools/gnunet-directory.c
 * @brief tool to list the entries stored in the database holding
 *        files for building directories, to delete all of these
 *        entries and to display the contents of  directories.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_uritrack_lib.h"
#include "gnunet_util.h"

static char *cfgFilename = DEFAULT_CLIENT_CONFIG_FILE;

static int do_list;

static int do_kill;

static int do_track;

static struct GE_Context *ectx;

static int
itemPrinter (EXTRACTOR_KeywordType type, const char *data, void *closure)
{
  printf ("\t%20s: %s\n",
          dgettext ("libextractor",
                    EXTRACTOR_getKeywordTypeAsString (type)), data);
  return GNUNET_OK;
}

static void
printMeta (const struct ECRS_MetaData *meta)
{
  ECRS_getMetaData (meta, &itemPrinter, NULL);
}

static int
printNode (const ECRS_FileInfo * fi,
           const GNUNET_HashCode * key, int isRoot, void *unused)
{
  char *string;

  string = ECRS_uriToString (fi->uri);
  printf ("%s:\n", string);
  GNUNET_free (string);
  printMeta (fi->meta);
  return GNUNET_OK;
}

static void
printDirectory (const char *filename)
{
  unsigned long long len;
  struct ECRS_MetaData *md;
  char *data;
  int ret;
  char *name;
  int fd;

  name = GNUNET_expand_file_name (ectx, filename);
  printf (_("==> Directory `%s':\n"), name);
  if ((GNUNET_OK != GNUNET_disk_file_size (ectx, name, &len, GNUNET_YES))
      || (len == 0))
    {
      printf (_("=\tError reading directory.\n"));
      GNUNET_free (name);
      return;
    }
  md = NULL;
  fd = GNUNET_disk_file_open (ectx, name, O_LARGEFILE | O_RDONLY);
  if (fd == -1)
    {
      ret = -1;
    }
  else
    {
      data = MMAP (NULL, len, PROT_READ, MAP_SHARED, fd, 0);
      if (data == MAP_FAILED)
        {
          GE_LOG_STRERROR_FILE (ectx,
                                GE_ERROR | GE_ADMIN | GE_BULK, "mmap", name);
          ret = -1;
        }
      else
        {
          ret = ECRS_listDirectory (ectx, data, len, &md, &printNode, NULL);
          MUNMAP (data, len);
        }
      CLOSE (fd);
    }
  if (ret == -1)
    printf (_("File format error (not a GNUnet directory?)\n"));
  else
    printf (_("%d files found in directory.\n"), ret);
  if (md != NULL)
    {
      printMeta (md);
      ECRS_freeMetaData (md);
    }
  printf ("\n");
  GNUNET_free (name);
}

/**
 * All gnunet-directory command line options
 */
static struct GNUNET_CommandLineOption gnunetdirectoryOptions[] = {
	GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),  /* -c */
	GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Perform directory related operations.")),    /* -h */
  {'k', "kill", NULL,
   gettext_noop
   ("remove all entries from the directory database and stop tracking URIs"),
   0, &GNUNET_getopt_configure_set_one, &do_kill},
  GNUNET_COMMAND_LINE_OPTION_LOGGING,   /* -L */
  {'l', "list", NULL,
   gettext_noop ("list entries from the directory database"),
   0, &GNUNET_getopt_configure_set_one, &do_list},
  {'t', "track", NULL,
   gettext_noop ("start tracking entries for the directory database"),
   0, &GNUNET_getopt_configure_set_one, &do_track},
   GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION),        /* -v */
  GNUNET_COMMAND_LINE_OPTION_VERBOSE,
  GNUNET_COMMAND_LINE_OPTION_END,
};

int
main (int argc, char *const *argv)
{
  int i;
  struct GC_Configuration *cfg;

  i = GNUNET_init (argc,
                   argv,
                   "gnunet-directory [OPTIONS] [FILENAMES]",
                   &cfgFilename, gnunetdirectoryOptions, &ectx, &cfg);
  if (i == -1)
    {
      GNUNET_fini (ectx, cfg);
      return -1;
    }
  if (do_list)
    printf (_("Listed %d matching entries.\n"),
            URITRACK_listURIs (ectx, cfg, GNUNET_YES, &printNode, NULL));
  if (do_kill)
    {
      URITRACK_trackURIS (ectx, cfg, GNUNET_NO);
      URITRACK_clearTrackedURIS (ectx, cfg);
    }
  if (do_track)
    URITRACK_trackURIS (ectx, cfg, GNUNET_YES);

  while (i < argc)
    printDirectory (argv[i++]);

  GNUNET_fini (ectx, cfg);
  return 0;
}

/* end of gnunet-directory.c */
