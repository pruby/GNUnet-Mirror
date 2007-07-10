/*
     This file is part of GNUnet.
     (C) 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file server/version.c
 * @brief check if we need to run gnunet-update
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_util_crypto.h"
#include "gnunet_directories.h"
#include "version.h"

#define VERSIONFILE "/state.sdb/GNUNET-VERSION"
#define VERSIONDIR "/state.sdb/"

/**
 * Extend string by "section:part=val;" where
 * val is the configuration value from the
 * configuration file.
 */
static void
dyncat (struct GC_Configuration *cfg,
        char **string, const char *section, const char *part)
{
  int len;
  char *tmp;
  char *val;

  len = strlen (*string);
  len += strlen (section) + 1;
  len += strlen (part) + 1;
  val = NULL;
  GC_get_configuration_value_string (cfg, section, part, "", &val);
  if (val == NULL)
    val = STRDUP ("");
  len += strlen (val) + 2;
  tmp = MALLOC (len);
  strcpy (tmp, *string);
  strcat (tmp, section);
  strcat (tmp, ":");
  strcat (tmp, part);
  strcat (tmp, "=");
  strcat (tmp, val);
  strcat (tmp, ";");
  FREE (val);
  FREE (*string);
  *string = tmp;
}

/**
 * Get the hash code that concatenated with the
 * current version defines the current configuration.
 *
 * The hash is determined from the configuration file,
 * since changes to certain values there will also
 * require us to run gnunet-update!
 */
static void
getVersionHash (struct GC_Configuration *cfg, EncName * enc)
{
  HashCode512 hc;
  char *string;

  string = STRDUP ("");
  /* yes, this is a bit ugly since we break the isolation between core
     and apps, but adding code to query the apps which configuration
     changes require gnunet-update feels like overkill for now; one
     simple alternative would be to require gnunet-update for any
     configuration change, but that again would be too strict. */
  dyncat (cfg, &string, "GNUNETD", "APPLICATIONS");
  dyncat (cfg, &string, "FS", "QUOTA");
  dyncat (cfg, &string, "MODULES", "sqstore");
  hash (string, strlen (string), &hc);
  hash2enc (&hc, enc);
  FREE (string);
}

static char *
getVersionFileName (struct GE_Context *ectx, struct GC_Configuration *cfg)
{
  char *en;
  char *cn;

  en = NULL;
  if (-1 == GC_get_configuration_value_filename (cfg,
                                                 "GNUNETD",
                                                 "GNUNETD_HOME",
                                                 VAR_DAEMON_DIRECTORY, &en))
    return NULL;
  GE_ASSERT (ectx, en != NULL);
  cn = MALLOC (strlen (en) + strlen (VERSIONFILE) + 1);
  strcpy (cn, en);
  strcat (cn, VERSIONDIR);
  disk_directory_create (ectx, cn);
  strcpy (cn, en);
  strcat (cn, VERSIONFILE);
  FREE (en);
  return cn;
}

#define MAX_VS sizeof(EncName) + 64

/**
 * Check if we are up-to-date.
 * @return OK if we are
 */
int
checkUpToDate (struct GE_Context *ectx, struct GC_Configuration *cfg)
{
  char version[MAX_VS];
  int len;
  EncName enc;
  char *fn;

  fn = getVersionFileName (ectx, cfg);
  if (fn == NULL)
    {
      GE_LOG (ectx,
              GE_ERROR | GE_USER | GE_BULK,
              _
              ("Failed to determine filename used to store GNUnet version information!\n"));
      return OK;                /* uh uh */
    }
  if (disk_file_test (ectx, fn) != YES)
    {
      FREE (fn);
      upToDate (ectx, cfg);     /* first start */
      return OK;
    }
  len = disk_file_read (ectx, fn, MAX_VS, version);
  FREE (fn);
  if (len == -1)
    {                           /* should never happen -- file should exist */
      upToDate (ectx, cfg);     /* first start */
      return OK;
    }
  if ((len != strlen (VERSION) + 1 + sizeof (EncName)) ||
      (0 != memcmp (VERSION, version, strlen (VERSION) + 1)))
    return SYSERR;              /* wrong version */
  getVersionHash (cfg, &enc);
  if (0 != memcmp (&enc, &version[strlen (VERSION) + 1], sizeof (EncName)))
    return SYSERR;              /* wrong hash */
  return OK;
}

/**
 * We are up-to-date.
 * Writes the version tag
 */
void
upToDate (struct GE_Context *ectx, struct GC_Configuration *cfg)
{
  char version[MAX_VS];
  int len;
  EncName enc;
  char *fn;

  fn = getVersionFileName (ectx, cfg);
  len = strlen (VERSION) + 1 + sizeof (EncName);
  GE_ASSERT (ectx, len < MAX_VS);
  memcpy (version, VERSION, strlen (VERSION) + 1);
  getVersionHash (cfg, &enc);
  memcpy (&version[strlen (VERSION) + 1], &enc, sizeof (EncName));
  UNLINK (fn);
  disk_file_write (ectx, fn, version, len, "600");
  FREE (fn);
}

/* end of version.c */
