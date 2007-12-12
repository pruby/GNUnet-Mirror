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
dyncat (struct GNUNET_GC_Configuration *cfg,
        char **string, const char *section, const char *part)
{
  int len;
  char *tmp;
  char *val;

  len = strlen (*string);
  len += strlen (section) + 1;
  len += strlen (part) + 1;
  val = NULL;
  GNUNET_GC_get_configuration_value_string (cfg, section, part, "", &val);
  if (val == NULL)
    val = GNUNET_strdup ("");
  len += strlen (val) + 2;
  tmp = GNUNET_malloc (len);
  strcpy (tmp, *string);
  strcat (tmp, section);
  strcat (tmp, ":");
  strcat (tmp, part);
  strcat (tmp, "=");
  strcat (tmp, val);
  strcat (tmp, ";");
  GNUNET_free (val);
  GNUNET_free (*string);
  *string = tmp;
}

/**
 * Get the GNUNET_hash code that concatenated with the
 * current version defines the current configuration.
 *
 * The GNUNET_hash is determined from the configuration file,
 * since changes to certain values there will also
 * require us to run gnunet-update!
 */
static void
getVersionHash (struct GNUNET_GC_Configuration *cfg, GNUNET_EncName * enc)
{
  GNUNET_HashCode hc;
  char *string;

  string = GNUNET_strdup ("");
  /* yes, this is a bit ugly since we break the isolation between core
     and apps, but adding code to query the apps which configuration
     changes require gnunet-update feels like overkill for now; one
     simple alternative would be to require gnunet-update for any
     configuration change, but that again would be too strict. */
  dyncat (cfg, &string, "GNUNETD", "APPLICATIONS");
  dyncat (cfg, &string, "FS", "QUOTA");
  dyncat (cfg, &string, "MODULES", "sqstore");
  GNUNET_hash (string, strlen (string), &hc);
  GNUNET_hash_to_enc (&hc, enc);
  GNUNET_free (string);
}

static char *
getVersionFileName (struct GNUNET_GE_Context *ectx,
                    struct GNUNET_GC_Configuration *cfg)
{
  char *en;
  char *cn;

  en = NULL;
  if (-1 == GNUNET_GC_get_configuration_value_filename (cfg,
                                                        "GNUNETD",
                                                        "GNUNETD_HOME",
                                                        GNUNET_DEFAULT_DAEMON_VAR_DIRECTORY,
                                                        &en))
    return NULL;
  GNUNET_GE_ASSERT (ectx, en != NULL);
  cn = GNUNET_malloc (strlen (en) + strlen (VERSIONFILE) + 1);
  strcpy (cn, en);
  strcat (cn, VERSIONDIR);
  GNUNET_disk_directory_create (ectx, cn);
  strcpy (cn, en);
  strcat (cn, VERSIONFILE);
  GNUNET_free (en);
  return cn;
}

#define MAX_VS sizeof(GNUNET_EncName) + 64

/**
 * Check if we are up-to-date.
 * @return GNUNET_OK if we are
 */
int
GNUNET_CORE_version_check_up_to_date (struct GNUNET_GE_Context *ectx,
                                      struct GNUNET_GC_Configuration *cfg)
{
  char version[MAX_VS];
  int len;
  GNUNET_EncName enc;
  char *fn;

  fn = getVersionFileName (ectx, cfg);
  if (fn == NULL)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_BULK,
                     _
                     ("Failed to determine filename used to store GNUnet version information!\n"));
      return GNUNET_OK;         /* uh uh */
    }
  if (GNUNET_disk_file_test (ectx, fn) != GNUNET_YES)
    {
      GNUNET_free (fn);
      GNUNET_CORE_version_mark_as_up_to_date (ectx, cfg);       /* first start */
      return GNUNET_OK;
    }
  len = GNUNET_disk_file_read (ectx, fn, MAX_VS, version);
  GNUNET_free (fn);
  if (len == -1)
    {                           /* should never happen -- file should exist */
      GNUNET_CORE_version_mark_as_up_to_date (ectx, cfg);       /* first start */
      return GNUNET_OK;
    }
  if ((len != strlen (VERSION) + 1 + sizeof (GNUNET_EncName)) ||
      (0 != memcmp (VERSION, version, strlen (VERSION) + 1)))
    return GNUNET_SYSERR;       /* wrong version */
  getVersionHash (cfg, &enc);
  if (0 !=
      memcmp (&enc, &version[strlen (VERSION) + 1], sizeof (GNUNET_EncName)))
    return GNUNET_SYSERR;       /* wrong GNUNET_hash */
  return GNUNET_OK;
}

/**
 * We are up-to-date.
 * Writes the version tag
 */
void
GNUNET_CORE_version_mark_as_up_to_date (struct GNUNET_GE_Context *ectx,
                                        struct GNUNET_GC_Configuration *cfg)
{
  char version[MAX_VS];
  int len;
  GNUNET_EncName enc;
  char *fn;

  fn = getVersionFileName (ectx, cfg);
  len = strlen (VERSION) + 1 + sizeof (GNUNET_EncName);
  GNUNET_GE_ASSERT (ectx, len < MAX_VS);
  memcpy (version, VERSION, strlen (VERSION) + 1);
  getVersionHash (cfg, &enc);
  memcpy (&version[strlen (VERSION) + 1], &enc, sizeof (GNUNET_EncName));
  UNLINK (fn);
  GNUNET_disk_file_write (ectx, fn, version, len, "600");
  GNUNET_free (fn);
}

/* end of version.c */
