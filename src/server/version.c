/*
     This file is part of GNUnet.
     (C) 2004 Christian Grothoff (and other contributing authors)

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
#include "version.h"

/**
 * Extend string by "section:part=val;" where
 * val is the configuration value from the
 * configuration file.
 */
static void dyncat(char ** string,
		   const char * section,
		   const char * part) {
  int len;
  char * tmp;
  char * val;

  len = strlen(*string);
  len += strlen(section) + 1;
  len += strlen(part) + 1;
  val = getConfigurationString(section, part);
  if (val == NULL)
    val = STRDUP("");
  len += strlen(val) + 2;
  tmp = MALLOC(len);
  strcpy(tmp, *string);
  strcat(tmp, section);
  strcat(tmp, ":");
  strcat(tmp, part);
  strcat(tmp, "=");
  strcat(tmp, val);
  strcat(tmp, ";");
  FREE(val);
  FREE(*string);
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
static void getVersionHash(EncName * enc) {
  HashCode512 hc;
  char * string;

  string = STRDUP("");
  /* yes, this is a bit ugly since we break the isolation between core
     and apps, but adding code to query the apps which configuration
     changes require gnunet-update feels like overkill for now; one
     simple alternative would be to require gnunet-update for any
     configuration change, but that again would be too strict. */
  dyncat(&string, "GNUNETD", "APPLICATIONS");
  dyncat(&string, "FS", "QUOTA");
  dyncat(&string, "MODULES", "sqstore");
  hash(string,
       strlen(string),
       &hc);
  hash2enc(&hc, enc);
  FREE(string);
}

/**
 * Check if we are up-to-date.
 * @return OK if we are
 */
int checkUpToDate() {
  char * version;
  int len;
  EncName enc;

  version = NULL;
  len = stateReadContent("GNUNET-VERSION",
			 (void**)&version);
  if (len == -1) {
    upToDate(); /* first start */
    return OK;
  }
  if ( (len != strlen(VERSION) + 1 + sizeof(EncName)) ||
       (0 != memcmp(VERSION,
		    version,
		    strlen(VERSION)+1)) ) {
    FREENONNULL(version);
    return SYSERR; /* wrong version */
  }
  getVersionHash(&enc);
  if (0 != memcmp(&enc,
		  &version[strlen(VERSION)+1],
		  sizeof(EncName))) {
    FREENONNULL(version);
    return SYSERR; /* wrong hash */
  }
  FREENONNULL(version);
  return OK;
}

/**
 * We are up-to-date.
 * Writes the version tag
 */
void upToDate() {
  char * version;
  int len;
  EncName enc;

  len = strlen(VERSION) + 1 + sizeof(EncName);
  version = MALLOC(len);
  memcpy(version, VERSION, strlen(VERSION)+1);
  getVersionHash(&enc);
  memcpy(&version[strlen(VERSION)+1], &enc, sizeof(EncName));
  stateWriteContent("GNUNET-VERSION",
		    len,
		    version);
  FREE(version);
}
		
/* end of version.c */
