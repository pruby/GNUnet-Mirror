/*
     This file is part of GNUnet.
     (C) 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/testing/remotetest.c
 * @brief Testcase for remote library
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_remote_lib.h"
#include "gnunet_directories.h"
#include "remote.h"

static char *configFile = GNUNET_DEFAULT_DAEMON_CONFIG_FILE;
static unsigned long long number_of_daemons;

static struct GNUNET_CommandLineOption gnunetRemoteOptions[] = {
  GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&configFile),    /* -c */
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Set up multiple gnunetd daemons across multiple hosts.")),    /* -h */
  GNUNET_COMMAND_LINE_OPTION_HOSTNAME,  /* -H */
  GNUNET_COMMAND_LINE_OPTION_LOGGING,   /* -L */
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION), /* -v */
  {'n', "number_of_daemons", "NUMBER_OF_DAEMONS",
   gettext_noop ("set number of daemons to start"),
   1, &GNUNET_getopt_configure_set_ulong, &number_of_daemons},  /* -n */
  GNUNET_COMMAND_LINE_OPTION_VERBOSE,
  GNUNET_COMMAND_LINE_OPTION_END,
};

/**
 * Testcase
 * @return 0: ok, -1: error
 */
int
main (int argc, char *const *argv)
{
  int res;

  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GC_Configuration *hostConfig;
  res =
    GNUNET_init (argc, argv, "remotetest", &configFile, gnunetRemoteOptions,
                 &ectx, &cfg);

  if (res == -1)
    {
      GNUNET_fini (ectx, cfg);
      return -1;
    }

  hostConfig = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (hostConfig, configFile))
    {
      GNUNET_free (hostConfig);
      GNUNET_free (configFile);
      GNUNET_fini (ectx, cfg);
      return -1;
    }

  GNUNET_REMOTE_start_daemons (hostConfig, number_of_daemons);

  GNUNET_GC_free (hostConfig);
  GNUNET_fini (ectx, cfg);
  return GNUNET_OK;
}

/* end of remotetest.c */
