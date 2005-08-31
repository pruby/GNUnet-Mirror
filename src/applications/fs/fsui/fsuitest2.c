/*
     This file is part of GNUnet.
     (C) 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/fsui/fsuitest.c
 * @brief testcase for fsui (upload-download)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_fsui_lib.h"

#define CHECK(a) if (!(a)) { ok = NO; BREAK(); goto FAILURE; }

static int parseCommandLine(int argc,
			    char * argv[]) {
  FREENONNULL(setConfigurationString("GNUNETD",
				     "_MAGIC_",
				     "NO"));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  FREENONNULL(setConfigurationString("GNUNET",
				     "LOGLEVEL",
				     "NOTHING"));
  FREENONNULL(setConfigurationString("GNUNET",
				     "GNUNETD-CONFIG",
				     "check.conf"));
  return OK;
}

static struct FSUI_Context * ctx;

static void eventCallback(void * cls,
			  const FSUI_Event * event) {
}


int main(int argc, char * argv[]){
  pid_t daemon;
  int ok;

  if (OK != initUtil(argc,
		     argv,
		     &parseCommandLine))
    return -1;
  daemon = startGNUnetDaemon(NO);
  GNUNET_ASSERT(daemon > 0);
  ok = YES;
  startCron();
  GNUNET_ASSERT(OK == waitForGNUnetDaemonRunning(30 * cronSECONDS));
  gnunet_util_sleep(5 * cronSECONDS); /* give apps time to start */

  /* ACTUAL TEST CODE */
  ctx = FSUI_start("fsuitest2",
		   YES,
		   &eventCallback,
		   NULL);
  CHECK(ctx != NULL);
  FSUI_stop(ctx);
  /* ACTUAL TEST CODE */
  ctx = FSUI_start("fsuitest2",
		   YES,
		   &eventCallback,
		   NULL);
  CHECK(ctx != NULL);
 FAILURE:
  if (ctx != NULL)
    FSUI_stop(ctx);

  stopCron();
  GNUNET_ASSERT(OK == stopGNUnetDaemon());
  GNUNET_ASSERT(OK == waitForGNUnetDaemonTermination(daemon));
  doneUtil();
  return (ok == YES) ? 0 : 1;
}

/* end of fsuitest2.c */
