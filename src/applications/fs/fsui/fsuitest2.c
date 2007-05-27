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
 * @file applications/fs/fsui/fsuitest2.c
 * @brief testcase for fsui (upload-download)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"

#define CHECK(a) if (!(a)) { ok = NO; GE_BREAK(NULL, 0); goto FAILURE; }


static struct FSUI_Context * ctx;

static void * eventCallback(void * cls,
			    const FSUI_Event * event) {
  return NULL;
}

#define START_DAEMON 1

int main(int argc, char * argv[]){
#if START_DAEMON
  pid_t daemon;
#endif
  int ok;
  struct GC_Configuration * cfg;

  cfg = GC_create_C_impl();
  if (-1 == GC_parse_configuration(cfg,
				   "check.conf")) {
    GC_free(cfg);
    return -1;
  }
#if START_DAEMON
  daemon  = os_daemon_start(NULL,
			    cfg,
			    "peer.conf",
			    NO);
  GE_ASSERT(NULL, daemon > 0);
  CHECK(OK == connection_wait_for_running(NULL,
					  cfg,
					  60 * cronSECONDS));
#endif
  ok = YES;
  PTHREAD_SLEEP(5 * cronSECONDS); /* give apps time to start */

  /* ACTUAL TEST CODE */
  ctx = FSUI_start(NULL,
		   cfg,
		   "fsuitest2",
		   32,
		   YES, /* do resume! */
		   &eventCallback,
		   NULL);
  CHECK(ctx != NULL);
  FSUI_stop(ctx);
  ctx = FSUI_start(NULL,
		   cfg,
		   "fsuitest2",
		   32,
		   YES,
		   &eventCallback,
		   NULL);
  CHECK(ctx != NULL);
 FAILURE:
  if (ctx != NULL)
    FSUI_stop(ctx);
#if START_DAEMON
  GE_ASSERT(NULL, OK == os_daemon_stop(NULL, daemon));
#endif
  GC_free(cfg);

  return (ok == YES) ? 0 : 1;
}

/* end of fsuitest2.c */
