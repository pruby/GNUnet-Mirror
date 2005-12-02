/*
     This file is part of GNUnet.
     (C) 2005 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/fsui/namespace_infotest.c
 * @brief testcase for namespace_info.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
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
  FREENONNULL(setConfigurationString("GNUNET",
				     "GNUNET_HOME",
				     "/tmp/gnunet-namespace-infotest"));
  return OK;
}


static void eventCallback(void * cls,
			  const FSUI_Event * event) {
}


int main(int argc, char * argv[]){
  pid_t daemon;
  int ok;
  struct ECRS_URI * uri = NULL;
  struct ECRS_URI * euri = NULL;
  struct ECRS_MetaData * meta = NULL;
  HashCode512 root;
  int old;
  struct FSUI_Context * ctx;

  if (OK != initUtil(argc,
		     argv,
		     &parseCommandLine))
    return -1;
  daemon = startGNUnetDaemon(NO);
  GNUNET_ASSERT(daemon > 0);
  ok = YES;
  startCron();
  GNUNET_ASSERT(OK == waitForGNUnetDaemonRunning(2 * cronMINUTES));
  ECRS_deleteNamespace("test");
  gnunet_util_sleep(5 * cronSECONDS); /* give apps time to start */

  /* ACTUAL TEST CODE */
  ctx = FSUI_start("namespace_infotest",
		   NO,
		   &eventCallback,
		   NULL);
  CHECK(ctx != NULL);
  old = FSUI_listNamespaces(ctx,
			    YES,
			    NULL,
			    NULL);
				
  meta = ECRS_createMetaData();
  ECRS_addToMetaData(meta,
		     0,
		     "test");
  hash("root", 4, &root);
  uri = FSUI_createNamespace(ctx,
			     1,
			     "test",
			     meta,
			     NULL,
			     &root);
  CHECK(uri != NULL);
  CHECK(old + 1 == FSUI_listNamespaces(ctx,
				       YES,
				       NULL,
				       NULL));
  old = FSUI_listNamespaceContent(ctx,
				  "test",
				  NULL,
				  NULL);
  euri = FSUI_addToNamespace(ctx,
			     1,
			     "test",
			     42,
			     NULL,
			     &root,
			     NULL,
			     uri,
			     meta);
  CHECK(euri != NULL);
  CHECK(old + 1 == FSUI_listNamespaceContent(ctx,
					     "test",
					     NULL,
					     NULL));
  CHECK(OK == ECRS_deleteNamespace("test"));
  /* END OF TEST CODE */
 FAILURE:
  if (ctx != NULL)
    FSUI_stop(ctx);
  if (uri != NULL)
    ECRS_freeUri(uri);
  if (euri != NULL)
    ECRS_freeUri(euri);
  if (meta != NULL)
    ECRS_freeMetaData(meta);
  ECRS_deleteNamespace("test");
  stopCron();
  GNUNET_ASSERT(OK == stopGNUnetDaemon());
  GNUNET_ASSERT(OK == waitForGNUnetDaemonTermination(daemon));
  doneUtil();
  return (ok == YES) ? 0 : 1;
}

/* end of namespace_infotest.c */
