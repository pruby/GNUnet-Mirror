/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/fsui/fsui-loader.c
 * @brief little program to just load and unload an FSUI file
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_util_config_impl.h"

static void * eventCallback(void * cls,
			    const FSUI_Event * event) {
#if 0
  switch(event->type) {
  case FSUI_search_result:
    printf("Received search result\n");
    break;
  case FSUI_upload_complete:
    printf("Upload complete.\n");
    break;
  case FSUI_download_complete:
    printf("Download complete.\n");
    break;
  case FSUI_unindex_complete:
    printf("Unindex complete.\n");
    break;
  default:
    printf("Other event.\n");
    break;
  }
#endif
  return NULL;
}

int main(int argc,
	 char * argv[]) {
  struct FSUI_Context * ctx;
  struct GC_Configuration * cfg;

  os_init(NULL);
  cfg = GC_create_C_impl();
  if (argc != 2) {
    fprintf(stderr,
	    "Call with name of FSUI resource file!\n");
    return -1;
  }
  ctx = FSUI_start(NULL,
		   cfg,
		   argv[1],
		   16,
		   YES,
		   &eventCallback,
		   NULL);
  if (ctx != NULL)
    FSUI_stop(ctx);
  else
    fprintf(stderr,
	    "FSUI_start failed!\n");
  GC_free(cfg);
  return (ctx == NULL);
}
