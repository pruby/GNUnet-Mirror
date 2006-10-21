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
 * @file util/boot/startup.c
 * @brief standard code for GNUnet startup and shutdown
 * @author Christian Grothoff
 */

#include "gnunet_util_boot.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_error_loggers.h"
#include "platform.h"

/**
 * Run a standard GNUnet startup sequence
 * (initialize loggers and configuration,
 * parse options).
 *
 * @return -1 on error, position of next
 *  command-line argument to be processed in argv
 *  otherwise
 */
int GNUNET_init(int argc,
		const char ** argv,
		const char * binaryName,
		char ** cfgFileName,
		const struct CommandLineOption * options,
		struct GE_Context ** ectx,
		struct GC_Configuration ** cfg) {
  int i;

  *ectx = GE_create_context_stderr(NO,
				   GE_WARNING | GE_ERROR | GE_FATAL |
				   GE_USER | GE_ADMIN | GE_DEVELOPER |
				   GE_IMMEDIATE | GE_BULK);
  GE_setDefaultContext(*ectx);
  os_init(*ectx);
  *cfg = GC_create_C_impl();
  GE_ASSERT(*ectx, *cfg != NULL);
  i = gnunet_parse_options(binaryName,
			   *ectx,
			   *cfg,
			   options,
			   (unsigned int) argc,
			   argv);
  if (i == -1)
    return -1;
  if (OK != GC_parse_configuration(*cfg,
				   *cfgFileName)) 
    return -1;
  return i;
}

/**
 * Free resources allocated during GNUnet_init.
 */
void GNUNET_fini(struct GE_Context * ectx,
		 struct GC_Configuration * cfg) {
  GC_free(cfg);
  GE_free_context(ectx);
}
		
