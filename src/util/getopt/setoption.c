/*
     This file is part of GNUnet
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
 * @file src/util/getopt/setoption.c
 * @brief implements command line that sets option
 * @author Christian Grothoff
 */

#include "gnunet_util_string.h"
#include "gnunet_util_config.h"
#include "gnunet_util_getopt.h"
#include "platform.h"


int gnunet_getopt_configure_set_option(CommandLineProcessorContext * ctx,
				       void * scls,
				       const char * cmdLineOption,
				       const char * value) {
  char * section = STRDUP(scls);
  struct GC_Configuration * cfg = ctx->cfg;
  char * option;
  int ret;

  option = strstr(section, ":");
  GE_ASSERT(ctx->ectx,
	    option != NULL);
  option[0] = '\0';
  option++;
  ret = GC_set_configuration_value_string(cfg,
					  ctx->ectx,
					  section,
					  option,
					  value);
  FREE(section);
  return ret;
}

int gnunet_getopt_configure_increment_value(CommandLineProcessorContext * ctx,
					    void * scls,
					    const char * cmdLineOption,
					    const char * value) {
  char * section = STRDUP(scls);
  struct GC_Configuration * cfg = ctx->cfg;
  char * option;
  int ret;
  unsigned long long old;

  option = strstr(section, ":");
  GE_ASSERT(ctx->ectx,
	    option != NULL);
  option[0] = '\0';
  option++;
  ret = GC_get_configuration_value_number(cfg,
					  section,
					  option,
					  0,
					  (unsigned long long) -1L,
					  0,
					  &old);
  if (ret == SYSERR) {
    FREE(section);
    return SYSERR;
  }
  ret = GC_set_configuration_value_number(cfg,
					  ctx->ectx,
					  section,
					  option,
					  old+1);
  FREE(section);
  return ret;
}

/* end of setoption.c */
