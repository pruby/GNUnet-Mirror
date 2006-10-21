/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/config_impl/configtest.c
 * @brief Test that the configuration module works.
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "platform.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_error_loggers.h"

static struct GC_Configuration * cfg;

static int testConfig() {
  char * c;
  unsigned long long l;

  if (0 != GC_get_configuration_value_string(cfg,
					     "test",
					     "b",
					     NULL,
					     &c))
    return 1;
  if (0 != strcmp("b",
		  c))
    return 1;
  FREE(c);
  if (0 != GC_get_configuration_value_number(cfg,
					     "test",
					     "five",
					     0,
					     10,
					     9,
					     &l))
    return 1;
  if (5 != l)
    return 1;
  GC_set_configuration_value_string(cfg,
				    NULL,
				    "more",
				    "c",
				    "YES");
  if (NO == GC_get_configuration_value_yesno(cfg,
					     "more",
					     "c",
					     NO))
    return 1;
  return 0;
}

int main(int argc,
	 char * argv[]) {
  struct GE_Context * ectx;
  int failureCount = 0;

  ectx = GE_create_context_stderr(NO,
				  GE_WARNING | GE_ERROR | GE_FATAL |
				  GE_USER | GE_ADMIN | GE_DEVELOPER |
				  GE_IMMEDIATE | GE_BULK);
  GE_setDefaultContext(ectx);
  cfg = GC_create_C_impl();
  if (0 != GC_parse_configuration(cfg,
				  "testconfig.conf")) {
    fprintf(stderr,
	    "Failed to parse configuration file\n");
    return 1;
  }
  GE_ASSERT(ectx, cfg != NULL);
  os_init(ectx);
  failureCount += testConfig();

  if (failureCount != 0)
    return 1;
  return 0;
}
