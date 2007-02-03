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
 * @file util/os/statuscallstest.c
 * @brief testcase for util/os/statuscalls.c
 */

#include "gnunet_util.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_error_loggers.h"
#include "platform.h"

int main(int argc, char * argv[]){
  int ret;
  cron_t start;
  struct GE_Context * ectx;
  struct GC_Configuration * cfg;

  ectx = GE_create_context_stderr(NO,
				  GE_WARNING | GE_ERROR | GE_FATAL |
				  GE_USER | GE_ADMIN | GE_DEVELOPER |
				  GE_IMMEDIATE | GE_BULK);
  GE_setDefaultContext(ectx);
  cfg = GC_create_C_impl();
  GE_ASSERT(ectx, cfg != NULL);
  os_init(ectx);
  /* need to run each phase for more than 10s since
     statuscalls only refreshes that often... */
  start = get_time();
  while (start + 12 * cronSECONDS > get_time())
    PTHREAD_SLEEP(1);
  start = get_time();
  ret = os_cpu_get_load(ectx,
			cfg);
  while (start + 60 * cronSECONDS > get_time())
    sqrt(245.2523); /* do some processing to drive load up */
  if (ret > os_cpu_get_load(ectx,
			    cfg)) {
    printf("busy loop decreased CPU load: %d < %d.\n",
	   ret,
	   os_cpu_get_load(ectx,
			   cfg));
    ret = 1;
  } else {
    ret = 0;
  }
  GC_free(cfg);
  GE_free_context(ectx);
  return ret;
}
