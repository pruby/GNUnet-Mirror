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
  if (value == NULL)
    value = "YES";
  ret = GC_set_configuration_value_string(cfg,
					  ctx->ectx,
					  section,
					  option,
					  value);

  if (ret != 0) {
    GE_LOG(ctx->ectx,
	   GE_USER | GE_BULK | GE_ERROR,
	   _("Setting option `%s' in section `%s' to `%s' when processing command line option `%s' was denied.\n"),
	   option,
	   section,
	   value,
	   cmdLineOption);
    FREE(section);
    return SYSERR;
  }
  FREE(section);
  return OK;
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
  if (ret == 0)
    ret = OK;
  else
    ret = SYSERR;
  return ret;
}

int gnunet_getopt_configure_set_one(CommandLineProcessorContext * ctx,
				    void * scls,
				    const char * option,
				    const char * value) {
  int * val = scls;
  *val = 1;
  return OK;
}

int gnunet_getopt_configure_set_string(CommandLineProcessorContext * ctx,
				       void * scls,
				       const char * option,
				       const char * value) {
  char ** val = scls;

  GE_ASSERT(NULL, value != NULL);
  *val = STRDUP(value);
  return OK;
}

int gnunet_getopt_configure_set_ulong(CommandLineProcessorContext * ctx,
				      void * scls,
				      const char * option,
				      const char * value) {
  unsigned long long * val = scls;
  if (1 != SSCANF(value, "%llu", val)) {
    GE_LOG(ctx->ectx,
	   GE_ERROR | GE_IMMEDIATE | GE_USER,
	   _("You must pass a number to the `%s' option.\n"),
	   "-X");
    return SYSERR;
  }
  return OK;
}

int gnunet_getopt_configure_set_uint(CommandLineProcessorContext * ctx,
				     void * scls,
				     const char * option,
				     const char * value) {
  unsigned int * val = scls;

  if (1 != SSCANF(value, "%u", val)) {
    GE_LOG(ctx->ectx,
	   GE_ERROR | GE_IMMEDIATE | GE_USER,
	   _("You must pass a number to the `%s' option.\n"),
	   "-X");
    return SYSERR;
  }
  return OK;
}


/* end of setoption.c */
