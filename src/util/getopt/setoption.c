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


int
GNUNET_getopt_configure_set_option (GNUNET_CommandLineProcessorContext * ctx,
                                    void *scls,
                                    const char *cmdLineOption,
                                    const char *value)
{
  char *section = GNUNET_strdup (scls);
  struct GNUNET_GC_Configuration *cfg = ctx->cfg;
  char *option;
  int ret;

  option = strstr (section, ":");
  GNUNET_GE_ASSERT (ctx->ectx, option != NULL);
  option[0] = '\0';
  option++;
  if (value == NULL)
    value = "YES";
  ret = GNUNET_GC_set_configuration_value_string (cfg,
                                                  ctx->ectx, section, option,
                                                  value);

  if (ret != 0)
    {
      GNUNET_GE_LOG (ctx->ectx,
                     GNUNET_GE_USER | GNUNET_GE_BULK | GNUNET_GE_ERROR,
                     _
                     ("Setting option `%s' in section `%s' to `%s' when processing command line option `%s' was denied.\n"),
                     option, section, value, cmdLineOption);
      GNUNET_free (section);
      return GNUNET_SYSERR;
    }
  GNUNET_free (section);
  return GNUNET_OK;
}

int
GNUNET_getopt_configure_increment_value (GNUNET_CommandLineProcessorContext *
                                         ctx, void *scls,
                                         const char *cmdLineOption,
                                         const char *value)
{
  char *section = GNUNET_strdup (scls);
  struct GNUNET_GC_Configuration *cfg = ctx->cfg;
  char *option;
  int ret;
  unsigned long long old;

  option = strstr (section, ":");
  GNUNET_GE_ASSERT (ctx->ectx, option != NULL);
  option[0] = '\0';
  option++;
  ret = GNUNET_GC_get_configuration_value_number (cfg,
                                                  section,
                                                  option,
                                                  0,
                                                  (unsigned long long) -1L, 0,
                                                  &old);
  if (ret == GNUNET_SYSERR)
    {
      GNUNET_free (section);
      return GNUNET_SYSERR;
    }
  ret = GNUNET_GC_set_configuration_value_number (cfg,
                                                  ctx->ectx,
                                                  section, option, old + 1);
  GNUNET_free (section);
  if (ret == 0)
    ret = GNUNET_OK;
  else
    ret = GNUNET_SYSERR;
  return ret;
}

int
GNUNET_getopt_configure_set_one (GNUNET_CommandLineProcessorContext * ctx,
                                 void *scls,
                                 const char *option, const char *value)
{
  int *val = scls;
  *val = 1;
  return GNUNET_OK;
}

int
GNUNET_getopt_configure_set_string (GNUNET_CommandLineProcessorContext * ctx,
                                    void *scls,
                                    const char *option, const char *value)
{
  char **val = scls;

  GNUNET_GE_ASSERT (NULL, value != NULL);
  *val = GNUNET_strdup (value);
  return GNUNET_OK;
}

int
GNUNET_getopt_configure_set_ulong (GNUNET_CommandLineProcessorContext * ctx,
                                   void *scls,
                                   const char *option, const char *value)
{
  unsigned long long *val = scls;
  if (1 != SSCANF (value, "%llu", val))
    {
      GNUNET_GE_LOG (ctx->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_IMMEDIATE | GNUNET_GE_USER,
                     _("You must pass a number to the `%s' option.\n"), "-X");
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

int
GNUNET_getopt_configure_set_uint (GNUNET_CommandLineProcessorContext * ctx,
                                  void *scls,
                                  const char *option, const char *value)
{
  unsigned int *val = scls;

  if (1 != SSCANF (value, "%u", val))
    {
      GNUNET_GE_LOG (ctx->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_IMMEDIATE | GNUNET_GE_USER,
                     _("You must pass a number to the `%s' option.\n"), "-X");
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}


/* end of setoption.c */
