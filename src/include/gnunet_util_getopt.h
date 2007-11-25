/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_util_getopt.h
 * @brief command line parsing and --help formatting
 *
 * @author Christian Grothoff
 */

#ifndef GNUNET_UTIL_GETOPT_H
#define GNUNET_UTIL_GETOPT_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_config.h"

/**
 * @brief General context for command line processors.
 */
typedef struct
{

  /**
   * Name of the application
   */
  const char *binaryName;

  /**
   * Name of application with option summary
   */
  const char *binaryOptions;

  /**
   * Array with all command line options.
   */
  const struct GNUNET_CommandLineOption *allOptions;

  /**
   * Original command line
   */
  char *const *argv;

  /**
   * Total number of argv's.
   */
  unsigned int argc;

  /**
   * Current argument.
   */
  unsigned int currentArgument;

  /**
   * For logging errors
   */
  struct GNUNET_GE_Context *ectx;

  /**
   * For configuration
   */
  struct GNUNET_GC_Configuration *cfg;

} GNUNET_CommandLineProcessorContext;

/**
 * @brief Process a command line option
 *
 * @param ctx context for all options
 * @param scls specific closure (for this processor)
 * @param option long name of the option (i.e. "config" for --config)
 * @param value argument, NULL if none was given
 * @return GNUNET_OK to continue processing other options, GNUNET_SYSERR to abort
 */
typedef
  int (*GNUNET_CommandLineOptionProcessor) (GNUNET_CommandLineProcessorContext
                                            * ctx, void *scls,
                                            const char *option,
                                            const char *value);

/**
 * @brief Definition of a command line option.
 */
typedef struct GNUNET_CommandLineOption
{

  /**
   * Short name of the option (use '\0' for none).
   */
  const char shortName;

  /**
   * Long name of the option (may not be NULL)
   */
  const char *name;

  /**
   * Name of the argument for the user in help text
   */
  const char *argumentHelp;

  /**
   * Help text for the option (description)
   */
  const char *description;

  /**
   * Is an argument required?  0: GNUNET_NO (includes optional), 1: GNUNET_YES.
   */
  int require_argument;

  /**
   * Handler for the option.
   */
  GNUNET_CommandLineOptionProcessor processor;

  /**
   * Specific closure to pass to the processor.
   */
  void *scls;

} GNUNET_CommandLineOption;

/**
 * Macro defining the option to print the command line
 * help text.
 *
 * @param about string with brief description of the application
 */
#define GNUNET_COMMAND_LINE_OPTION_HELP(about) \
  { 'h', "help", (const char *) NULL, gettext_noop("print this help"), 0, &GNUNET_getopt_format_help_, (void *) about }

/**
 * Macro defining the option to print the version of
 * the application
 *
 * @param version string with the version number
 */
#define GNUNET_COMMAND_LINE_OPTION_VERSION(version) \
  { 'v', "version", (const char *) NULL, gettext_noop("print the version number"), 0, &GNUNET_getopt_print_version_, (void *) version }

/**
 * Set the configuration option for logging.
 */
#define GNUNET_COMMAND_LINE_OPTION_LOGGING \
  { 'L', "log", "LOGLEVEL", gettext_noop("configure logging to use LOGLEVEL"), 1, &GNUNET_getopt_configure_set_option, (void *) "LOGGING:USER-LEVEL" }

/**
 * Set the configuration option for increasing verbosity.
 */
#define GNUNET_COMMAND_LINE_OPTION_VERBOSE \
  { 'V', "verbose", (const char *) NULL, gettext_noop("be verbose"), 0, &GNUNET_getopt_configure_increment_value, (void *) "GNUNET:VERBOSE" }

/**
 * Set the configuration option for the configuration file.
 */
#define GNUNET_COMMAND_LINE_OPTION_CFG_FILE(fn)				\
  { 'c', "config", "FILENAME", gettext_noop("use configuration file FILENAME"), 1, &GNUNET_getopt_configure_set_string, (void *) fn }

/**
 * Set the configuration option for the configuration file.
 */
#define GNUNET_COMMAND_LINE_OPTION_HOSTNAME \
  { 'H', "host", "HOSTNAME", gettext_noop("specify host on which gnunetd is running"), 1, &GNUNET_getopt_configure_set_option, (void *) "NETWORK:HOST" }

/**
 * Marker to end the list of options.
 */
#define GNUNET_COMMAND_LINE_OPTION_END \
  { '\0', NULL, NULL, NULL, 0, NULL, NULL }

/**
 * Parse the command line.
 *
 * @param binaryName name of the binary / application with options
 * @param ectx for reporting errors
 * @param cfg for storing/accessing configuration data
 * @param allOptions defined options and handlers
 * @param argc number of arguments
 * @param argv actual arguments
 * @return index into argv with first non-option
 *   argument, or -1 on error
 */
int GNUNET_parse_options (const char *binaryName,
                          struct GNUNET_GE_Context *ectx,
                          struct GNUNET_GC_Configuration *cfg,
                          const GNUNET_CommandLineOption * allOptions,
                          unsigned int argc, char *const *argv);

int GNUNET_getopt_configure_set_option (GNUNET_CommandLineProcessorContext *
                                        ctx, void *scls, const char *option,
                                        const char *value);

int GNUNET_getopt_configure_set_ulong (GNUNET_CommandLineProcessorContext *
                                       ctx, void *scls, const char *option,
                                       const char *value);

int GNUNET_getopt_configure_set_uint (GNUNET_CommandLineProcessorContext *
                                      ctx, void *scls, const char *option,
                                      const char *value);

int GNUNET_getopt_configure_set_one (GNUNET_CommandLineProcessorContext * ctx,
                                     void *scls,
                                     const char *option, const char *value);

int GNUNET_getopt_configure_set_string (GNUNET_CommandLineProcessorContext *
                                        ctx, void *scls, const char *option,
                                        const char *value);

int
GNUNET_getopt_configure_increment_value (GNUNET_CommandLineProcessorContext *
                                         ctx, void *scls, const char *option,
                                         const char *value);

/* *************** internal prototypes - use macros above! ************* */

int GNUNET_getopt_format_help_ (GNUNET_CommandLineProcessorContext * ctx,
                                void *scls,
                                const char *option, const char *value);

int GNUNET_getopt_print_version_ (GNUNET_CommandLineProcessorContext * ctx,
                                  void *scls,
                                  const char *option, const char *value);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_UTIL_GETOPT_H */
#endif
/* end of gnunet_util_getopt.h */
