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
 * @file include/gnunet_config_impl.h
 * @brief configuration API
 *
 * @author Christian Grothoff
 */

#ifndef GNUNET_UTIL_CONFIG_IMPL_H
#define GNUNET_UTIL_CONFIG_IMPL_H

#include "gnunet_util_config.h"

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

struct GC_ConfigurationData;

typedef struct GC_Configuration {

  /**
   * Internal configuration data.
   */
  struct GC_ConfigurationData * data;

  void (*free)(struct GC_Configuration * cfg);

  /**
   * Set the context for reporting configuration IO errors
   * (and errors reported by configuration change notification
   * callbacks when reading a new configuration).
   *
   * Note that for setting options a different context can be
   * used (since failing to change an option may have to be reported
   * in a fundamentally different way to the user).
   *
   * @parm ectx maybe NULL, in that case errors will no longer
   *       be reported
   */
  void (*set_error_context)(struct GC_Configuration * cfg,
			    struct GE_Context * ectx);

  /**
   * Parse a configuration file, add all of the options in the
   * file to the configuration environment.
   * @return 0 on success, -1 on error
   */
  int (*parse_configuration)(struct GC_Configuration * cfg,
			     const char * filename);

  /**
   * Test if there are configuration options that were
   * changed since the last save.
   * @return 0 if clean, 1 if dirty, -1 on error (i.e. last save failed)
   */
  int (*test_dirty)(struct GC_Configuration * cfg);


  /**
   * Write configuration file.
   * @return 0 on success, -1 on error
   */
  int (*write_configuration)(struct GC_Configuration * cfg,
			     const char * filename);


  /**
   * Expand an expression of the form "$FOO/BAR" to "DIRECTORY/BAR"
   * where either in the current section or globally FOO is set to
   * DIRECTORY.
   *
   * @param old string to $-expand (will be freed!)
   * @return $-expanded string
   */
  char * (*configuration_expand_dollar)(struct GC_Configuration * cfg,
					char * old);

  /**
   * Get a configuration value that should be a number.
   * @param min minimal legal value
   * @param max maximal legal value
   * @param def default value (use indicated by return value)
   * @return 0 on success, -1 on error, 1 for default
   */
  int (*get_configuration_value_number)(struct GC_Configuration * cfg,
					const char * section,
					const char * option,
					unsigned long long min,
					unsigned long long max,
					unsigned long long def,
					unsigned long long * number);


  /**
   * Get a configuration value that should be a string.
   * @param default default value (use indicated by return value;
   *        will NOT be aliased, maybe NULL)
   * @param value will be set to a freshly allocated configuration
   *        value, or NULL if option is not specified and no default given
   * @return 0 on success, -1 on error, 1 for default
   */
  int (*get_configuration_value_string)(struct GC_Configuration * cfg,
					const char * section,
					const char * option,
					const char * def,
					char ** value);

  /**
   * Get a configuration value that should be a file name.
   * @param default default value (use indicated by return value;
   *        will NOT be aliased, maybe NOT be NULL)
   * @param value will be set to a freshly allocated configuration
   *        value, or NULL if option is not specified and no default given
   * @return 0 on success, -1 on error, 1 for default
   */
  int (*get_configuration_value_filename)(struct GC_Configuration * cfg,
					  const char * section,
					  const char * option,
					  const char * def,
					  char ** value);

  /**
   * Get a configuration value that should be in a set of
   * predefined strings
   * @param choices NULL-terminated list of legal values
   * @param default default value (use indicated by return value;
   *        will NOT be aliased, maybe NULL), must be reference
   *        into set given by choices
   * @param value will be set to an entry in the legal list,
   *        or NULL if option is not specified and no default given
   * @return 0 on success, -1 on error, 1 for default
   */
  int (*get_configuration_value_choice)(struct GC_Configuration * cfg,
					const char * section,
					const char * option,
					const char ** choices,
					const char * def,
					const char ** value);

  /**
   * Set a configuration value that should be a number.
   * @return 0 on success, -1 on error (i.e. out of memory,
   *   or update refused by registered callback)
   */
  int (*set_configuration_value_number)(struct GC_Configuration * cfg,
					struct GE_Context * ectx,
					const char * section,
					const char * option,
					unsigned long long number);


  /**
   * Set a configuration value that should be a string.
   * @param value
   * @return 0 on success, -1 on error (i.e. out of memory,
   *   or update refused by registered callback)
   */
  int (*set_configuration_value_string)(struct GC_Configuration * cfg,
					struct GE_Context * ectx,
					const char * section,
					const char * option,
					const char * value);

  /**
   * Set a configuration value that should be in a set of
   * predefined strings.
   * @param value
   * @return 0 on success, -1 on error (i.e. out of memory,
   *   or update refused by registered callback)
   */
  int (*set_configuration_value_choice)(struct GC_Configuration * cfg,
					struct GE_Context * ectx,
					const char * section,
					const char * option,
					const char * choice);

  /**
   * Attach a callback that is notified whenever a
   * configuration option changes.
   * @return 0 on success, -1 on error
   */
  int (*attach_change_listener)(struct GC_Configuration * cfg,
				GC_ChangeListener callback,
				void * ctx);

  /**
   * Attach a callback that is notified whenever a
   * configuration option changes.
   * @return 0 on success, -1 on error, 1 for no such handler registered
   */
  int (*detach_change_listener)(struct GC_Configuration * cfg,
				GC_ChangeListener callback,
				void * ctx);

  int (*have_configuration_value)(struct GC_Configuration * cfg,
				  const char * section,
				  const char * option);

} GC_Configuration;

/**
 * Create a GC_Configuration (C implementation).
 */
GC_Configuration * GC_create_C_impl(void);


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
