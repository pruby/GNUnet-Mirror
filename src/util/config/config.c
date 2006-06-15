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
 * @file src/util/config/config.c
 * @brief configuration API
 *
 * @author Christian Grothoff
 */

#include "gnunet_util_config_impl.h"

void GC_free(struct GC_Configuration * cfg) {
  cfg->free(cfg);
}

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
void GC_set_error_context(struct GC_Configuration * cfg,
			  struct GE_Context * ectx) {
  cfg->set_error_context(cfg, ectx);
}

/**
 * Parse a configuration file, add all of the options in the
 * file to the configuration environment.
 * @return 0 on success, -1 on error
 */
int GC_parse_configuration(struct GC_Configuration * cfg,
			   const char * filename) {
  return cfg->parse_configuration(cfg, filename);
}

/**
 * Test if there are configuration options that were
 * changed since the last save.
 * @return 0 if clean, 1 if dirty, -1 on error (i.e. last save failed)
 */
int GC_test_dirty(struct GC_Configuration * cfg) {
  return cfg->test_dirty(cfg);
}


/**
 * Write configuration file.
 * @return 0 on success, -1 on error
 */
int GC_write_configuration(struct GC_Configuration * cfg,
			   const char * filename) {
  return cfg->write_configuration(cfg, filename);
}

/**
 * Get a configuration value that should be a number.
 * @param min minimal legal value
 * @param max maximal legal value
 * @param def default value (use indicated by return value)
 * @return 0 on success, -1 on error, 1 for default
 */
int GC_get_configuration_value_number(struct GC_Configuration * cfg,
				      const char * section,
				      const char * option,
				      unsigned long long min,
				      unsigned long long max,
				      unsigned long long def,
				      unsigned long long * number) {
  return cfg->get_configuration_value_number(cfg, section, option, min, max, def, number);
}


/**
 * Get a configuration value that should be a string.
 * @param def default value (use indicated by return value;
 *        will NOT be aliased, maybe NULL)
 * @param value will be set to a freshly allocated configuration
 *        value, or NULL if option is not specified and no default given
 * @return 0 on success, -1 on error, 1 for default
 */
int GC_get_configuration_value_string(struct GC_Configuration * cfg,
				      const char * section,
				      const char * option,
				      const char * def,
				      char ** value) {
  return cfg->get_configuration_value_string(cfg, section, option, def, value);
}

/**
 * Get a configuration value that should be in a set of
 * predefined strings
 * @param choices NULL-terminated list of legal values
 * @param def default value (use indicated by return value;
 *        will NOT be aliased, maybe NULL), must be reference
 *        into set given by choices
 * @param value will be set to an entry in the legal list,
 *        or NULL if option is not specified and no default given
 * @return 0 on success, -1 on error, 1 for default
 */
int GC_get_configuration_value_choice(struct GC_Configuration * cfg,
				      const char * section,
				      const char * option,
				      const char ** choices,
				      const char * def,
				      const char ** value) {
  return cfg->get_configuration_value_choice(cfg, section, option, choices, def, value);
}

/**
 * Set a configuration value that should be a number.
 * @return 0 on success, -1 on error (i.e. out of memory,
 *   or update refused by registered callback)
 */
int GC_set_configuration_value_number(struct GC_Configuration * cfg,
				      struct GE_Context * ectx,
				      const char * section,
				      const char * option,
				      unsigned long long number) {
  return cfg->set_configuration_value_number(cfg, ectx, section, option, number);
}


/**
 * Set a configuration value that should be a string.
 * @param value
 * @return 0 on success, -1 on error (i.e. out of memory,
 *   or update refused by registered callback)
 */
int GC_set_configuration_value_string(struct GC_Configuration * cfg,
				      struct GE_Context * ectx,
				      const char * section,
				      const char * option,
				      const char * value) {
  return cfg->set_configuration_value_string(cfg, ectx, section, option, value);
}

/**
 * Set a configuration value that should be in a set of
 * predefined strings.  
 * @param value
 * @return 0 on success, -1 on error (i.e. out of memory,
 *   or update refused by registered callback)
 */
int GC_set_configuration_value_choice(struct GC_Configuration * cfg,
				      struct GE_Context * ectx,
				      const char * section,
				      const char * option,
				      const char * choice) {
  return cfg->set_configuration_value_choice(cfg, ectx, section, option, choice);
}

/**
 * Attach a callback that is notified whenever a 
 * configuration option changes.
 * @return 0 on success, -1 on error
 */
int GC_attach_change_listener(struct GC_Configuration * cfg,
			      GC_ChangeListener callback,
			      void * ctx) {
  return cfg->attach_change_listener(cfg, callback, ctx);
}

/**
 * Attach a callback that is notified whenever a 
 * configuration option changes.
 * @return 0 on success, -1 on error, 1 for no such handler registered
 */
int GC_detach_change_listener(struct GC_Configuration * cfg,
			      GC_ChangeListener callback,
			      void * ctx) {
  return cfg->detach_change_listener(cfg, callback, ctx);
}

