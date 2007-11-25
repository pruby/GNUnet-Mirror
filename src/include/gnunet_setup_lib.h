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
 * @file include/gnunet_setup_lib.h
 * @brief public interface to libgnunetsetup
 *  Note that this API has various special requirements on
 *  clients using it:
 *  <ul>
 *  <li>libguile must be initialized by the main method of any
 *     program using it
 *  <li>the API does not support concurrent calls
 *  <li>GNUNET_GNS_TreeChangeListener callbacks must not call back
 *     into the API (in particular not unregister themselves)
 *  <li>clients may only read the tree, not modify it
 *  <li>values and visibility flags in the tree may change
 *     whenever the underlying configuration changes;
 *     clients must make sure that there are no concurrent
 *     changes to the configuration when reading values from
 *     the tree
 *  </ul>
 *
 * @author Christian Grothoff
 */

#ifndef GNUNET_SETUP_LIB_H
#define GNUNET_SETUP_LIB_H

#include "gnunet_util.h"

/**
 * Types of nodes and values in the configuration tree.
 */
typedef enum
{
  GNUNET_GNS_KIND_ROOT = 0,
  GNUNET_GNS_KIND_NODE = 1,
  GNUNET_GNS_KIND_LEAF = 2,
  GNUNET_GNS_KIND_MASK = 3,

  /**
   * Binary type (yes/no).
   */
  GNUNET_GNS_TYPE_BOOLEAN = 4,

  /**
   * Unsigned integer type.
   */
  GNUNET_GNS_TYPE_UINT64 = 8,

  /**
   * Double value type.
   */
  GNUNET_GNS_TYPE_DOUBLE = 16,

  /**
   * Free-form string (possibly with suggestions)
   */
  GNUNET_GNS_TYPE_STRING = 32,

  /**
   * Multiple choice (results in space-seperated
   * strings, one for each choice).
   */
  GNUNET_GNS_TYPE_MULTIPLE_CHOICE = 64,

  /**
   * Single choice (results in individual string
   * representing the choice).
   */
  GNUNET_GNS_TYPE_SINGLE_CHOICE = 128,

  GNUNET_GNS_TYPE_MASK = 252,
} GNUNET_GNS_TreeNodeKindAndType;

/**
 * @brief configuration value
 *
 * A configuration value does not only specify a value
 * but also the legal range of values.
 */
typedef union
{

  struct
  {
    int val;

    int def;
  } Boolean;

  struct
  {
    unsigned long long val;
    unsigned long long min;
    unsigned long long max;
    unsigned long long def;
  } UInt64;

  struct
  {
    double val;
    double def;
  } Double;

  /**
   * Data for GNUNET_GNS_TYPE_STRING, GNUNET_GNS_TYPE_MULTIPLE_CHOICE and GNUNET_GNS_TYPE_SINGLE_CHOICE.
   */
  struct
  {
    /**
     * 0-terminated string, never NULL
     */
    char *val;

    char *def;

    /**
     * Set of legal or suggested values for
     * "val", NULL termianted.
     */
    char **legalRange;

  } String;

} GNUNET_GNS_Value;

/**
 * @brief node in the configuration tree
 *
 * GNS clients may read this structure but must NEVER modify
 * it.  Note that the structure may change whenever the
 * configuration is changed (GNUnet's configuration manager
 * will notify GNS and GNS will update the tree).  What
 * may change are the concrete values and the visibility
 * attribute, but not the overall tree structure.
 */
typedef struct GNUNET_GNS_TreeNode
{

  /**
   * Section for this node (maybe NULL)
   */
  char *section;

  /**
   * Option name for this node (maybe NULL)
   */
  char *option;

  /**
   * Description for this node (never NULL)
   */
  char *description;

  /**
   * Helptext for this node (never NULL)
   */
  char *help;

  /**
   * NULL-terminated list of subnodes (must be empty for
   * nodes of type "leaf")
   */
  struct GNUNET_GNS_TreeNode **children;

  /**
   * Is this node visible to the user at this point?
   */
  int visible;

  /**
   * Type of the node (bitmask).
   */
  GNUNET_GNS_TreeNodeKindAndType type;

  /**
   * Value for this node (type of pointer is determined
   * by the type field)
   */
  GNUNET_GNS_Value value;

} GNUNET_GNS_TreeNode;

/**
 * @brief gnunet setup context
 */
struct GNUNET_GNS_Context;

/**
 * Start the setup process by loading a scheme file that
 * contains the configuration specification.
 *
 * @param ectx for error reporting
 * @param cfg configuration values that have a known initial value
 * @param specification name of the guile file containing the spec
 * @return NULL on error (i.e. specification file not found)
 */
struct GNUNET_GNS_Context *GNUNET_GNS_load_specification (struct
                                                          GNUNET_GE_Context
                                                          *ectx,
                                                          struct
                                                          GNUNET_GC_Configuration
                                                          *cfg,
                                                          const char
                                                          *specification);

/**
 * Obtain the GNUNET_GNS_TreeNode from the GNS system.  The tree is only valid
 * until GNUNET_GNS_free_specification is called.  Note that visibility and
 * values in the tree may change whenever the configuration of the GNS
 * context changes.
 *
 * @return NULL on error
 */
struct GNUNET_GNS_TreeNode *GNUNET_GNS_get_tree_root (struct
                                                      GNUNET_GNS_Context
                                                      *ctx);

/**
 * Free resources associated with the GNS context.
 */
void GNUNET_GNS_free_specification (struct GNUNET_GNS_Context *ctx);

/**
 * Callback that GNS will call whenever the GNUNET_GNS_TreeNode
 * is changed.
 *
 * @param node the node that has changed
 */
typedef void (*GNUNET_GNS_TreeChangeListener) (const struct
                                               GNUNET_GNS_TreeNode * node,
                                               void *cls);

/**
 * Register a tree change listener with GNS.
 *
 * @param listener callback to call whenever the tree changes
 */
void
GNUNET_GNS_register_tree_change_listener (struct GNUNET_GNS_Context *ctx,
                                          GNUNET_GNS_TreeChangeListener
                                          listener, void *cls);

/**
 * Release a tree change listener from GNS (do not call the listener
 * in the future for change events).
 */
void
GNUNET_GNS_unregister_tree_change_listener (struct GNUNET_GNS_Context *ctx,
                                            GNUNET_GNS_TreeChangeListener
                                            listener, void *cls);

/**
 * Convert the default value of the given tree entry to
 * a string.
 *
 * @return NULL on error
 */
char *GNUNET_GNS_get_default_value_as_string (GNUNET_GNS_TreeNodeKindAndType
                                              type,
                                              const GNUNET_GNS_Value * value);

#endif
