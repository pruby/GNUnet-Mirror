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
 * @file src/setup/lib/gns.c
 * @brief public interface to libgnunetsetup
 * @author Christian Grothoff
 */

#include "gnunet_setup_lib.h"
#include "gnunet_util.h"
#include "platform.h"

#include "tree.h"

typedef struct GNS_TCL
{

  GNUNET_GNS_TreeChangeListener l;

  void *c;

  struct GNS_TCL *next;

} GNS_TCL;

/**
 * @brief gnunet setup context
 */
struct GNUNET_GNS_Context
{

  struct GNUNET_GE_Context *ectx;

  struct GNUNET_GC_Configuration *cfg;

  struct GNUNET_GNS_TreeNode *root;

  GNS_TCL *listeners;

  unsigned int in_notify;

};

static void
notify_listeners (void *ctx, struct GNUNET_GNS_TreeNode *tree)
{
  struct GNUNET_GNS_Context *g = ctx;
  GNS_TCL *lpos;

  if (g->in_notify > 0)
    return;                     /* do not do recursive notifications! */
  g->in_notify++;
  lpos = g->listeners;
  while (lpos != NULL)
    {
      lpos->l (tree, lpos->c);
      lpos = lpos->next;
    }
  g->in_notify--;
}

/**
 * Callback function that is called if a configuration option
 * changes.  Validates the choice, updates the tree and
 * notifies the tree to recompute visibility.  Then
 * notifies the client.
 *
 * @param ectx context to log errors to
 * @return 0 if the change is ok, -1 if the change must be
 *         refused
 */
static int
configChangeListener (void *ctx,
                      struct GNUNET_GC_Configuration *cfg,
                      struct GNUNET_GE_Context *ectx,
                      const char *section, const char *option)
{
  struct GNUNET_GNS_Context *g = ctx;
  struct GNUNET_GNS_TreeNode *pos;

  pos = GNUNET_GNS_tree_lookup (g->root, section, option);
  if (pos == NULL)
    {
      GNUNET_GE_LOG (g->ectx,
                     GNUNET_GE_DEVELOPER | GNUNET_GE_BULK | GNUNET_GE_ERROR,
                     "Tree lookup for unknown option `%s' in section `%s'!\n",
                     option, section);
      return 0;                 /* or refuse? */
    }
  /* first, check if value is valid */
  if ((pos->type & GNUNET_GNS_KIND_MASK) != GNUNET_GNS_KIND_LEAF)
    {
      GNUNET_GE_LOG (g->ectx,
                     GNUNET_GE_DEVELOPER | GNUNET_GE_BULK | GNUNET_GE_ERROR,
                     "Tree value change for non-leaf option `%s' in section `%s'!\n",
                     option, section);
      return 0;
    }
  switch (pos->type & GNUNET_GNS_TYPE_MASK)
    {
    case GNUNET_GNS_TYPE_BOOLEAN:
      {
        int val;

        val = GNUNET_GC_get_configuration_value_yesno (cfg,
                                                       section,
                                                       option,
                                                       pos->value.Boolean.
                                                       def);
        if (val == GNUNET_SYSERR)
          {
            return GNUNET_SYSERR;
          }
        pos->value.Boolean.val = val;
        break;
      }
    case GNUNET_GNS_TYPE_UINT64:
      {
        unsigned long long val;

        if (GNUNET_SYSERR == GNUNET_GC_get_configuration_value_number (cfg,
                                                                       section,
                                                                       option,
                                                                       pos->
                                                                       value.
                                                                       UInt64.
                                                                       min,
                                                                       pos->
                                                                       value.
                                                                       UInt64.
                                                                       max,
                                                                       pos->
                                                                       value.
                                                                       UInt64.
                                                                       def,
                                                                       &val))
          {
            return GNUNET_SYSERR;
          }
        pos->value.UInt64.val = val;
        break;
      }
    case GNUNET_GNS_TYPE_DOUBLE:
      {
        char *s;
        double d;

        s = NULL;
        GNUNET_GC_get_configuration_value_string (cfg, section, option, NULL,
                                                  &s);
        if (s == NULL)
          {
            pos->value.Double.val = pos->value.Double.def;
          }
        else
          {
            if (1 != sscanf (s, "%lf", &d))
              {
                GNUNET_GE_LOG (ectx,
                               GNUNET_GE_USER | GNUNET_GE_ERROR |
                               GNUNET_GE_IMMEDIATE,
                               "`%s' is not a valid double-precision floating point number.\n",
                               s);
                GNUNET_free (s);
                return GNUNET_SYSERR;
              }
            pos->value.Double.val = d;
            GNUNET_free (s);
          }
        break;
      }
    case GNUNET_GNS_TYPE_STRING:
    case GNUNET_GNS_TYPE_MULTIPLE_CHOICE:
      {
        char *val;

        if (GNUNET_SYSERR == GNUNET_GC_get_configuration_value_string (cfg,
                                                                       section,
                                                                       option,
                                                                       pos->
                                                                       value.
                                                                       String.
                                                                       def,
                                                                       &val))
          return GNUNET_SYSERR;
        GNUNET_free (pos->value.String.val);
        pos->value.String.val = val;
        break;
      }
    case GNUNET_GNS_TYPE_SINGLE_CHOICE:
      {
        const char *ival;

        if (GNUNET_SYSERR == GNUNET_GC_get_configuration_value_choice (cfg,
                                                                       section,
                                                                       option,
                                                                       (const
                                                                        char
                                                                        **)
                                                                       pos->
                                                                       value.
                                                                       String.
                                                                       legalRange,
                                                                       pos->
                                                                       value.
                                                                       String.
                                                                       def,
                                                                       &ival))
          return GNUNET_SYSERR;
        GNUNET_free (pos->value.String.val);
        pos->value.String.val = GNUNET_strdup (ival);
        break;
      }
    }

  /* notify client about value change */
  notify_listeners (g, pos);

  /* allow tree to update visibility */
  GNUNET_GNS_tree_notify_change (cfg, &notify_listeners, g, g->ectx, g->root,
                                 pos);
  return 0;
}

static void
free_tree (struct GNUNET_GNS_TreeNode *t)
{
  int i;

  i = 0;
  while (t->children[i] != NULL)
    {
      free_tree (t->children[i]);
      i++;
    }
  switch (t->type & GNUNET_GNS_TYPE_MASK)
    {
    case 0:
      break;                    /* no value */
    case GNUNET_GNS_TYPE_BOOLEAN:
    case GNUNET_GNS_TYPE_UINT64:
    case GNUNET_GNS_TYPE_DOUBLE:
      break;                    /* nothing to free */
    case GNUNET_GNS_TYPE_STRING:
    case GNUNET_GNS_TYPE_MULTIPLE_CHOICE:
    case GNUNET_GNS_TYPE_SINGLE_CHOICE:
      i = 0;
      while (t->value.String.legalRange[i] != NULL)
        {
          GNUNET_free (t->value.String.legalRange[i]);
          i++;
        }
      GNUNET_free (t->value.String.legalRange);
      GNUNET_free (t->value.String.val);
      break;
    default:
      GNUNET_GE_BREAK (NULL, 0);
      break;
    }
  GNUNET_free (t->description);
  GNUNET_free (t->help);
  GNUNET_free (t->children);
  GNUNET_free (t);
}


/**
 * Start the setup process by loading a scheme file that
 * contains the configuration specification.
 *
 * @param ectx for error reporting
 * @param cfg configuration values that have a known initial value
 * @param specification name of the guile file containing the spec
 * @return NULL on error (i.e. specification file not found)
 */
struct GNUNET_GNS_Context *
GNUNET_GNS_load_specification (struct GNUNET_GE_Context *ectx,
                               struct GNUNET_GC_Configuration *cfg,
                               const char *specification)
{
  struct GNUNET_GNS_Context *ctx;
  struct GNUNET_GNS_TreeNode *root;

  root = GNUNET_GNS_tree_parse (ectx, specification);
  if (root == NULL)
    return NULL;
  ctx = GNUNET_malloc (sizeof (struct GNUNET_GNS_Context));
  ctx->ectx = ectx;
  ctx->cfg = cfg;
  ctx->root = root;
  ctx->in_notify = 0;
  if (-1 ==
      GNUNET_GC_attach_change_listener (cfg, &configChangeListener, ctx))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_IMMEDIATE,
                     _
                     ("Configuration does not satisfy constraints of configuration specification file `%s'!\n"),
                     specification);
      GNUNET_free (ctx);
      free_tree (root);
      return NULL;
    }
  return ctx;
}

/**
 * Obtain the GNUNET_GNS_TreeNode from the GNS system.  The tree is only valid
 * until GNUNET_GNS_free_specification is called.  Note that visibility and
 * values in the tree may change whenever the configuration of the GNS
 * context changes.
 *
 * @return NULL on error
 */
struct GNUNET_GNS_TreeNode *
GNUNET_GNS_get_tree_root (struct GNUNET_GNS_Context *ctx)
{
  return ctx->root;
}

/**
 * Free resources associated with the GNS context.
 */
void
GNUNET_GNS_free_specification (struct GNUNET_GNS_Context *ctx)
{
  GNUNET_GC_detach_change_listener (ctx->cfg, &configChangeListener, ctx);
  free_tree (ctx->root);
  GNUNET_GE_ASSERT (ctx->ectx, ctx->listeners == NULL);
  GNUNET_free (ctx);
}

/**
 * Register a tree change listener with GNS.
 *
 * @param listener callback to call whenever the tree changes
 */
void
GNUNET_GNS_register_tree_change_listener (struct GNUNET_GNS_Context *ctx,
                                          GNUNET_GNS_TreeChangeListener
                                          listener, void *cls)
{
  GNS_TCL *n;

  n = GNUNET_malloc (sizeof (GNS_TCL));
  n->l = listener;
  n->c = cls;
  n->next = ctx->listeners;
  ctx->listeners = n;
}

/**
 * Release a tree change listener from GNS (do not call the listener
 * in the future for change events).
 */
void
GNUNET_GNS_unregister_tree_change_listener (struct GNUNET_GNS_Context *ctx,
                                            GNUNET_GNS_TreeChangeListener
                                            listener, void *cls)
{
  GNS_TCL *pos;
  GNS_TCL *prev;

  prev = NULL;
  pos = ctx->listeners;
  while (pos != NULL)
    {
      if ((pos->l == listener) && (pos->c == cls))
        {
          if (prev == NULL)
            ctx->listeners = pos->next;
          else
            prev->next = pos->next;
          GNUNET_free (pos);
          return;               /* only unregister one! */
        }
      prev = pos;
      pos = pos->next;
    }
}

/**
 * Convert the default value of the given tree entry to
 * a string.
 *
 * @return NULL on error
 */
char *
GNUNET_GNS_get_default_value_as_string (GNUNET_GNS_TreeNodeKindAndType type,
                                        const GNUNET_GNS_Value * value)
{
  char buf[48];

  if (value == NULL)
    return NULL;
  switch (type & GNUNET_GNS_TYPE_MASK)
    {
    case GNUNET_GNS_TYPE_BOOLEAN:
      if (value->Boolean.def)
        return GNUNET_strdup ("YES");
      return GNUNET_strdup ("NO");
    case GNUNET_GNS_TYPE_STRING:
    case GNUNET_GNS_TYPE_MULTIPLE_CHOICE:
    case GNUNET_GNS_TYPE_SINGLE_CHOICE:
      if (value->String.def == NULL)
        return NULL;
      return GNUNET_strdup (value->String.def);
    case GNUNET_GNS_TYPE_DOUBLE:
      GNUNET_snprintf (buf, 48, "%f", value->Double.def);
      return GNUNET_strdup (buf);
    case GNUNET_GNS_TYPE_UINT64:
      GNUNET_snprintf (buf, 48, "%llu", value->UInt64.def);
      return GNUNET_strdup (buf);
    default:
      return NULL;
    }
}
