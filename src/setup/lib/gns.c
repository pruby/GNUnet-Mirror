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

typedef struct GNS_TCL {

  GNS_TreeChangeListener l;

  void * c;

  struct GNS_TCL * next;

} GNS_TCL;

/**
 * @brief gnunet setup context
 */
struct GNS_Context {

  struct GE_Context * ectx;

  struct GC_Configuration * cfg;

  struct GNS_Tree * root;

  GNS_TCL * listeners;

  unsigned int in_notify;

};

static void notify_listeners(void * ctx,
			     struct GNS_Tree * tree) {
  struct GNS_Context * g = ctx;
  GNS_TCL * lpos;

  if (g->in_notify > 0)
    return; /* do not do recursive notifications! */
  g->in_notify++;
  lpos = g->listeners;
  while (lpos != NULL) {
    lpos->l(tree, lpos->c);
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
int configChangeListener(void * ctx,
			 struct GC_Configuration * cfg,
			 struct GE_Context * ectx,
			 const char * section,
			 const char * option) {
  struct GNS_Context * g = ctx;
  struct GNS_Tree * pos;

  pos = tree_lookup(g->root,
		    section,
		    option);
  if (pos == NULL) {
    GE_LOG(g->ectx,
	   GE_DEVELOPER | GE_BULK | GE_ERROR,
	   "Tree lookup for unknown option `%s' in section `%s'!\n",
	   option,
	   section);
    return 0; /* or refuse? */
  }
  /* first, check if value is valid */
  if ((pos->type & GNS_KindMask) != GNS_Leaf) {
    GE_LOG(g->ectx,
	   GE_DEVELOPER | GE_BULK | GE_ERROR,
	   "Tree value change for non-leaf option `%s' in section `%s'!\n",
	   option,
	   section);
    return 0;
  }
  switch (pos->type & GNS_TypeMask) {
  case GNS_Boolean: {
    int val;

    val = GC_get_configuration_value_yesno(cfg,
					   section,
					   option,
					   pos->value.Boolean.def);
    if (val == SYSERR) {
      return SYSERR;
    }
    pos->value.Boolean.val = val;
    break;
  }
  case GNS_UInt64: {
    unsigned long long val;

    if (SYSERR == GC_get_configuration_value_number(cfg,
						    section,
						    option,
						    pos->value.UInt64.min,
						    pos->value.UInt64.max,
						    pos->value.UInt64.def,
						    &val)) {
      return SYSERR;
    }
    pos->value.UInt64.val = val;
    break;
  }
  case GNS_Double: {
    char * s;
    double d;

    s = NULL;
    GC_get_configuration_value_string(cfg,
				      section,
				      option,
				      NULL,
				      &s);
    if (s == NULL) {
      pos->value.Double.val = pos->value.Double.def;
    } else {
      if (1 != sscanf(s, "%lf", &d)) {
	GE_LOG(ectx,
	       GE_USER | GE_ERROR | GE_IMMEDIATE,
	       "`%s' is not a valid double-precision floating point number.\n",
	       s);
	FREE(s);
	return SYSERR;
      }
      pos->value.Double.val = d;
      FREE(s);
    }
    break;
  }
  case GNS_String:
  case GNS_MC: {
    char * val;

    if (SYSERR == GC_get_configuration_value_string(cfg,
						    section,
						    option,
						    pos->value.String.def,
						    &val))
      return SYSERR;
    FREE(pos->value.String.val);
    pos->value.String.val = val;
    break;
  }
  case GNS_SC: {
    const char * ival;

    if (SYSERR == GC_get_configuration_value_choice(cfg,
						    section,
						    option,
						    (const char**) pos->value.String.legalRange,
						    pos->value.String.def,
						    &ival))
      return SYSERR;
    FREE(pos->value.String.val);
    pos->value.String.val = STRDUP(ival);
    break;
  }
  }

  /* notify client about value change */
  notify_listeners(g, pos);

  /* allow tree to update visibility */
  tree_notify_change(cfg,
		     &notify_listeners,
		     g,
		     g->ectx,
		     g->root,
		     pos);
  return 0;
}

static void free_tree(struct GNS_Tree * t) {
  int i;

  i = 0;
  while (t->children[i] != NULL) {
    free_tree(t->children[i]);
    i++;
  }
  switch (t->type & GNS_TypeMask) {
  case 0:
    break; /* no value */
  case GNS_Boolean:
  case GNS_UInt64:
  case GNS_Double:
    break; /* nothing to free */
  case GNS_String:
  case GNS_MC:
  case GNS_SC:
    i = 0;
    while (t->value.String.legalRange[i] != NULL) {
      FREE(t->value.String.legalRange[i]);
      i++;
    }
    FREE(t->value.String.legalRange);
    FREE(t->value.String.val);
    break;
  default:
    GE_BREAK(NULL, 0);
    break;
  }
  FREE(t->description);
  FREE(t->help);
  FREE(t->children);
  FREE(t);
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
struct GNS_Context *
GNS_load_specification(struct GE_Context * ectx,
		       struct GC_Configuration * cfg,
		       const char * specification) {
  struct GNS_Context * ctx;
  struct GNS_Tree * root;

  root = tree_parse(ectx, specification);
  if (root == NULL)
    return NULL;
  ctx = MALLOC(sizeof(struct GNS_Context));
  ctx->ectx = ectx;
  ctx->cfg = cfg;
  ctx->root = root;
  ctx->in_notify = 0;
  if (-1 == GC_attach_change_listener(cfg,
				      &configChangeListener,
				      ctx)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_USER | GE_IMMEDIATE,
	   _("Configuration does not satisfy constraints of configuration specification file `%s'!\n"),
	   specification);
    FREE(ctx);
    free_tree(root);
    return NULL;
  }
  return ctx;
}

/**
 * Obtain the GNS_Tree from the GNS system.  The tree is only valid
 * until GNS_free_specification is called.  Note that visibility and
 * values in the tree may change whenever the configuration of the GNS
 * context changes.
 *
 * @return NULL on error
 */
struct GNS_Tree *
GNS_get_tree(struct GNS_Context * ctx) {
  return ctx->root;
}

/**
 * Free resources associated with the GNS context.
 */
void
GNS_free_specification(struct GNS_Context * ctx) {
  GC_detach_change_listener(ctx->cfg,
			    &configChangeListener,
			    ctx);
  free_tree(ctx->root);
  GE_ASSERT(ctx->ectx, ctx->listeners == NULL);
  FREE(ctx);
}

/**
 * Register a tree change listener with GNS.
 *
 * @param listener callback to call whenever the tree changes
 */
void
GNS_register_tree_change_listener(struct GNS_Context * ctx,
				  GNS_TreeChangeListener listener,
				  void * cls) {
  GNS_TCL  * n;

  n = MALLOC(sizeof(GNS_TCL));
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
GNS_unregister_tree_change_listener(struct GNS_Context * ctx,
				    GNS_TreeChangeListener listener,
				    void * cls) {
  GNS_TCL * pos;
  GNS_TCL * prev;

  prev = NULL;
  pos = ctx->listeners;
  while (pos != NULL) {
    if ( (pos->l == listener) &&
	 (pos->c == cls)) {
      if (prev == NULL)
	ctx->listeners = pos->next;
      else
	prev->next = pos->next;
      FREE(pos);
      return; /* only unregister one! */
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
GNS_get_default_value_as_string(GNS_Type type,
				const GNS_Value * value) {
  char buf[48];

  if (value == NULL)
    return NULL;
  switch (type & GNS_TypeMask) {
  case GNS_Boolean:
    if (value->Boolean.def)
      return STRDUP("YES");
    return STRDUP("NO");
  case GNS_String:
  case GNS_MC:
  case GNS_SC:
    if (value->String.def == NULL)
      return NULL;
    return STRDUP(value->String.def);
  case GNS_Double:
    SNPRINTF(buf, 48, "%f", value->Double.def);
    return STRDUP(buf);
  case GNS_UInt64:
    SNPRINTF(buf, 48, "%llu", value->UInt64.def);
    return STRDUP(buf);
  default:
    return NULL;
  }
}
