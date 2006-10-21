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
 * @file src/setup/tree.h
 * @brief tree API (guile integration)
 * @author Christian Grothoff
 */

/**
 * Parse the specification file and create the tree.
 * Set all values to defaults.
 */
struct GNS_Tree *
tree_parse(struct GE_Context * ectx,
	   const char * specification);

struct GNS_Tree *
tree_lookup(struct GNS_Tree * root,
	    const char * section,
	    const char * option);

typedef void (*VisibilityChangeListener)(void * ctx,
					 struct GNS_Tree * tree);

/**
 * A value in the tree has been changed.
 * Update visibility (and notify about changes).
 */
void tree_notify_change(struct GC_Configuration * cfg,
			VisibilityChangeListener vcl,
			void * ctx,
			struct GE_Context * ectx,
			struct GNS_Tree * root,
			struct GNS_Tree * change);

