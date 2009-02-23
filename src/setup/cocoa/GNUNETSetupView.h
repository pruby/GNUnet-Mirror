/*
     This file is part of GNUnet.
     (C) 2008 Christian Grothoff (and other contributing authors)

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
 * @brief GNUnet Setup
 * @file setup/cocoa/config_cocoa.c
 * @author Heikki Lindholm
 */

#include "gnunet_setup_lib.h"
#import <Cocoa/Cocoa.h>

struct P2W;

@class GNUNETSetupTreeNode;
@class PackingBoxContainer;

@interface GNUNETSetupView:NSView
{
  struct GNUNET_GC_Configuration *gnunetConfig;
  struct GNUNET_GNS_Context *gnunetGNSCtx;
  struct GNUNET_GE_Context *gnunetGECtx;
  struct P2W *pws;
  NSMutableArray *controlDelegates;

  PackingBoxContainer *rootView;
  NSTabView *rootTabView;
  NSTextField *rootTitle;
  GNUNETSetupTreeNode *rootNode;
}

-(id) init;
-(id) initWithConfig:(struct GNUNET_GC_Configuration *)
     config setupContext:(struct GNUNET_GNS_Context *)
     gns errorContext:(struct GNUNET_GE_Context *)
     ectx maxWidth:(float) maxWidth;
-(void) dealloc;
-(struct GNUNET_GC_Configuration *) gnunetGCConfiguration;
-(struct GNUNET_GE_Context *) gnunetGEContext;
-(void) updateVisibility;
-(void) linkVisibilityNode:(struct GNUNET_GNS_TreeNode *)
     pos view:(NSView *) w;
-(int) addNodeToTreeWithTabView:(NSTabView *)
     tabView parent:(GNUNETSetupTreeNode *)
     parent pos:(struct GNUNET_GNS_TreeNode *) pos;
-(int) addLeafToTreeWithContainer:(PackingBoxContainer *)
     parent pos:(struct GNUNET_GNS_TreeNode *) pos;
-(void) repackViewTreeFrom:(NSView *) v;
-(void) alertDidEnd:(NSAlert *)
     alert returnCode:(int)
     returnCode contextInfo:(void *) contextInfo;
-(void) tabView:(NSTabView *)
     tabView didSelectTabViewItem:(NSTabViewItem *) tabViewItem;
// NSOutlineView data source
-(int) outlineView:(NSOutlineView *)
     outlineView numberOfChildrenOfItem:(id) item;
-(BOOL) outlineView:(NSOutlineView *)
     outlineView isItemExpandable:(id) item;
-(id) outlineView:(NSOutlineView *)
     outlineView child:(int)
     index ofItem:(id) item;
-(id) outlineView:(NSOutlineView *)
     outlineView objectValueForTableColumn:(NSTableColumn *)
     tableColumn byItem:(id) item;
@end
