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

#import <Cocoa/Cocoa.h>
#include "platform.h"
#import "PackingBoxContainer.h"
#import "GNUNETSetupView.h"

struct P2W
{
	struct P2W *next;
	struct GNUNET_GNS_TreeNode *pos;
	NSView *w;
};

@interface GNUnetSetupDelegate : NSObject
{
	GNUNETSetupView *setupView;
	struct GNUNET_GNS_TreeNode *gnsTreeNode;
}
- (id) initWithSetupView:(GNUNETSetupView *)view
	treeNode:(struct GNUNET_GNS_TreeNode *)node;
- (struct GNUNET_GNS_TreeNode *) treeNode;
- (void) handleAction:(id)sender;
@end

@interface GNUnetSetupBooleanDelegate : GNUnetSetupDelegate
- (void) handleAction:(id)sender;
@end

@interface GNUnetSetupMultiChoiceDelegate : GNUnetSetupDelegate
- (void) handleAction:(id)sender;
@end

@interface GNUnetSetupSingleChoiceDelegate : GNUnetSetupDelegate
- (void) handleAction:(id)sender;
@end

@interface GNUnetSetupStringDelegate : GNUnetSetupDelegate
- (void) handleAction:(id)sender;
- (BOOL) control:(NSControl *)control
	textShouldEndEditing:(NSText *)fieldEditor;
@end

// NSOutlineView data source item: map outline items to
// tab view panels and hold NSString titles
@interface GNUNETSetupTreeNode : NSObject
{
	NSString *title;
	struct GNUNET_GNS_TreeNode *gnsTreeNode;
	NSTabViewItem *tabViewItem;

	GNUNETSetupTreeNode *parent;
	NSMutableArray *children;
}
- (id) initWithNode:(struct GNUNET_GNS_TreeNode *)node
	parent:(GNUNETSetupTreeNode *)p;
- (void) addChildNode:(GNUNETSetupTreeNode *)node;
- (int) numberOfChildren;
- (GNUNETSetupTreeNode *) childAtIndex:(int)n;
- (GNUNETSetupTreeNode *) parent;
- (NSString *) title;
- (struct GNUNET_GNS_TreeNode *) treeNode;
- (NSTabViewItem *) tabViewItem;
- (void) setTabViewItem:(NSTabViewItem *)item;
@end

@implementation GNUNETSetupTreeNode : NSObject
- (id) initWithNode:(struct GNUNET_GNS_TreeNode *)node
	parent:(GNUNETSetupTreeNode *)p
{
	if (self = [super init]) {
		parent = p;
		children = nil;
		gnsTreeNode = node;
		title = [[NSString alloc]
				initWithCString:node->description
				encoding:NSUTF8StringEncoding];
	}
	
	return self;
}

- (void) addChildNode:(GNUNETSetupTreeNode *)node
{
	if (children == nil)
		children = [NSMutableArray new];

	[children addObject:node];
}

- (GNUNETSetupTreeNode *) childAtIndex:(int)n
{
	if (children != nil)
		return [children objectAtIndex:n];
	else
		return nil;
}

- (int) numberOfChildren
{
	if (children != nil)
		return [children count];
	else
		return -1;
}

- (GNUNETSetupTreeNode *) parent
{
	return parent;
}

- (NSString *) title
{
	return title;
}

- (struct GNUNET_GNS_TreeNode *) treeNode
{
	return gnsTreeNode;
}

- (NSTabViewItem *) tabViewItem
{
	return tabViewItem;
}

- (void) setTabViewItem:(NSTabViewItem *)item
{
	tabViewItem = item;
}

- (void)dealloc
{
	if (children != nil)
		[children release];
	[title release];
	[super dealloc];
}
@end

//
// delegates
//
@implementation GNUnetSetupDelegate : NSObject
- (id) initWithSetupView:(GNUNETSetupView *)view
	treeNode:(struct GNUNET_GNS_TreeNode *)node;
{
	if ((self = [super init])) {
		setupView = view;
		gnsTreeNode = node;
	}
	return self;
}

- (struct GNUNET_GNS_TreeNode *) treeNode
{
	return gnsTreeNode;
}
-(void) handleAction:(id)sender;
{
}
@end

@implementation GNUnetSetupBooleanDelegate : GNUnetSetupDelegate
-(void) handleAction:(id)sender;
{
	GNUNET_GC_set_configuration_value_string(
		[setupView gnunetGCConfiguration],
		[setupView gnunetGEContext],
		gnsTreeNode->section,
		gnsTreeNode->option,
		[(NSButton *)sender state] == NSOnState ? "YES" : "NO");
	[setupView updateVisibility];
}
@end

@implementation GNUnetSetupMultiChoiceDelegate : GNUnetSetupDelegate
-(void) handleAction:(id)sender;
{
	char *val;
	const char *opt;
	char *ret;
	char *v;
	char *s;
	NSString *obj;

	obj = [[(NSButton *)sender cell] representedObject];

	val = NULL;
	GNUNET_GC_get_configuration_value_string (
		[setupView gnunetGCConfiguration],
		gnsTreeNode->section,
		gnsTreeNode->option,
		NULL,
		&val);
	GNUNET_GE_ASSERT ([setupView gnunetGEContext], val != NULL);
	opt = [obj UTF8String];
	if ([(NSButton *)sender state] == NSOnState) {
		ret = GNUNET_malloc (strlen (val) + strlen (opt) + 2);
		strcpy (ret, val);
		strcat (ret, " ");
		strcat (ret, opt);
	}
	else {
		v = val;
		while ((NULL != (s = strstr (v, opt))) &&
			(((s[strlen (opt)] != '\0') &&
			(s[strlen (opt)] != ' ')) ||
			((s != val) && (s[-1] != ' '))))
			v = s + 1;
		GNUNET_GE_ASSERT (NULL, s != NULL);
		ret = GNUNET_malloc (strlen (val) + 1);
		s[0] = '\0';
		if (s != val)
		s[-1] = '\0'; /* kill space */
		strcpy (ret, val);
		strcat (ret, &s[strlen (opt)]);
	}
	GNUNET_GC_set_configuration_value_string (
		[setupView gnunetGCConfiguration],
		[setupView gnunetGEContext],
		gnsTreeNode->section,
		gnsTreeNode->option,
		ret);
	GNUNET_free (ret);
	GNUNET_free (val);
	[setupView updateVisibility];
}
@end

@implementation GNUnetSetupSingleChoiceDelegate : GNUnetSetupDelegate
-(void) handleAction:(id)sender;
{
	NSString *obj;

	obj = [[(NSMatrix *)sender selectedCell] representedObject];
	GNUNET_GC_set_configuration_value_string (
		[setupView gnunetGCConfiguration],
		[setupView gnunetGEContext],
		gnsTreeNode->section,
		gnsTreeNode->option,
		[obj UTF8String]);
	[setupView updateVisibility];
}
@end

@implementation GNUnetSetupStringDelegate : GNUnetSetupDelegate
-(void) handleAction:(id)sender;
{
}
- (BOOL) control:(NSControl *)control textShouldEndEditing:(NSText *)fieldEditor
{
	char *val;
	struct GNUNET_GE_Context *ectx;
	struct GNUNET_GE_Memory *ectxMemory;
	int ret;

	ectxMemory = GNUNET_GE_memory_create (2);
	ectx = GNUNET_GE_create_context_memory (GNUNET_GE_ALL, ectxMemory);
	GNUNET_GC_set_error_context([setupView gnunetGCConfiguration], ectx);
	ret = GNUNET_GC_set_configuration_value_string(
		[setupView gnunetGCConfiguration],
		[setupView gnunetGEContext],
		gnsTreeNode->section,
		gnsTreeNode->option,
		[[control stringValue] UTF8String]);
	GNUNET_GC_set_error_context([setupView gnunetGCConfiguration],
		[setupView gnunetGEContext]);
	if (ret != 0) {
		NSAlert *alert = [[[NSAlert alloc] init] autorelease];
		[alert setMessageText:[[[NSString alloc]
			initWithCString:_("Error!")
			encoding:NSUTF8StringEncoding] autorelease]];
		[alert addButtonWithTitle:[[[NSString alloc]
			initWithCString:_("OK")
			encoding:NSUTF8StringEncoding] autorelease]]; 
		[alert setInformativeText:[[[NSString alloc]
			initWithCString:GNUNET_GE_memory_get(ectxMemory, 0)
			encoding:NSUTF8StringEncoding] autorelease]];
		[alert setAlertStyle:NSWarningAlertStyle];
		[alert beginSheetModalForWindow:[(NSControl *)control window]
			modalDelegate:setupView
			didEndSelector:@selector(alertDidEnd:returnCode:
				contextInfo:)
			contextInfo:control];

		// if the control is hidden (i.e. the user hid it with an
		// invalid value) , we just have to replace the user
		// input with the old value 
		if ([control isHidden]) {
			GNUNET_GC_get_configuration_value_string (
				[setupView gnunetGCConfiguration],
				gnsTreeNode->section,
				gnsTreeNode->option,
				NULL,
				&val);
			GNUNET_GE_ASSERT ([setupView gnunetGEContext],
				val != NULL);
			[control setStringValue:[[[NSString alloc]
					initWithCString:val
					encoding:NSUTF8StringEncoding] 
				autorelease]];
			GNUNET_free (val);
		}
	}
	GNUNET_GE_memory_free (ectxMemory);
	[setupView updateVisibility];

	return (ret != 0 ? NO : YES);
}
@end



@implementation GNUNETSetupView : NSView

- (id) init
{
	return nil;
}

- (id) initWithConfig:(struct GNUNET_GC_Configuration *)config
	setupContext:(struct GNUNET_GNS_Context *)gns
	errorContext:(struct GNUNET_GE_Context *)ectx
	maxWidth:(float)maxWidth
{

	if ((self = [super init])) {
		NSOutlineView *outlineView;
		NSTableColumn *col;
		NSScrollView *scrollView;
		NSSplitView *splitView;
		PackingBoxContainer *settingsPanel;
		PackingBoxContainer *settingsAndOutlinePanel;
		float settingsPanelHeight = 500.0;
		float outlinePanelWidth = 160.0;
		NSSize s;

		gnunetConfig = config;
		gnunetGNSCtx = gns;
		gnunetGECtx = ectx;

		if (maxWidth / 3 < outlinePanelWidth)
			outlinePanelWidth = maxWidth / 3;

		controlDelegates = [NSMutableArray new];

		rootView = [[[PackingBoxContainer alloc] init] autorelease];
		[rootView setReversedPacking:YES];

		settingsAndOutlinePanel = [[[PackingBoxContainer alloc]
			initWithSpacing:5.0
			horizontal:YES] autorelease];
		[settingsAndOutlinePanel setReversedPacking:YES];
		settingsPanel = [[[PackingBoxContainer alloc]
			initWithSpacing:5.0
			horizontal:NO] autorelease];
		[settingsPanel setReversedPacking:YES];
		// settings panel title
		rootTitle = [[NSTextField new] autorelease];
		[[rootTitle cell] setFont:[NSFont
			systemFontOfSize:[NSFont smallSystemFontSize]]];
		[rootTitle setStringValue:[[[NSString alloc]
				initWithCString:""
				encoding:NSUTF8StringEncoding] 
			autorelease]];
		[rootTitle setEditable:NO];
		[rootTitle setSelectable:NO];
		[rootTitle setBordered:NO];
		[rootTitle setBezeled:NO];
		[rootTitle setDrawsBackground:NO];
		[rootTitle sizeToFit];
		s = [[rootTitle cell] cellSize];
		[rootTitle setFrame:NSMakeRect(
			0.0, settingsPanelHeight - s.height, 
			maxWidth - (outlinePanelWidth + 5.0), s.height)];
		[settingsPanel addSubview:rootTitle]; 

		// settings panel
		scrollView = [[NSScrollView alloc]
			initWithFrame:NSMakeRect(
				3.0, 0.0f,
				maxWidth - (outlinePanelWidth + 8.0), 
				settingsPanelHeight - s.height - 8.0f)];
		[scrollView autorelease];
		[scrollView setHasVerticalScroller:YES];
		[scrollView setHasHorizontalScroller:NO];
		[scrollView setAutohidesScrollers:NO];
		[scrollView setBorderType:NSGrooveBorder];
		[scrollView setDrawsBackground:NO];

		rootTabView = [[NSTabView new] autorelease];
		[rootTabView setTabViewType:NSNoTabsNoBorder];
		[rootTabView setFrameSize:[scrollView contentSize]];
		[rootTabView setDelegate:self];
		[scrollView setDocumentView:rootTabView];
		[settingsPanel addSubview:scrollView];

		rootNode = [[GNUNETSetupTreeNode alloc] 
			initWithNode:GNUNET_GNS_get_tree_root (gns)
			parent:nil];
		[self addNodeToTreeWithTabView:rootTabView parent:rootNode
			pos:GNUNET_GNS_get_tree_root (gns)];
	
		[settingsAndOutlinePanel addSubview:settingsPanel];
	


		scrollView = [[NSScrollView alloc]
			initWithFrame:NSMakeRect(0.0f, 0.0f,
				outlinePanelWidth, settingsPanelHeight)];
		[scrollView autorelease];
		[scrollView setHasVerticalScroller:YES];
		[scrollView setHasHorizontalScroller:YES];
		[scrollView setAutohidesScrollers:YES];
		[scrollView setBorderType:NSBezelBorder];
		outlineView = [[NSOutlineView new] autorelease];
		col = [[[NSTableColumn alloc] initWithIdentifier:@"Category"]
			autorelease];
		[[col dataCell] setFont:[NSFont
			systemFontOfSize:[NSFont smallSystemFontSize]]];
		[col setWidth:[scrollView contentSize].width]; //XXX
		[col setEditable:NO];
		[outlineView addTableColumn:col];
		[outlineView setOutlineTableColumn:col];
		[outlineView setAutoresizesOutlineColumn:YES];
		[outlineView setAllowsColumnReordering:NO];
		[outlineView setAllowsColumnResizing:NO];
		[outlineView setAllowsColumnSelection:NO];
		[outlineView setAllowsEmptySelection:NO];
		[outlineView setAllowsMultipleSelection:NO];
		[outlineView setUsesAlternatingRowBackgroundColors:YES];
		[outlineView setHeaderView:nil];
		[outlineView setDelegate:self];
		[outlineView setDataSource:self];
//		[outlineView sizeToFit];
//		[outlineView reloadData];
		[scrollView setDocumentView:outlineView];
		[settingsAndOutlinePanel addSubview:scrollView];

		[rootView addSubview:settingsAndOutlinePanel];

		[self addSubview:rootView];

		NSIndexSet *set;
		set = [[[NSIndexSet alloc] 
			initWithIndex:0]
			autorelease];
		[outlineView selectRowIndexes:set 
			byExtendingSelection:NO];

		[self updateVisibility];
		[self setFrameSize:[rootView frame].size];
	}

	return self;
}

- (void) dealloc
{
	[rootView removeFromSuperview];
	[rootNode release];
	[controlDelegates release];
	[super dealloc];
}

- (struct GNUNET_GC_Configuration *) gnunetGCConfiguration;
{
	return gnunetConfig;
}

- (struct GNUNET_GE_Context *) gnunetGEContext;
{
	return gnunetGECtx;
}

- (void) updateVisibility
{
	struct P2W *pos;

	pos = pws;
	while (pos != NULL) {
		if (pos->pos->visible && [pos->w isHidden] == YES) {
			[pos->w setHidden:NO];
			[self repackViewTreeFrom:pos->w];
		}
		else if (!pos->pos->visible && [pos->w isHidden] == NO) {
			NSResponder *resp = [[pos->w window] firstResponder];
			[pos->w setHidden:YES];
			[self repackViewTreeFrom:pos->w];
			// if the hidden control is firstresponder
			// set firstresponder to nil
			if ([resp isKindOfClass:[NSView class]] &&
					[(NSView *)resp isDescendantOf:pos->w])
			{
				[[pos->w window] makeFirstResponder:nil];
			}

		}
		pos = pos->next;
	}
}

- (void) linkVisibilityNode:(struct GNUNET_GNS_TreeNode *)pos view:(NSView *)w
{
	struct P2W *pw;

	pw = GNUNET_malloc (sizeof (struct P2W));
	pw->pos = pos;
	pw->w = w;
	pw->next = pws;
	pws = pw;
}

- (int) addNodeToTreeWithTabView:(NSTabView *)tabView
	parent:(GNUNETSetupTreeNode *)parent
	pos:(struct GNUNET_GNS_TreeNode *)pos;
{
	int i;
	struct GNUNET_GNS_TreeNode *child;
	GNUNETSetupTreeNode *node;
	PackingBoxContainer *vbox;
	int have;

	have = 0;
	i = 0;
	vbox = [[[PackingBoxContainer alloc]
		initWithSpacing:12.0f
		horizontal:NO] autorelease];
	[vbox setHorizontalMargins:16.0f];
	[vbox setVerticalMargins:16.0f];
	[vbox setReversedPacking:YES];
	[vbox setFrameSize:[tabView frame].size];
	[vbox setMaxWidth:[tabView frame].size.width];
	while (NULL != (child = pos->children[i])) {
		switch (child->type & GNUNET_GNS_KIND_MASK) {
			case GNUNET_GNS_KIND_NODE:
				node = [[GNUNETSetupTreeNode alloc]
					initWithNode:child parent:parent];
				[parent addChildNode:node];
				[node release];
				have = have | 
					[self addNodeToTreeWithTabView:tabView
						parent:node
						pos:child];
				break;
			case GNUNET_GNS_KIND_LEAF:
				have = have |
					[self addLeafToTreeWithContainer:vbox
						pos:child];
				break;
			case GNUNET_GNS_KIND_ROOT:
			default:
				GNUNET_GE_ASSERT (NULL, 0);
				break;
		}
		i++;
	}
	if (have != 0) {
		if (pos == GNUNET_GNS_get_tree_root(gnunetGNSCtx)) {
			if ([[vbox subviews] count] > 0)
				[rootView addSubview:vbox];
		}
		else {
			NSTabViewItem *tvi;

			// TODO: if no items, place a text along the lines
			// of 'nothing to see here' in the container
			tvi = [[[NSTabViewItem alloc] initWithIdentifier:nil]
				autorelease];
			[tvi setLabel:[[[NSString alloc]
					initWithCString:pos->description
					encoding:NSUTF8StringEncoding] 
				autorelease]];

			[tvi setView:vbox];
			[tabView addTabViewItem:tvi];
			[parent setTabViewItem:tvi];
		}
	}

	return have;
}

- (int) addLeafToTreeWithContainer:(PackingBoxContainer *)parent
	pos:(struct GNUNET_GNS_TreeNode *)pos;
{
	NSButton *button;
	NSTextField *textField;
	NSStepper *stepper;
	NSMatrix *matrix;
	NSButtonCell *cell;
	PackingBoxContainer *box;
	GNUnetSetupDelegate *delegate;
	NSPoint o;
	NSSize s;
	int i;
	const char *lri;

	switch (pos->type & GNUNET_GNS_TYPE_MASK) {
		case GNUNET_GNS_TYPE_BOOLEAN:
			box = [[[PackingBoxContainer alloc]
				initWithSpacing:0.0f
				horizontal:NO] autorelease];
			button = [[NSButton new] autorelease];
			[[button cell] setControlSize:NSSmallControlSize];
			[[button cell] setFont:[NSFont
				systemFontOfSize:[NSFont smallSystemFontSize]]];
			[button setButtonType:NSSwitchButton];
			[button setTitle:[[[NSString alloc]
					initWithCString:pos->description
					encoding:NSUTF8StringEncoding] 
				autorelease]];
			[button setToolTip:[[[NSString alloc]
					initWithCString:pos->help
					encoding:NSUTF8StringEncoding] 
				autorelease]];
			[button setState:(pos->value.Boolean.val ?
				NSOnState : NSOffState)];
			[button sizeToFit];
			o = [button frame].origin;
			o.x += 1.0;
			[button setFrameOrigin:o];
			delegate = [[[GNUnetSetupBooleanDelegate alloc]
					initWithSetupView:self
					treeNode:pos] autorelease];
			[controlDelegates addObject:delegate];
			[button setTarget:delegate];
			[button setAction:@selector(handleAction:)];
			[box addSubview:button]; 
			break;
		case GNUNET_GNS_TYPE_STRING:
			box = [[[PackingBoxContainer alloc]
				initWithSpacing:8.0f
				horizontal:NO] autorelease];
			[box setReversedPacking:YES];
			// label
			textField = [[NSTextField new] autorelease];
			[[textField cell] setFont:[NSFont
				systemFontOfSize:[NSFont smallSystemFontSize]]];
			[textField setStringValue:[[[NSString alloc]
					initWithCString:pos->description
					encoding:NSUTF8StringEncoding] 
				autorelease]];
			[textField setToolTip:[[[NSString alloc]
					initWithCString:pos->help
					encoding:NSUTF8StringEncoding] 
				autorelease]];
			[textField setEditable:NO];
			[textField setSelectable:NO];
			[textField setBordered:NO];
			[textField setBezeled:NO];
			[textField setDrawsBackground:NO];
			[textField sizeToFit];
			[box addSubview:textField]; 
			// input field
			textField = [[NSTextField new] autorelease];
			[[textField cell] setFont:[NSFont
				systemFontOfSize:[NSFont smallSystemFontSize]]];
			[[textField cell] setScrollable:YES];
			[textField setStringValue:[[[NSString alloc]
					initWithCString:pos->value.String.val
					encoding:NSUTF8StringEncoding] 
				autorelease]];
			[textField setToolTip:[[[NSString alloc]
					initWithCString:pos->help
					encoding:NSUTF8StringEncoding] 
				autorelease]];
			[textField setEditable:YES];
			[textField sizeToFit];
			s.width = [parent frame].size.width -
				2 * [parent horizontalMargins];
			s.height = [textField frame].size.height;
			[textField setFrameSize:s];
			delegate = [[[GNUnetSetupStringDelegate alloc]
				initWithSetupView:self
				treeNode:pos] autorelease];
			[controlDelegates addObject:delegate];
			[textField setTarget:delegate];
			[textField setAction:@selector(handleAction:)];
			[textField setDelegate:delegate];
			[box addSubview:textField]; 
			break;
		case GNUNET_GNS_TYPE_MULTIPLE_CHOICE:
			box = [[[PackingBoxContainer alloc]
				initWithSpacing:2.0
				horizontal:NO] autorelease];
			[box setReversedPacking:YES];
			// label
			textField = [[NSTextField new] autorelease];
			[[textField cell] setFont:[NSFont
				systemFontOfSize:[NSFont smallSystemFontSize]]];
			[textField setStringValue:[[[NSString alloc]
					initWithCString:pos->description
					encoding:NSUTF8StringEncoding] 
				autorelease]];
			[textField setToolTip:[[[NSString alloc]
					initWithCString:pos->help
					encoding:NSUTF8StringEncoding] 
				autorelease]];
			[textField setEditable:NO];
			[textField setSelectable:NO];
			[textField setBordered:NO];
			[textField setBezeled:NO];
			[textField setDrawsBackground:NO];
			[textField sizeToFit];
			[box addSubview:textField]; 
			delegate = [[[GNUnetSetupMultiChoiceDelegate alloc]
					initWithSetupView:self
					treeNode:pos] autorelease];
			[controlDelegates addObject:delegate];
			i = 0;
			while ((lri = pos->value.String.legalRange[i])) {
				button = [[NSButton new] autorelease];
				[[button cell]
					setControlSize:NSSmallControlSize];
				[[button cell] setFont:[NSFont 
					systemFontOfSize:[NSFont
						smallSystemFontSize]]];
				[button setButtonType:NSSwitchButton];
				[button setTitle:[[[NSString alloc]
						initWithCString:lri
						encoding:NSUTF8StringEncoding] 
					autorelease]];
				[button setToolTip:[[[NSString alloc]
						initWithCString:pos->help
						encoding:NSUTF8StringEncoding] 
					autorelease]];
				[button setState:(pos->value.Boolean.val ?
					NSOnState : NSOffState)];
				[button sizeToFit];
				o = [button frame].origin;
				o.x += 13.0;
				[button setFrameOrigin:o];
				[[button cell] setRepresentedObject:
					[[[NSString alloc]
						initWithCString:lri
						encoding:NSUTF8StringEncoding]
					autorelease]];
				if ((NULL != strstr (pos->value.String.val,
					lri)) &&
					((' ' == strstr (pos->value.String.val,
					lri)[strlen (lri)])
					|| ('\0' ==
					strstr (pos->value.String.val,
					lri)[strlen (lri)]))
					&&
					((pos->value.String.val ==
					strstr (pos->value.String.val,
					lri))
					|| (' ' == strstr 
					(pos->value.String.val, lri)[-1])))
					[button setState:NSOnState];
				else
					[button setState:NSOffState];

				[button setTarget:delegate];
				[button setAction:@selector(handleAction:)];
				[box addSubview:button];
				i++;
			}
			break;
		case GNUNET_GNS_TYPE_SINGLE_CHOICE:
			box = [[[PackingBoxContainer alloc]
				initWithSpacing:4.0
				horizontal:NO] autorelease];
			[box setReversedPacking:YES];
			// label
			textField = [[NSTextField new] autorelease];
			[[textField cell] setFont:[NSFont
				systemFontOfSize:[NSFont smallSystemFontSize]]];
			[textField setStringValue:[[[NSString alloc]
					initWithCString:pos->description
					encoding:NSUTF8StringEncoding] 
				autorelease]];
			[textField setToolTip:[[[NSString alloc]
					initWithCString:pos->help
					encoding:NSUTF8StringEncoding] 
				autorelease]];
			[textField setEditable:NO];
			[textField setSelectable:NO];
			[textField setBordered:NO];
			[textField setBezeled:NO];
			[textField setDrawsBackground:NO];
			[textField sizeToFit];
			[box addSubview:textField]; 
			// buttons
			cell = [[[NSButtonCell alloc] init] autorelease];
			[cell setControlSize:NSSmallControlSize];
			[cell setFont:[NSFont
				systemFontOfSize:[NSFont smallSystemFontSize]]];
			[cell setButtonType:NSRadioButton];
			matrix = [[[NSMatrix alloc]
				initWithFrame:NSMakeRect(0.0f, 0.0f, 0.0f, 0.0f)
				mode:NSRadioModeMatrix
				prototype:cell 
				numberOfRows:0 
				numberOfColumns:1] autorelease];
			s.width = 4.0;
			s.height = 2.0;
			[matrix setIntercellSpacing:s];
			[matrix setAllowsEmptySelection:NO];
			
			delegate = [[[GNUnetSetupSingleChoiceDelegate alloc]
					initWithSetupView:self
					treeNode:pos] autorelease];
			[controlDelegates addObject:delegate];
			i = 0;
			s.width = s.height = 0.0f;
			while (NULL != (lri = pos->value.String.legalRange[i]))
			{
				NSSize ts;
				[matrix addRow];
				[[matrix cellAtRow:i column:0]
						setTitle:[[[NSString alloc]
						initWithCString:lri
						encoding:NSUTF8StringEncoding]
					autorelease]];
				ts = [[matrix cellAtRow:i column:0] cellSize];
				if (ts.width > s.width)
					s.width = ts.width;
				if (ts.height > s.height)
					s.height = ts.height;
				[matrix	setToolTip:[[[NSString alloc]
						initWithCString:pos->help
						encoding:NSUTF8StringEncoding]
					autorelease]
					forCell:[matrix cellAtRow:i column:0]];
				[[matrix cellAtRow:i column:0]
					setRepresentedObject:
					[[[NSString alloc]
						initWithCString:lri
						encoding:NSUTF8StringEncoding]
					autorelease]];
				if (0 == strcmp (lri, pos->value.String.val))
					[matrix setState:1 atRow:i column:0];
				[[matrix cellAtRow:i column:0] setTarget:delegate];
				[[matrix cellAtRow:i column:0] setAction:@selector(handleAction:)];
				i++;
			}
			[matrix setCellSize:s];
			[matrix sizeToCells];
			o = [matrix frame].origin;
			o.x += 13.0;
			[matrix setFrameOrigin:o];
			[box addSubview:matrix]; 
			break;
		case GNUNET_GNS_TYPE_DOUBLE:
			box = [[[PackingBoxContainer alloc]
				initWithSpacing:5.0
				horizontal:YES] autorelease];
			// label
			textField = [[NSTextField new] autorelease];
			[[textField cell] setFont:[NSFont
				systemFontOfSize:[NSFont smallSystemFontSize]]];
			[textField setStringValue:[[[NSString alloc]
					initWithCString:pos->description
					encoding:NSUTF8StringEncoding] 
				autorelease]];
			[textField setToolTip:[[[NSString alloc]
					initWithCString:pos->help
					encoding:NSUTF8StringEncoding] 
				autorelease]];
			[textField setEditable:NO];
			[textField setSelectable:NO];
			[textField setBordered:NO];
			[textField setBezeled:NO];
			[textField setDrawsBackground:NO];
			[textField sizeToFit];
			o = [textField frame].origin;
			o.y += 2.0;
			[textField setFrameOrigin:o];
			[box addSubview:textField]; 
			// input field
			textField = [[NSTextField new] autorelease];
			[[textField cell] setFont:[NSFont
				systemFontOfSize:[NSFont smallSystemFontSize]]];
			[[textField cell] setScrollable:YES];
			[textField setDoubleValue:pos->value.Double.val];
			[textField setToolTip:[[[NSString alloc]
					initWithCString:pos->help
					encoding:NSUTF8StringEncoding] 
				autorelease]];
			[textField setEditable:YES];
			[textField sizeToFit];
			delegate = [[[GNUnetSetupStringDelegate alloc]
					initWithSetupView:self
					treeNode:pos] autorelease];
			[controlDelegates addObject:delegate];
			[textField setTarget:delegate];
			[textField setAction:@selector(handleAction:)];
			[textField setDelegate:delegate];
			[box addSubview:textField]; 
			break;
		case GNUNET_GNS_TYPE_UINT64:
			box = [[[PackingBoxContainer alloc]
				initWithSpacing:5.0
				horizontal:YES] autorelease];
			// label
			textField = [[NSTextField new] autorelease];
			[[textField cell] setFont:[NSFont
				systemFontOfSize:[NSFont smallSystemFontSize]]];
			[textField setStringValue:[[[NSString alloc]
					initWithCString:pos->description
					encoding:NSUTF8StringEncoding] 
				autorelease]];
			[textField setToolTip:[[[NSString alloc]
					initWithCString:pos->help
					encoding:NSUTF8StringEncoding] 
				autorelease]];
			[textField setEditable:NO];
			[textField setSelectable:NO];
			[textField setBordered:NO];
			[textField setBezeled:NO];
			[textField setDrawsBackground:NO];
			[textField sizeToFit];
			o = [textField frame].origin;
			o.y += 2.0;
			[textField setFrameOrigin:o];
			[box addSubview:textField]; 
			// input field
			/*stepper = [[NSStepper new] autorelease];
			[stepper setMinValue:pos->value.UInt64.min];
			[stepper setMaxValue:pos->value.UInt64.max];
			[stepper setIncrement:1.0];
			[stepper setDoubleValue:pos->value.UInt64.val];
			[stepper setToolTip:[[[NSString alloc]
					initWithCString:pos->help
					encoding:NSUTF8StringEncoding] 
				autorelease]];
			[stepper sizeToFit];
			s.width = 200;
			s.height = [stepper frame].size.height;
			[stepper setFrameSize:s];
			delegate = [[[GNUnetSetupStringDelegate alloc]
					initWithSetupView:self
					treeNode:pos] autorelease];
			[controlDelegates addObject:delegate];
			[stepper setTarget:delegate];
			[stepper setAction:@selector(handleAction:)];
			[box addSubview:stepper]; */
			// input field
			textField = [[NSTextField new] autorelease];
			[[textField cell] setFont:[NSFont
				systemFontOfSize:[NSFont smallSystemFontSize]]];
			[[textField cell] setScrollable:YES];
			[textField setDoubleValue:pos->value.UInt64.max];
			[textField setToolTip:[[[NSString alloc]
					initWithCString:pos->help
					encoding:NSUTF8StringEncoding] 
				autorelease]];
			[textField setEditable:YES];
			[textField sizeToFit];
			[textField setDoubleValue:pos->value.UInt64.val];
			delegate = [[[GNUnetSetupStringDelegate alloc]
					initWithSetupView:self
					treeNode:pos] autorelease];
			[controlDelegates addObject:delegate];
			[textField setTarget:delegate];
			[textField setAction:@selector(handleAction:)];
			[textField setDelegate:delegate];
			[box addSubview:textField]; 
			break;
		default:
			GNUNET_GE_ASSERT (NULL, 0);
			return 0;
	}
	[self linkVisibilityNode:pos view:box];
	[parent addSubview:box];
	return 1;
}

- (void) alertDidEnd:(NSAlert *)alert returnCode:(int)returnCode contextInfo:(void *)contextInfo;
{
	//NSControl *sender = (NSControl *)contextInfo;
}

- (void) repackViewTreeFrom:(NSView *)v
{
	do {
		NSSize s;
		if ([v isKindOfClass:[PackingBoxContainer class]]) {
			[(PackingBoxContainer *)v repack];
		}
		else if ([v isKindOfClass:[NSTabView class]]) {
			NSTabView *tv = (NSTabView *)v;
			s.width = [tv frame].size.width;
			s.height = ([tv frame].size.height -
					[tv contentRect].size.height) +
				[[[tv selectedTabViewItem] view] 
					frame].size.height;
			[tv setFrameSize:s];
		}
		else 
			break;
		[v setNeedsDisplay:YES];
		v = [v superview];
	} while (v != nil && v != self);
	[self setFrameSize:[rootView frame].size];
	[self setNeedsDisplay:YES];
}

- (void) tabView:(NSTabView *)tabView
	didSelectTabViewItem:(NSTabViewItem *)tabViewItem
{
	[self repackViewTreeFrom:[tabViewItem view]];
}

// outline view data source
- (int) outlineView:(NSOutlineView *)outlineView numberOfChildrenOfItem:(id)item
{
	return (item == nil) ?
		[rootNode numberOfChildren] :
		[item numberOfChildren];
}

- (BOOL) outlineView:(NSOutlineView *)outlineView isItemExpandable:(id)item
{
	return (item == nil) ?  
		([rootNode numberOfChildren] != -1) :
		([item numberOfChildren] != -1);
}

- (id) outlineView:(NSOutlineView *)outlineView
    child:(int)index
    ofItem:(id)item
{
	return (item == nil) ?
		(GNUNETSetupTreeNode *)[rootNode childAtIndex:index] : 
		(GNUNETSetupTreeNode *)[item childAtIndex:index];
}

- (id) outlineView:(NSOutlineView *)outlineView
    objectValueForTableColumn:(NSTableColumn *)tableColumn
    byItem:(id)item
{
	return (item == nil) ? [rootNode title] : [item title];
}

// outline view delegate
- (BOOL) outlineView:(NSOutlineView *)outlineView shouldSelectItem:(id)item
{
	if ([[outlineView window] firstResponder] != nil && 
			[[outlineView window] firstResponder] != outlineView)
		return [[outlineView window] makeFirstResponder:nil];
	else
		return YES;
}

- (void) outlineViewSelectionDidChange:(NSNotification *)notification
{
	NSOutlineView *outlineView;
	GNUNETSetupTreeNode *setupTreeNode;
	const char *s;

	outlineView = (NSOutlineView *)[notification object];
	setupTreeNode = [outlineView itemAtRow:[outlineView selectedRow]];
	
	s = [setupTreeNode treeNode]->help;
	if (s == NULL || strlen(s) == 0)
		s = [setupTreeNode treeNode]->description;

	[rootTitle setStringValue:[[[NSString alloc]
			initWithCString:(s == NULL ? "" : s)
			encoding:NSUTF8StringEncoding] 
		autorelease]];
	[rootTabView selectTabViewItem:[setupTreeNode tabViewItem]];

	[[outlineView window] makeFirstResponder:outlineView];
}

// if a collapsing node's child is selected, update selection
// to the collapsing node (otherwise selection would become nil)
- (void)outlineViewItemWillCollapse:(NSNotification *)notification
{
	NSOutlineView *outlineView;
	GNUNETSetupTreeNode *collapsedNode;
	GNUNETSetupTreeNode *node;

	outlineView = (NSOutlineView *)[notification object];

	collapsedNode = [[notification userInfo]
		objectForKey:@"NSObject"];
	node = [outlineView itemAtRow:[outlineView selectedRow]];
	while ((node = [node parent]) != nil) {
		if (node == collapsedNode) {
			NSIndexSet *set;
			set = [[[NSIndexSet alloc] 
				initWithIndex:[outlineView rowForItem:node]]
				autorelease];
			[outlineView selectRowIndexes:set 
				byExtendingSelection:NO];
		}
	}	
}
@end

