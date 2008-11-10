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
 * @brief GNUnet Setup in Cocoa
 * @file setup/cocoa/config_cocoa.c
 * @author Heikki Lindholm
 */

#import <AppKit/NSWindow.h>
#import <AppKit/NSApplication.h>
#import <Carbon/Carbon.h>
#include "platform.h"
#include "gnunet_setup_lib.h"
#import "PackingBoxContainer.h"
#import "GNUNETSetupView.h"
#include "config_cocoa.h"

@interface GNUNETSetupApp : NSObject
{
	struct GNUNET_GC_Configuration *gnunetConfig;
	struct GNUNET_GNS_Context *gnunetGNSCtx;
	struct GNUNET_GE_Context *gnunetGECtx;
	const char *configFilename;

	NSWindow *setupWindow;
	PackingBoxContainer *rootView;
	GNUNETSetupView *setupView;
}

- (id) initWithConfig:(struct GNUNET_GC_Configuration *)config
	setupContext:(struct GNUNET_GNS_Context *)gns
	errorContext:(struct GNUNET_GE_Context *)ectx
	configFilename:(const char *)filename;
- (void) createWindow;
- (void) setupViewDidResize;
- (BOOL) needsToSaveConfig;
- (void) errorSavingAlertDidEnd:(NSAlert *)theAlert
	returnCode:(int)returnCode
	contextInfo:(void *)contextInfo;
- (void) saveOnExitAlertDidEnd:(NSAlert *)theAlert
	returnCode:(int)returnCode
	contextInfo:(void *)contextInfo;
- (void) applicationWillFinishLaunching: (NSNotification *)not;
- (void) applicationDidFinishLaunching: (NSNotification *)not;
- (BOOL) windowShouldClose:(id)window;
- (void) windowWillClose:(NSNotification *)notification;
- (NSApplicationTerminateReply)
	applicationShouldTerminate:(NSApplication *)sender;
@end

@implementation GNUNETSetupApp : NSObject 
- (id) initWithConfig:(struct GNUNET_GC_Configuration *)config
	setupContext:(struct GNUNET_GNS_Context *)gns
	errorContext:(struct GNUNET_GE_Context *)ectx
	configFilename:(const char *)filename
{
	if ((self = [super init])) {
		gnunetConfig = config;
		gnunetGNSCtx = gns;
		gnunetGECtx = ectx;
		configFilename = filename;
	}

	return self;
}
- (void) dealloc
{
	[setupWindow release];
	[super dealloc];
}

- (void) createWindow
{
	rootView = [[[PackingBoxContainer alloc]
		initWithSpacing:8.0
		horizontal:NO] autorelease];
	[rootView setHorizontalMargins:16.0];
	[rootView setVerticalMargins:16.0];
	setupView = [[[GNUNETSetupView alloc]
		initWithConfig:gnunetConfig
		setupContext:gnunetGNSCtx
		errorContext:gnunetGECtx
		maxWidth:768] autorelease];
	[rootView addSubview:setupView];

	setupWindow = [NSWindow alloc];
	setupWindow = [setupWindow
		initWithContentRect:NSMakeRect(0.0, 0.0, 800.0, 580.0)
		styleMask:NSTitledWindowMask |
				NSClosableWindowMask |
				NSMiniaturizableWindowMask
		backing:NSBackingStoreBuffered
		defer: NO];
	[setupWindow setTitle:@"gnunet-setup"];
	[setupWindow setReleasedWhenClosed:NO];

	[rootView setPostsFrameChangedNotifications:YES];
	[[NSNotificationCenter defaultCenter] addObserver:self
		selector:@selector(setupViewDidResize)
		name:NSViewFrameDidChangeNotification object:rootView];

	[[setupWindow contentView] addSubview:rootView];
	[setupWindow setDelegate:self];
	[self setupViewDidResize];
	[setupWindow center];
}

- (void) setupViewDidResize
{
	NSRect frame;
	frame = [setupWindow frame];
	frame.size = [setupWindow
		frameRectForContentRect:[rootView frame]].size;
	frame.origin.y -= (frame.size.height - [setupWindow frame].size.height);
	[setupWindow setFrame:frame display:YES];

}

- (void) errorSavingAlertDidEnd:(NSAlert *)theAlert
	returnCode:(int)returnCode
	contextInfo:(void *)contextInfo
{
	[setupWindow close];
}

- (void) saveOnExitAlertDidEnd:(NSAlert *)theAlert
	returnCode:(int)returnCode
	contextInfo:(void *)contextInfo
{
	if (returnCode == NSAlertFirstButtonReturn) { // Yes
		if (0 != GNUNET_GC_write_configuration (gnunetConfig, 
				configFilename)) {
			NSAlert *alert = [[[NSAlert alloc] init] autorelease];
			[[theAlert window] orderOut:self];
			[alert setMessageText:[[[NSString alloc]
				initWithCString:_("Error saving configuration.")
				encoding:NSUTF8StringEncoding] autorelease]];
			[alert addButtonWithTitle:[[[NSString alloc]
				initWithCString:_("OK")
				encoding:NSUTF8StringEncoding] autorelease]]; 
// TODO: insert reason, if possible
//			[alert setInformativeText:[[[NSString alloc]
//				initWithCString:_("Error saving configuration.")
//				encoding:NSUTF8StringEncoding] autorelease]];
			[alert setAlertStyle:NSWarningAlertStyle];
			[alert beginSheetModalForWindow:setupWindow
				modalDelegate:self
				didEndSelector:@selector(errorSavingAlertDidEnd:
					returnCode:
					contextInfo:)
				contextInfo:nil];
		}
		else {
			[setupWindow close];
		}
	}
	else if (returnCode == NSAlertThirdButtonReturn) { // No
		[setupWindow close];
	}
	// for 'Cancel' (NSAlertSecondButtonReturn) we do nothing
}

- (BOOL) needsToSaveConfig
{
	if (GNUNET_GC_test_dirty (gnunetConfig)) {
		NSAlert *alert = [[[NSAlert alloc] init] autorelease];
		[alert setMessageText:[[[NSString alloc]
			initWithCString:_("Configuration changed. Save?")
			encoding:NSUTF8StringEncoding] autorelease]];
		[alert addButtonWithTitle:[[[NSString alloc]
			initWithCString:_("Yes")
			encoding:NSUTF8StringEncoding] autorelease]]; 
		[alert addButtonWithTitle:[[[NSString alloc]
			initWithCString:_("Cancel")
			encoding:NSUTF8StringEncoding] autorelease]]; 
		[alert addButtonWithTitle:[[[NSString alloc]
			initWithCString:_("No")
			encoding:NSUTF8StringEncoding] autorelease]]; 
// 
//		[alert setInformativeText:[[[NSString alloc]
//			initWithCString:_("Configuration changed. Save?")
//			encoding:NSUTF8StringEncoding] autorelease]];
		[alert setAlertStyle:NSWarningAlertStyle];
		[alert beginSheetModalForWindow:setupWindow
			modalDelegate:self
			didEndSelector:@selector(saveOnExitAlertDidEnd:
				returnCode:
				contextInfo:)
			contextInfo:nil];
		return YES;
	}
	return NO;
}

- (void) applicationWillFinishLaunching:(NSNotification *)notification
{
	[self createWindow];
}

- (void) applicationDidFinishLaunching:(NSNotification *)notification
{
	[setupWindow makeKeyAndOrderFront: nil];
}

- (BOOL) windowShouldClose:(id)window
{
	if ([window firstResponder] != nil &&
			[window makeFirstResponder:nil] == NO)
		return NO;

	return [self needsToSaveConfig] == YES ? NO : YES;
}

- (void) windowWillClose:(NSNotification *)notification
{
	[[NSNotificationCenter defaultCenter] removeObserver:self];
	[setupWindow setDelegate:nil];
	[rootView removeFromSuperview];
	[NSApp stop:self];
}

- (NSApplicationTerminateReply)
	applicationShouldTerminate:(NSApplication *)sender
{
	if ([setupWindow firstResponder] != nil && 
			[setupWindow makeFirstResponder:nil] == NO)
		return NSTerminateCancel;

	return [self needsToSaveConfig] == YES ? NO : YES;
}
@end



int config_cocoa_mainsetup_cocoa (int argc, const char **argv,
	struct GNUNET_PluginHandle *selfHandle,
	struct GNUNET_GE_Context *ectx,
	struct GNUNET_GC_Configuration *cfg,
	struct GNUNET_GNS_Context *gns,
	const char *filename,
	int is_daemon)
{
	NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
	GNUNETSetupApp *setup;
	ProcessSerialNumber psn;

#if ENABLE_NLS
	bind_textdomain_codeset (PACKAGE, "UTF-8");
#endif

	if (GetCurrentProcess(&psn) == noErr) {
		TransformProcessType(
			&psn,kProcessTransformToForegroundApplication);
		SetFrontProcess(&psn);
	}

	NSApp = [NSApplication sharedApplication];

	setup = [[GNUNETSetupApp alloc]
                initWithConfig:cfg setupContext:gns errorContext:ectx
		configFilename:filename];
	[NSApp setDelegate:setup];
	//[NSApp setMainMenu:[[NSMenu alloc] init]];
	
	[NSApp run];

	[NSApp setDelegate:nil];
	[setup release];
	[NSApp release];
	[pool release];

	return 0;
}

