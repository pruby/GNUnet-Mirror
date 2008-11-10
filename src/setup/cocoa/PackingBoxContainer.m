/*
 *  PackingBoxContainer
 *  Copyright (C) 2008  Heikki Lindholm <holindho@cs.helsinki.fi>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#import <Foundation/NSNotification.h>
#import <Foundation/NSEnumerator.h>
#import <PackingBoxContainer.h>

@implementation PackingBoxContainer : NSView
- (id)init
{
	return [self initWithSpacing:0.0 horizontal:NO];
}

- (id)initWithSpacing:(float)spacing horizontal:(BOOL)horizontal
{
	if ((self = [super init])) {
		if (!(subviewArray = [NSMutableArray new])) {
			[self release];
			return nil;
		}
		itemSpacing = spacing;
		horizontalMargins = verticalMargins = 0.0;
		maxWidth = maxHeight = 10000.0;
		if (itemSpacing < 0.0)
			itemSpacing = 0.0;
		isHorizontal = horizontal;
		isReversed = NO;
	}

	return self;
}

- (void)dealloc
{
	NSEnumerator *e;
	NSView *v;
	e = [subviewArray objectEnumerator];
	while ((v = [e nextObject])) {
		[v removeFromSuperview];
	}
	[[NSNotificationCenter defaultCenter] removeObserver:self];
	[subviewArray release];
	[super dealloc];
}

- (void) setReversedPacking:(BOOL)value
{
	isReversed = value;
}

- (void) setHorizontalMargins:(float)value
{
	horizontalMargins = value;
}

- (float) horizontalMargins
{
	return horizontalMargins;
}

- (void) setVerticalMargins:(float)value
{
	verticalMargins = value;
}

- (float) verticalMargins
{
	return verticalMargins;
}

- (void) setMaxWidth:(float)width
{
	maxWidth = width;
}

- (void) setMaxHeight:(float)height;
{
	maxHeight = height;
}

- (void) addSubview:(NSView *)subview
{
	NSPoint origin;

	if (subview == nil)
		return;

	origin = [subview frame].origin;
	if (isHorizontal)
		origin.y += verticalMargins;
	else
		origin.x += horizontalMargins;
	[subview setFrameOrigin:origin];	
	[subviewArray addObject:subview];

	[self repack];

	[super addSubview:subview];	
}

- (void)willRemoveSubview:(NSView *)subview
{
	[[NSNotificationCenter defaultCenter] removeObserver:self
		name:NSViewFrameDidChangeNotification object:subview];
	[subviewArray removeObject:subview];
	[super willRemoveSubview:subview];	
}

- (void)repack
{
	NSSize oldSize;
	NSSize newSize;
	NSEnumerator *e;
	NSView *v;

	oldSize = [self frame].size;
	newSize = oldSize;

	[[NSNotificationCenter defaultCenter] removeObserver:self];

	if (isHorizontal)
		newSize.width = 0.0 + horizontalMargins;
	else
		newSize.height = 0.0 + verticalMargins;

	if (isReversed)
		e = [subviewArray reverseObjectEnumerator];
	else
		e = [subviewArray objectEnumerator];

	while ((v = [e nextObject])) {
		NSPoint origin;
		NSSize size;

		if ([v isHidden]) 
			continue;

		origin = [v frame].origin;
		size = [v frame].size;
		if (isHorizontal) {
			origin.x = newSize.width;
			//origin.y = verticalMargins;

			newSize.width += size.width + itemSpacing;

			if (size.height > maxHeight - 2*verticalMargins) {
				size.height = maxHeight - 2*verticalMargins;
				[v setFrameSize:size]; 
			}
			if (origin.y + size.height > newSize.height)
				newSize.height = origin.y + size.height;
		}
		else {
			//origin.x = horizontalMargins;
			origin.y = newSize.height;

			if (size.width > maxWidth - 2*horizontalMargins) {
				size.width = maxWidth - 2*horizontalMargins;
				[v setFrameSize:size]; 
			}
			if (origin.x + size.width > newSize.width)
				newSize.width = origin.x + size.width;

			newSize.height += size.height + itemSpacing;

		}
		[v setFrameOrigin:origin];
		[v setNeedsDisplay:YES];
		[v setPostsFrameChangedNotifications:YES];
		[[NSNotificationCenter defaultCenter] addObserver:self
			selector:@selector(repack)
			name:NSViewFrameDidChangeNotification object:v];

	}
	newSize.width += horizontalMargins;
	newSize.height += verticalMargins;
	if (isHorizontal) {
		if (newSize.width > 0.0)
			newSize.width -= itemSpacing;
		if (newSize.height < oldSize.height)
			newSize.height = oldSize.height;
		if (newSize.height > maxHeight)
			newSize.height = maxHeight;
	}
	else {
		if (newSize.height > 0.0)
			newSize.height -= itemSpacing;
		if (newSize.width < oldSize.width)
			newSize.width = oldSize.width;
		if (newSize.width > maxWidth)
			newSize.width = maxWidth;
	}
	if (newSize.width != oldSize.width ||
			newSize.height != oldSize.height) {
		[[self superview] setNeedsDisplayInRect:[self frame]];
		[self setFrameSize:newSize];
	}
	[self setNeedsDisplay:YES];
}
@end

