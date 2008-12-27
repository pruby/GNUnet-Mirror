/*
 *  PackingBoxContainer
 *  Copyright (C) 2008  Heikki Lindholm <holindho@cs.helsinki.fi>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#import <Foundation/NSArray.h>
#import <AppKit/NSView.h>

@ interface PackingBoxContainer:NSView
{
  NSMutableArray *subviewArray;
  float itemSpacing;
  float horizontalMargins;
  float verticalMargins;
  float maxWidth;
  float maxHeight;
  BOOL isHorizontal;
  BOOL isReversed;
}

-(id) init;
-(id) initWithSpacing:(float)
     spacing horizontal:(BOOL) horizontal;
-(void) setReversedPacking:(BOOL) value;
-(void) setHorizontalMargins:(float) value;
-(float) horizontalMargins;
-(void) setVerticalMargins:(float) value;
-(float) verticalMargins;
-(void) setMaxWidth:(float) maxWidth;
-(void) setMaxHeight:(float) maxHeight;
-(void) dealloc;
-(void) addSubview:(NSView *) subview;
-(void) willRemoveSubview:(NSView *) subview;
-(void) repack;
@end
