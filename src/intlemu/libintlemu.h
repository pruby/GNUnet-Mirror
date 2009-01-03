/*
 *  libintlemu - A Core Foundation libintl emulator
 *  Copyright (C) 2008  Heikki Lindholm <holin@iki.fi>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#ifndef LIBINTLEMU_H
#define LIBINTLEMU_H

#include <CoreFoundation/CoreFoundation.h>

#define gettext(msgid) \
	intlemu_bgettext(CFBundleGetMainBundle(), msgid)

#define dgettext(domainname, msgid) \
	intlemu_bgettext(CFBundleGetBundleWithIdentifier(CFSTR(domainname)), msgid)

#define gettext_noop(s) s

extern char *intlemu_bgettext (CFBundleRef bundle, const char *msgid);

#endif
