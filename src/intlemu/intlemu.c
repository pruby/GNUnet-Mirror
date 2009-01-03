/*
 *  libintlemu - A Core Foundation libintl emulator
 *  Copyright (C) 2008  Heikki Lindholm <holin@iki.fi>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <pthread.h>

static pthread_mutex_t intlemu_lock;
static CFMutableDictionaryRef intlemu_dict;

static void
intlemu_cstring_release (CFAllocatorRef allocator, const void *value)
{
  free ((void *) value);
}

void __attribute__ ((constructor)) intlemu_init_ ()
{
  CFDictionaryValueCallBacks cstring_value_callbacks = {
    0,                          /* version */
    NULL,                       /* retain callback */
    &intlemu_cstring_release,   /* release callback */
    NULL,                       /* copy description */
    NULL                        /* equal */
  };
  if (pthread_mutex_init (&intlemu_lock, NULL) != 0)
    abort ();

  intlemu_dict = CFDictionaryCreateMutable (kCFAllocatorDefault,
                                            0,
                                            &kCFCopyStringDictionaryKeyCallBacks,
                                            &cstring_value_callbacks);
  if (intlemu_dict == NULL)
    abort ();
}

void __attribute__ ((destructor)) intlemu_fini_ ()
{
  if (intlemu_dict)
    CFRelease (intlemu_dict);

  pthread_mutex_destroy (&intlemu_lock);
}

char *
intlemu_bgettext (CFBundleRef bundle, const char *msgid)
{
  CFStringRef key;
  const char *value;
  CFStringRef s;
  CFRange r;
  CFIndex len;
  CFIndex clen;
  char *buf;

  if (msgid == NULL)
    return NULL;
  if (bundle == NULL)
    return msgid;

  key = CFStringCreateWithBytes (kCFAllocatorDefault,
                                 (const UInt8 *) msgid,
                                 (CFIndex) strlen (msgid),
                                 kCFStringEncodingUTF8, false);

  if (pthread_mutex_lock (&intlemu_lock) != 0)
    abort ();
  value = (char *) CFDictionaryGetValue (intlemu_dict, key);
  if (pthread_mutex_unlock (&intlemu_lock) != 0)
    abort ();
  if (value != NULL)
    {
      CFRelease (key);
      return (char *) value;
    }

  /* no cached translaation, so, find one from the bundle */
  s = CFBundleCopyLocalizedString (bundle, key, NULL, NULL);
  if (s == key)
    {
      CFRelease (key);
      return (char *) msgid;
    }
  /* get the length in bytes */
  r.location = 0;
  r.length = CFStringGetLength (s);
  len = 0;
  clen = CFStringGetBytes (s,
                           r, kCFStringEncodingUTF8, 0, false, NULL, 0, &len);
  buf = NULL;
  if (clen == r.length)
    {
      buf = malloc (len + 1);
    }

  if (buf == NULL)
    {
      CFRelease (s);
      CFRelease (key);
      return (char *) msgid;
    }

  clen = CFStringGetBytes (s,
                           r,
                           kCFStringEncodingUTF8,
                           0, false, (UInt8 *) buf, len, &len);
  buf[len] = '\0';
  if (clen == r.length)
    {
      if (pthread_mutex_lock (&intlemu_lock) != 0)
        abort ();
      CFDictionaryAddValue (intlemu_dict, key, buf);
      if (pthread_mutex_unlock (&intlemu_lock) != 0)
        abort ();
      value = buf;
    }
  else
    {
      free (buf);
      value = msgid;
    }

  CFRelease (s);

  CFRelease (key);

  return (char *) value;
}
