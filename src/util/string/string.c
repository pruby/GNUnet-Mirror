/*
     This file is part of GNUnet.
     (C) 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/string/string.c
 * @brief string functions
 * @author Nils Durner
 * @author Christian Grothoff
 */

#include "gnunet_util_string.h"
#include "platform.h"
#if HAVE_ICONV_H
#include <iconv.h>
#endif


int
SNPRINTF (char *buf, size_t size, const char *format, ...)
{
  int ret;
  va_list args;

  va_start (args, format);
  ret = VSNPRINTF (buf, size, format, args);
  va_end (args);
  GE_ASSERT (NULL, ret <= size);
  return ret;
}

#if !HAVE_STRLCPY
/**
 * @brief Copy a %NUL terminated string into a sized buffer
 * @author Linus Torvalds
 * @param dest Where to copy the string to
 * @param src Where to copy the string from
 * @param size size of destination buffer
 * @remarks Compatible with *BSD: the result is always a valid
 *          NUL-terminated string that fits in the buffer (unless,
 *          of course, the buffer size is zero). It does not pad
 *          out the result like strncpy() does.
 */
size_t
strlcpy (char *dest, const char *src, size_t size)
{
  size_t ret;

  GE_ASSERT (NULL, dest != NULL);
  GE_ASSERT (NULL, size > 0);
  GE_ASSERT (NULL, src != NULL);
  ret = strlen (src);

  if (size)
    {
      size_t len = (ret >= size) ? size - 1 : ret;
      memcpy (dest, src, len);
      dest[len] = '\0';
    }
  return ret;
}
#endif

#if !HAVE_STRLCAT
/**
 * @brief Append a length-limited, %NUL-terminated string to another
 * @author Linus Torvalds
 * @param dest The string to be appended to
 * @param src The string to append to it
 * @param count The size of the destination buffer.
 */
size_t
strlcat (char *dest, const char *src, size_t count)
{
  size_t dsize;
  size_t len;
  size_t res;

  GE_ASSERT (NULL, dest != NULL);
  GE_ASSERT (NULL, src != NULL);
  GE_ASSERT (NULL, count > 0);
  dsize = strlen (dest);
  len = strlen (src);
  res = dsize + len;
  GE_ASSERT (NULL, dsize < count);

  dest += dsize;
  count -= dsize;
  if (len >= count)
    len = count - 1;
  memcpy (dest, src, len);
  dest[len] = 0;
  return res;
}
#endif

/**
 * Give relative time in human-readable fancy format.
 * @param delta time in milli seconds
 */
char *
string_get_fancy_time_interval (unsigned long long delta)
{
  const char *unit = _( /* time unit */ "ms");
  char *ret;

  if (delta > 5 * 1000)
    {
      delta = delta / 1000;
      unit = _( /* time unit */ "s");
      if (delta > 5 * 60)
        {
          delta = delta / 60;
          unit = _( /* time unit */ "m");
          if (delta > 5 * 60)
            {
              delta = delta / 60;
              unit = _( /* time unit */ "h");
              if (delta > 5 * 24)
                {
                  delta = delta / 24;
                  unit = _( /* time unit */ " days");
                }
            }
        }
    }
  ret = MALLOC (32);
  SNPRINTF (ret, 32, "%llu%s", delta, unit);
  return ret;
}

/**
 * Convert a given filesize into a fancy human-readable format.
 */
char *
string_get_fancy_byte_size (unsigned long long size)
{
  const char *unit = _( /* size unit */ "b");
  char *ret;

  if (size > 5 * 1024)
    {
      size = size / 1024;
      unit = _( /* size unit */ "KiB");
      if (size > 5 * 1024)
        {
          size = size / 1024;
          unit = _( /* size unit */ "MiB");
          if (size > 5 * 1024)
            {
              size = size / 1024;
              unit = _( /* size unit */ "GiB");
              if (size > 5 * 1024)
                {
                  size = size / 1024;
                  unit = _( /* size unit */ "TiB");
                }
            }
        }
    }
  ret = MALLOC (32);
  SNPRINTF (ret, 32, "%llu%s", size, unit);
  return ret;
}




/**
 * Convert the len characters long character sequence
 * given in input that is in the given charset
 * to UTF-8.
 * @return the converted string (0-terminated),
 *  if conversion fails, a copy of the orignal
 *  string is returned.
 */
char *
string_convertToUtf8 (struct GE_Context *ectx,
                      const char *input, size_t len, const char *charset)
{
  char *ret;
#if ENABLE_NLS && HAVE_ICONV
  size_t tmpSize;
  size_t finSize;
  char *tmp;
  char *itmp;
  iconv_t cd;

  cd = iconv_open ("UTF-8", charset);
  if (cd == (iconv_t) - 1)
    {
      GE_LOG_STRERROR (ectx,
                       GE_USER | GE_ADMIN | GE_WARNING | GE_BULK,
                       "iconv_open");
      ret = MALLOC (len + 1);
      memcpy (ret, input, len);
      ret[len] = '\0';
      return ret;
    }
  tmpSize = 3 * len + 4;
  tmp = MALLOC (tmpSize);
  itmp = tmp;
  finSize = tmpSize;
  if (iconv (cd, (char **) &input, &len, &itmp, &finSize) == (size_t) - 1)
    {
      GE_LOG_STRERROR (ectx, GE_USER | GE_WARNING | GE_BULK, "iconv");
      iconv_close (cd);
      FREE (tmp);
      ret = MALLOC (len + 1);
      memcpy (ret, input, len);
      ret[len] = '\0';
      return ret;
    }
  ret = MALLOC (tmpSize - finSize + 1);
  memcpy (ret, tmp, tmpSize - finSize);
  ret[tmpSize - finSize] = '\0';
  FREE (tmp);
  if (0 != iconv_close (cd))
    GE_LOG_STRERROR (ectx, GE_ADMIN | GE_WARNING | GE_REQUEST, "iconv_close");
  return ret;
#else
  ret = MALLOC (len + 1);
  memcpy (ret, input, len);
  ret[len] = '\0';
  return ret;
#endif
}




/**
 * Complete filename (a la shell) from abbrevition.
 * @param fil the name of the file, may contain ~/ or
 *        be relative to the current directory
 * @returns the full file name,
 *          NULL is returned on error
 */
char *
string_expandFileName (struct GE_Context *ectx, const char *fil)
{
  char *buffer;
#ifndef MINGW
  size_t len;
  size_t n;
  char *fm;
  const char *fil_ptr;
#else
  char *fn;
  long lRet;
#endif

  if (fil == NULL)
    return NULL;

#ifndef MINGW
  if (fil[0] == DIR_SEPARATOR)
    /* absolute path, just copy */
    return STRDUP (fil);
  if (fil[0] == '~')
    {
      fm = getenv ("HOME");
      if (fm == NULL)
        {
          GE_LOG (ectx,
                  GE_USER | GE_ADMIN | GE_WARNING | GE_IMMEDIATE,
                  _
                  ("Failed to expand `$HOME': environment variable `HOME' not set"));
          return NULL;
        }
      fm = STRDUP (fm);
      /* do not copy '~' */
      fil_ptr = fil + 1;

      /* skip over dir seperator to be consistent */
      if (fil_ptr[0] == DIR_SEPARATOR)
        fil_ptr++;
    }
  else
    {
      /* relative path */
      fil_ptr = fil;
      len = 512;
      fm = NULL;
      while (1)
        {
          buffer = MALLOC (len);
          if (getcwd (buffer, len) != NULL)
            {
              fm = buffer;
              break;
            }
          if ((errno == ERANGE) && (len < 1024 * 1024 * 4))
            {
              len *= 2;
              FREE (buffer);
              continue;
            }
          FREE (buffer);
          break;
        }
      if (fm == NULL)
        {
          GE_LOG_STRERROR (ectx,
                           GE_USER | GE_WARNING | GE_IMMEDIATE, "getcwd");
          buffer = getenv ("PWD");      /* alternative */
          if (buffer != NULL)
            fm = STRDUP (buffer);
        }
      if (fm == NULL)
        fm = STRDUP ("./");     /* give up */
    }
  n = strlen (fm) + 1 + strlen (fil_ptr) + 1;
  buffer = MALLOC (n);
  SNPRINTF (buffer, n, "%s/%s", fm, fil_ptr);
  FREE (fm);
  return buffer;
#else
  fn = MALLOC (MAX_PATH + 1);

  if ((lRet = plibc_conv_to_win_path (fil, fn)) != ERROR_SUCCESS)
    {
      SetErrnoFromWinError (lRet);
      GE_LOG_STRERROR (ectx,
                       GE_USER | GE_WARNING | GE_IMMEDIATE,
                       "plibc_conv_to_win_path");
      return NULL;
    }
  /* is the path relative? */
  if ((strncmp (fn + 1, ":\\", 2) != 0) && (strncmp (fn, "\\\\", 2) != 0))
    {
      char szCurDir[MAX_PATH + 1];
      lRet = GetCurrentDirectory (MAX_PATH + 1, szCurDir);
      if (lRet + strlen (fn) + 1 > (MAX_PATH + 1))
        {
          SetErrnoFromWinError (ERROR_BUFFER_OVERFLOW);
          GE_LOG_STRERROR (ectx,
                           GE_USER | GE_WARNING | GE_IMMEDIATE,
                           "GetCurrentDirectory");
          return NULL;
        }
      buffer = MALLOC (MAX_PATH + 1);
      SNPRINTF (buffer, MAX_PATH + 1, "%s\\%s", szCurDir, fn);
      FREE (fn);
      fn = buffer;
    }

  return fn;
#endif
}



/* end of string.c */
