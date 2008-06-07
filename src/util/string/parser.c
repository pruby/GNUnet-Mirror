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
 * @file util/string/parser.c
 * @brief string parser helper functions
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util.h"

/**
 * Fill a buffer of the given size with
 * count 0-terminated strings (given as varargs).
 * If "buffer" is NULL, only compute the amount of
 * space required (sum of "strlen(arg)+1").
 *
 * Unlike using "snprintf" with "%s", this function
 * will add 0-terminators after each string.  The
 * "GNUNET_string_buffer_tokenize" function can be
 * used to parse the buffer back into individual
 * strings.
 *
 * @return number of bytes written to the buffer
 *         (or number of bytes that would have been written)
 */
unsigned int
GNUNET_string_buffer_fill (char *buffer,
                           unsigned int size, unsigned int count, ...)
{
  unsigned int needed;
  unsigned int slen;
  const char *s;
  va_list ap;

  needed = 0;
  va_start (ap, count);
  while (count > 0)
    {
      s = va_arg (ap, const char *);
      slen = strlen (s) + 1;
      if (buffer != NULL)
        {
          GNUNET_GE_ASSERT (NULL, needed + slen <= size);
          memcpy (&buffer[needed], s, slen);
        }
      needed += slen;
      count--;
    }
  va_end (ap);
  return needed;
}

/**
 * Given a buffer of a given size, find "count"
 * 0-terminated strings in the buffer and assign
 * the count (varargs) of type "const char**" to the
 * locations of the respective strings in the
 * buffer.
 *
 * @param buffer the buffer to parse
 * @param size size of the buffer
 * @param count number of strings to locate
 * @return offset of the character after the last 0-termination
 *         in the buffer, or 0 on error.
 */
unsigned int
GNUNET_string_buffer_tokenize (const char *buffer,
                               unsigned int size, unsigned int count, ...)
{
  unsigned int start;
  unsigned int needed;
  const char **r;
  va_list ap;

  needed = 0;
  va_start (ap, count);
  while (count > 0)
    {
      r = va_arg (ap, const char **);
      start = needed;
      while ((needed < size) && (buffer[needed] != '\0'))
        needed++;
      if (needed == size)
        {
          va_end (ap);
          return 0;             /* error */
        }
      *r = &buffer[start];
      needed++;                 /* skip 0-termination */
      count--;
    }
  va_end (ap);
  return needed;
}

/* end of parser.c */
