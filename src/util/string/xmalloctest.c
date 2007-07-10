/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/string/xmalloctest.c
 * @brief testcase for util/string/xmalloc.c
 */

#include "gnunet_util.h"
#include "platform.h"

static int
check ()
{
#define MAX_TESTVAL 1024
  char *ptrs[MAX_TESTVAL];
  int i;
  int j;
  int k;
  unsigned int ui;

  /* MALLOC/FREE test */
  k = 352;                      /* random start value */
  for (i = 1; i < MAX_TESTVAL; i++)
    {
      ptrs[i] = MALLOC (i);
      for (j = 0; j < i; j++)
        ptrs[i][j] = k++;
    }

  for (i = MAX_TESTVAL - 1; i >= 1; i--)
    {
      for (j = i - 1; j >= 0; j--)
        if (ptrs[i][j] != (char) --k)
          return 1;
      FREE (ptrs[i]);
    }

  /* STRNDUP tests */
  FREE (STRNDUP ("foo", 0));
  ptrs[0] = STRNDUP ("foo", 42);
  if (0 != strcmp (ptrs[0], "foo"))
    return 1;
  FREE (ptrs[0]);
  ptrs[0] = STRNDUP ("foo", 2);
  if (0 != strcmp (ptrs[0], "fo"))
    return 2;
  FREE (ptrs[0]);

  /* FREENONNULL test */
  FREENONNULL (NULL);
  FREENONNULL (MALLOC (4));

  /* STRDUP tests */
  ptrs[0] = STRDUP ("bar");
  if (0 != strcmp (ptrs[0], "bar"))
    return 3;
  FREE (ptrs[0]);

  /* GROW tests */
  ptrs[0] = NULL;
  ui = 0;
  GROW (ptrs[0], ui, 42);
  if (ui != 42)
    return 4;
  GROW (ptrs[0], ui, 22);
  if (ui != 22)
    return 5;
  for (j = 0; j < 22; j++)
    ptrs[0][j] = j;
  GROW (ptrs[0], ui, 32);
  for (j = 0; j < 22; j++)
    if (ptrs[0][j] != j)
      return 6;
  for (j = 22; j < 32; j++)
    if (ptrs[0][j] != 0)
      return 7;
  GROW (ptrs[0], ui, 0);
  if (i != 0)
    return 8;
  if (ptrs[0] != NULL)
    return 9;


  return 0;
}

int
main (int argc, char *argv[])
{
  int ret;
  ret = check ();
  if (ret != 0)
    fprintf (stderr, "ERROR %d.\n", ret);
  return ret;
}

/* end of xmalloctest.c */
