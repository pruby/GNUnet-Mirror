/*
      This file is part of GNUnet

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
 * This is a testcase for the vector, waiting to be extended.
 */

#include "platform.h"
#include "gnunet_util.h"

#define DUMP(v) fprintf(stderr, "At %d: \n", __LINE__); vectorDump(v);

static int test(int size) {
  struct Vector * v;

  v = vectorNew(size);
  if (0 != vectorSize(v))
    { DUMP(v); return 1; }
  if (OK != vectorInsertAt(v, "first", 0))
    { DUMP(v); return 1; }
  if (OK == vectorInsertAt(v, "not", 2))
    { DUMP(v); return 1; }
  if (OK != vectorInsertAt(v, "zero", 0))
    { DUMP(v); return 1; }
  if (OK != vectorInsertAt(v, "second", 2))
    { DUMP(v); return 1; }
  vectorInsertLast(v, "third");
  if (4 != vectorSize(v))
    { DUMP(v); return 1; }
  if (0 != strcmp(vectorGetAt(v, 1), "first"))
    { DUMP(v); return 1; }
  if (0 != strcmp(vectorGetAt(v, 3), "third"))
    { DUMP(v); return 1; }
  if (0 != strcmp(vectorGetAt(v, 0), "zero"))
    { DUMP(v); return 1; }
  if (0 != strcmp(vectorGetFirst(v), "zero"))
    { DUMP(v); return 1; }
  if (0 != strcmp(vectorGetLast(v), "third"))
    { DUMP(v); return 1; }
  if (0 != strcmp(vectorRemoveAt(v, 1), "first"))
    { DUMP(v); return 1; }
  if (0 != strcmp(vectorGetAt(v, 1), "second"))
    { DUMP(v); return 1; }
  if (NULL != vectorRemoveAt(v, 3))
    { DUMP(v); return 1; }
  if (3 != vectorSize(v))
    { DUMP(v); return 1; }
  if (0 != strcmp(vectorRemoveAt(v, 1), "second"))
    { DUMP(v); return 1; }
  if (0 != strcmp(vectorRemoveObject(v, "third"), "third"))
    { DUMP(v); return 1; }
  if (NULL != vectorRemoveObject(v, "third"))
    { DUMP(v); return 1; }
  if (0 != strcmp(vectorRemoveLast(v), "zero"))
    { DUMP(v); return 1; }
  if (0 != vectorSize(v))
    { DUMP(v); return 1; }
  if (NULL != vectorRemoveLast(v))
    { DUMP(v); return 1; }
  if (0 != vectorSize(v))
    { DUMP(v); return 1; }
  vectorFree(v);
  return 0;
}

static int test2(int size) {
  int i;
  struct Vector * v;

  v = vectorNew(size);

  for (i=0;i<500;i++)
    if (OK != vectorInsertAt(v, (void*)i, 0))
      { DUMP(v); return 1; }
  if (500 != vectorSize(v))
    { DUMP(v); return 1; }
  for (i=0;i<500;i++)
    if (499 - i != (int) vectorGetAt(v, i))
      { DUMP(v); return 1; }
  if (499 != (int) vectorGetFirst(v))
    { DUMP(v); return 1; }
  for (i=498;i>=0;i--)
    if (i != (int) vectorGetNext(v))
      { DUMP(v); return 1; }

  if (499 != (int) vectorGetFirst(v))
    { DUMP(v); return 1; }
  for (i=498;i>=250;i--)
    if (i != (int) vectorGetNext(v))
      { DUMP(v); return 1; }
  for (i=251;i<499;i++)
    if (i != (int) vectorGetPrevious(v))
      { DUMP(v); return 1; }

  vectorFree(v);
  return 0;
}


int main(int argc,
	 char * argv[]) {
  if (NULL != vectorNew(0))
    { printf("At %d\n", __LINE__); return 1; }
  if (NULL != vectorNew(1))
    { printf("At %d\n", __LINE__); return 1; }
  if (test(2) != 0)
    { printf("At %d\n", __LINE__); return 1; }
  if (test(3) != 0)
    { printf("At %d\n", __LINE__); return 1; }
  if (test(4) != 0)
    { printf("At %d\n", __LINE__); return 1; }
  if (test(128) != 0)
    { printf("At %d\n", __LINE__); return 1; }
  if (test(65536) != 0)
    { printf("At %d\n", __LINE__); return 1; }
  if (test(2*65536) != 0)
    { printf("At %d\n", __LINE__); return 1; }

  if (test2(2) != 0)
    { printf("At %d\n", __LINE__); return 1; }
  if (test2(3) != 0)
    { printf("At %d\n", __LINE__); return 1; }
  if (test2(4) != 0)
    { printf("At %d\n", __LINE__); return 1; }
  if (test2(128) != 0)
    { printf("At %d\n", __LINE__); return 1; }
  return 0;
}
