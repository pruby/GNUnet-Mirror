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
 * @file applications/dht/module/datastore_memory_test.c
 * @brief testcase for the Datastore API (memory).
 * @author Christian Grothoff
 *
 * TODO: test out-of-memory condition, iterator
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_dht_datastore_memory.h"
#include "gnunet_dht_service.h"

#define DUMP(v) fprintf(stderr, "At %d: \n", __LINE__);

static int store(Blockstore * s,
		 char * key,
		 char * val) {
  HashCode512 hc;
  DataContainer * cont;

  cont = MALLOC(sizeof(DataContainer) + strlen(val));
  cont->size = htonl(strlen(val) + sizeof(DataContainer));
  memcpy(&cont[1],
	 val,
	 strlen(val));
  hash(key,
       strlen(key),
       &hc);
  if (OK != s->put(s->closure,
		   &hc,
		   cont,
		   0)) {
    DUMP(s);
    FREE(cont);
    return 1;
  }
  FREE(cont);
  return 0;
}

static int rem(Blockstore * s,
	       char * key,
	       char * val) {
  HashCode512 hc;
  DataContainer * cont;

  if (val == NULL) {
    cont = NULL;
  } else {
    cont = MALLOC(sizeof(DataContainer) + strlen(val));
    cont->size = htonl(strlen(val) + sizeof(DataContainer));
    memcpy(&cont[1],
	   val,
	   strlen(val));
  }
  hash(key,
       strlen(key),
       &hc);
  if (OK != s->del(s->closure,
		   &hc,
		   cont)) {
    FREE(cont);
    DUMP(s);
    return 1;
  }
  FREE(cont);
  return 0;
}

static int resCB(const HashCode512 * key,
		 const DataContainer * val,
		 void * cls) {
  DataContainer ** trg = cls;
  *trg = MALLOC(ntohl(val->size));
  memcpy(*trg,
	 val,
	 ntohl(val->size));
  return OK;
}

static int load(Blockstore * s,
		char * key,
		char * val) {
  HashCode512 hc;
  DataContainer * cont;

  cont = NULL;
  hash(key,
       strlen(key),
       &hc);
  if (OK != s->get(s->closure,
		   0,
		   0,
		   1,
		   &hc,
		   &resCB,
		   &cont)) {
    if (val == NULL)
      return 0;
    DUMP(s);
    return 1;
  } else if (val == NULL) {
    FREE(cont);
    DUMP(s);
    return 1;
  }
  if ( (val == NULL) &&
       (cont == NULL) )
    return 0;
  if ( (val == NULL) &&
       (cont != NULL) ) {
    DUMP(s);
    FREE(cont);
    return 1;
  }
  if (cont == NULL) {
    DUMP(s);
    return 1;
  }
  if (0 != strncmp(val,
		   (char*) &cont[1],
		   strlen(val))) {
    DUMP(s);
    return 1;
  }
  FREE(cont);
  return 0;
}


static int test(Blockstore * s) {
  GNUNET_ASSERT(0 == store(s, "a", "Hello"));
  GNUNET_ASSERT(0 == store(s, "b", "World"));
  GNUNET_ASSERT(0 == load(s, "a", "Hello"));
  GNUNET_ASSERT(0 == load(s, "b", "World"));
  GNUNET_ASSERT(0 == rem(s, "a", "Hello"));
  GNUNET_ASSERT(0 == rem(s, "b", "World"));
  GNUNET_ASSERT(0 == load(s, "a", NULL));
  GNUNET_ASSERT(0 == load(s, "b", NULL));

  return 0;
}

/**
 * Perform option parsing from the command line.
 */
static int parseCommandLine(int argc,
			    char * argv[]) {
  return OK;
}

int main(int argc,
	 char * argv[]) {
  Blockstore * s;
  int i;

  initUtil(argc, argv, &parseCommandLine);
  s = create_blockstore_memory(65536);
  for (i=0;i<65536;i++)
    if (0 != test(s))
      { DUMP(s); return 1; }
  destroy_blockstore_memory(s);
  doneUtil();

  return 0;
}

/* end of datastore_memory_test.c */
