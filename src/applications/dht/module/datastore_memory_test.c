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
 * @file applications/dht/module/datastore_memory_test.h
 * @brief testcase for the Datastore API (memory).
 * @author Christian Grothoff
 *
 * TODO: test out-of-memory condition, iterator, options
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_dht_datastore_memory.h"
#include "gnunet_dht_service.h"

#define DUMP(v) fprintf(stderr, "At %d: \n", __LINE__); 

static int store(DHT_Datastore * s,
		 char * key,
		 char * val,
		 int flags) {
  HashCode160 hc;
  DHT_DataContainer cont;

  cont.dataLength = strlen(val);
  cont.data = val;
  hash(key,
       strlen(key),
       &hc);
  if (OK != s->store(s->closure,
		     &hc,
		     &cont,
		     flags))
    { DUMP(s); return 1; }
  return 0;
}

static int rem(DHT_Datastore * s,
	       char * key,
	       char * val,
	       int flags) {
  HashCode160 hc;
  DHT_DataContainer cont;

  if (val == NULL)
    cont.dataLength = 0;
  else
    cont.dataLength = strlen(val);
  cont.data = val;
  hash(key,
       strlen(key),
       &hc);
  if (OK != s->remove(s->closure,
		      &hc,
		      &cont,
		      flags))
    { DUMP(s); return 1; }
  return 0;
}

static int load(DHT_Datastore * s,
		char * key,
		char * val,
		int flags) {
  HashCode160 hc;
  DHT_DataContainer cont;

  cont.dataLength = 0;
  cont.data = NULL;
  hash(key,
       strlen(key),
       &hc);
  if (OK != s->lookup(s->closure,
		      &hc,
		      1,
		      &cont,
		      flags))
    { DUMP(s); return 1; }
  if (0 != strncmp(val,
		   (char*)cont.data,
		   strlen(val)))
    return 1;
  FREENONNULL(cont.data);
  return 0;
}


static int test(DHT_Datastore * s) {
  DHT_DataContainer containers[4];
  char data[24];
  int i;
  HashCode160 key1;
  HashCode160 key2;

  for (i=0;i<24;i++)
    data[i] = i;
  key1.a = 4;
  key2.a = 5;
  containers[0].dataLength = 24;
  containers[0].data = &data[0];
  if (OK != s->store(s->closure,
		     &key1,
		     &containers[0],
		     DHT_FLAGS__APPEND))
    { DUMP(s); return 1; }
  containers[1].dataLength = 0;
  containers[1].data = NULL;
  if (0 != s->lookup(s->closure,
		     &key2, 3,
		     &containers[1],
		     DHT_FLAGS__APPEND))
    { DUMP(s); return 1; }  
  if (1 != s->lookup(s->closure,
		     &key1, 3,
		     &containers[1],
		     DHT_FLAGS__APPEND))
    { DUMP(s); return 1; }
  if ( (containers[1].dataLength != containers[0].dataLength) ||
       (0 != memcmp(containers[1].data,
		    containers[0].data,
		    containers[1].dataLength)) )
    { DUMP(s); return 1; }
  FREE(containers[1].data);
  containers[1].dataLength = 0;
  containers[1].data = NULL;
  if (OK != s->remove(s->closure,
		      &key1,
		      NULL,
		      DHT_FLAGS__APPEND))
    { DUMP(s); return 1; }
  if (0 != s->lookup(s->closure,
		     &key1, 3,
		     &containers[1],
		     DHT_FLAGS__APPEND))
    { DUMP(s); return 1; }  


  GNUNET_ASSERT(0 == store(s, "a", "Hello", 0));
  GNUNET_ASSERT(0 == store(s, "b", "World", 0));
  GNUNET_ASSERT(0 == load(s, "a", "Hello", 0));
  GNUNET_ASSERT(0 == load(s, "b", "World", 0));
  GNUNET_ASSERT(0 == rem(s, "a", "Hello", 0));
  GNUNET_ASSERT(0 == rem(s, "b", "World", 0));


  return 0;
}

int main(int args,
	 char * argv[]) {
  DHT_Datastore * s;
  int i;
  
  s = create_datastore_memory(65536);
  for (i=0;i<65536;i++)
    if (0 != test(s))
      { DUMP(s); return 1; }
  destroy_datastore_memory(s);

  return 0;
}

/* end of datastore_memory_test.c */
