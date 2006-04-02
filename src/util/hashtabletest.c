/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/hashtabletest.c
 * @brief testcase for util/hashtable.c
 * @author Nils Durner
 */

#include "gnunet_util.h"
#include "platform.h"

static int testHT()
{
  struct HashTable *ht = ht_create(10);
  void *val;
  unsigned int vallen;
  
  if (HT_PUT(ht, "Sweden", "Stockholm") != YES ||
    HT_PUT(ht, "Germany", "Berlin") != YES ||
    HT_PUT(ht, "France", "Paris") != YES ||
    HT_PUT(ht, "Spain", "Madrid") != YES ||
    HT_PUT(ht, "Italy", "Rome") != YES ||
    HT_PUT(ht, "USA", "Washington") != YES)
  {
    puts("ht_put failed\n");
    return 1;
  }
  
  if (HT_CONTAINS_KEY(ht, "France") != YES ||
    HT_CONTAINS_KEY(ht, "Iceland") != NO)
  {
    puts("ht_contains_key failed!\n");
    return 1;
  }
  
  if (HT_CONTAINS_VALUE(ht, "Paris") != YES ||
    HT_CONTAINS_VALUE(ht, "London") != NO)
  {
    puts("ht_contains_value failed!\n");
    return 1;
  }
  
  if (HT_GET(ht, "USA", &val, &vallen) != YES)
  {
    puts("ht_get failed!\n");
    return 1;
  }
  
  if (strcmp((char *) val, "Washington") != 0)
  {
    puts("ht_get result invalid!\n");
    return 1;
  }
  
  HT_REMOVE(ht, "Spain");
  if (HT_CONTAINS_KEY(ht, "Spain") != NO)
  {
    puts("ht_remove failed!\n");
    return 1;    
  }
  
  if (ht_size(ht) != 5)
  {
    puts("ht_size failed!\n");
    return 1;    
  }
  
  ht_removeAll(ht);
  if (ht_size(ht) != 0)
  {
    puts("ht_size#2 failed!\n");
    return 1;    
  }
  
  ht_destroy(ht);
  
  return 0;
}


/**
 * Perform option parsing from the command line.
 */
static int parseCommandLine(int argc,
			    char * argv[]) {
  char c;

  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      { "loglevel",1, 0, 'L' },
      { "config",  1, 0, 'c' },
      { 0,0,0,0 }
    };

    c = GNgetopt_long(argc,
		      argv,
		      "c:L:",
		      long_options,
		      &option_index);

    if (c == -1)
      break;  /* No more flags to process */

    switch(c) {
    case 'L':
      FREENONNULL(setConfigurationString("GNUNET",
					 "LOGLEVEL",
					 GNoptarg));
      break;
    case 'c':
      FREENONNULL(setConfigurationString("FILES",
					 "gnunet.conf",
					 GNoptarg));
      break;
    } /* end of parsing commandline */
  }
  return OK;
}

int main(int argc, char * argv[]){
  int ret = 0;

  initUtil(argc, argv, &parseCommandLine);
  ret = testHT();
  doneUtil();

  return ret;
}
