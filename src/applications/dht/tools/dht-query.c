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
 * @file dht-query.c
 * @brief perform DHT operations (insert, lookup, remove)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_util.h"
#include "gnunet_dht_lib.h"

static DHT_TableId table;

static void printHelp() {
  static Help help[] = {
    HELP_CONFIG,
    HELP_HELP,
    HELP_LOGLEVEL,
    { 't', "table", "NAME",
      gettext_noop("query table called NAME") },
    { 'T', "timeout", "TIME",
      gettext_noop("allow TIME ms to process each command") },
    HELP_VERSION,
    HELP_END,
  };
  formatHelp("dht-query [OPTIONS] COMMANDS",
	     _("Query (get KEY, put KEY VALUE, remove KEY VALUE) a DHT table."),
	     help);
}

static int parseOptions(int argc,
			char ** argv) {
  int c;

  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "table", 1, 0, 't' },
      { "timeout", 1, 0, 'T' },
      { 0,0,0,0 }
    };
    c = GNgetopt_long(argc,
		      argv,
		      "vhH:c:L:dt:T:",
		      long_options,
		      &option_index);
    if (c == -1)
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'h':
      printHelp();
      return SYSERR;
    case 't':
      FREENONNULL(setConfigurationString("DHT-QUERY",
					 "TABLE",
					 GNoptarg));
      break;
     case 'T': {
      unsigned int max;
      if (1 != sscanf(GNoptarg, "%ud", &max)) {
	LOG(LOG_FAILURE,
	    _("You must pass a number to the `%s' option.\n"),
	    "-T");
	return SYSERR;
      } else {	
	setConfigurationInt("DHT-QUERY",
			    "TIMEOUT",
			    max);
      }
      break;
    }
    case 'v':
      printf("dht-query v0.0.1\n");
      return SYSERR;
    default:
      LOG(LOG_FAILURE,
	  _("Use --help to get a list of options.\n"),
	  c);
      return SYSERR;
    } /* end of parsing commandline */
  } /* while (1) */
  if (argc - GNoptind == 0) {
    LOG(LOG_WARNING,
	_("No commands specified.\n"));
    printHelp();
    return SYSERR;
  }
  setConfigurationStringList(&argv[GNoptind],
			     argc - GNoptind);
  return OK;
}

static int printCallback(const HashCode512 * hash,
			 const DataContainer * data,
			 char * key) {
  printf("%s(%s): '%.*s'\n",
	 "get",
	 key,
	 ntohl(data->size),
	 (char*)&data[1]);
  return OK;
}

static void do_get(GNUNET_TCP_SOCKET * sock,
		   const char * key) {
  int ret;
  HashCode512 hc;

  hash(key,
       strlen(key),
       &hc);
  LOG(LOG_DEBUG,
      "Issuing '%s(%s)' command.\n",
      "get", key);
  ret = DHT_LIB_get(&table,
		    DHT_STRING2STRING_BLOCK,
		    1, /* prio */
		    1, /* key count */
		    &hc,
		    getConfigurationInt("DHT-QUERY",
					"TIMEOUT"),
		    (DataProcessor) &printCallback,
		    (void*) key);
  if (ret == 0)
    printf("%s(%s) operation returned no results.\n",
	   "get",
	   key);
}

static void do_put(GNUNET_TCP_SOCKET * sock,
		   const char * key,
		   char * value) {
  DataContainer * dc;
  HashCode512 hc;

  hash(key, strlen(key), &hc);
  dc = MALLOC(sizeof(DataContainer)
	      + strlen(value));
  dc->size = htonl(strlen(value)
		   + sizeof(DataContainer));
  memcpy(&dc[1], value, strlen(value));
  LOG(LOG_DEBUG,
      "Issuing '%s(%s,%s)' command.\n",
      "put", key, value);
  if (OK == DHT_LIB_put(&table,		
			&hc,
			1, /* prio */
			getConfigurationInt("DHT-QUERY",
					    "TIMEOUT"),
			dc)) {
    printf(_("'%s(%s,%s)' succeeded\n"),
	   "put",
	   key, value);
  } else {
    printf(_("'%s(%s,%s)' failed.\n"),
	   "put",
	   key, value);
  }	
  FREE(dc);
}

static void do_remove(GNUNET_TCP_SOCKET * sock,
		      const char * key,
		      char * value) {
  DataContainer * dc;
  HashCode512 hc;

  hash(key, strlen(key), &hc);
  dc = MALLOC(sizeof(DataContainer)
	      + strlen(value));
  dc->size = htonl(strlen(value)
		   + sizeof(DataContainer));
  memcpy(&dc[1], value, strlen(value));
  LOG(LOG_DEBUG,
      "Issuing '%s(%s,%s)' command.\n",
      "remove", key, value);
  if (OK == DHT_LIB_remove(&table,
			   &hc,
			   getConfigurationInt("DHT-QUERY",
					       "TIMEOUT"),
			   dc)) {
    printf(_("'%s(%s,%s)' succeeded\n"),
	   "remove",
	   key, value);
  } else {
    printf(_("'%s(%s,%s)' failed.\n"),
	   "remove",
	   key, value);
  }	
  FREE(dc);
}


int main(int argc,
	 char **argv) {
  char * tableName;
  int count;
  char ** commands;
  int i;
  GNUNET_TCP_SOCKET * handle;

  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return 0;

  count = getConfigurationStringList(&commands);
  tableName = getConfigurationString("DHT-QUERY",
				     "TABLE");
  if (tableName == NULL) {
    printf(_("No table name specified, using `%s'.\n"),
	   "test");
    tableName = STRDUP("test");
  }
  if (OK != enc2hash(tableName,
		     &table)) {
    hash(tableName,
	 strlen(tableName),
	 &table);
  }
  FREE(tableName);
  DHT_LIB_init();
  handle = getClientSocket();
  if (handle == NULL) {
    fprintf(stderr,
	    _("Failed to connect to gnunetd.\n"));
    return 1;
  }

  for (i=0;i<count;i++) {
    if (0 == strcmp("get", commands[i])) {
      if (i+2 > count)
	errexit(_("Command `%s' requires an argument (`%s').\n"),
		"get",
		"key");
      do_get(handle, commands[++i]);
      continue;
    }
    if (0 == strcmp("put", commands[i])) {
      if (i+3 > count)
	errexit(_("Command `%s' requires two arguments (`%s' and `%s').\n"),
		"put",
		"key",
		"value");
      do_put(handle, commands[i+1], commands[i+2]);
      i+=2;
      continue;
    }
    if (0 == strcmp("remove", commands[i])) {
      if (i+3 > count)
	errexit(_("Command `%s' requires two arguments (`%s' and `%s').\n"),
		"remove",
		"key",
		"value");
      do_remove(handle, commands[i+1], commands[i+2]);
      i+=2;
      continue;
    }
    printf(_("Unsupported command `%s'.  Aborting.\n"),
	   commands[i]);
    break;
  }
  releaseClientSocket(handle);
  for (i=0;i<count;i++)
    FREE(commands[i]);
  FREE(commands);
  DHT_LIB_done();
  return 0;
}

/* end of dht-query.c */
