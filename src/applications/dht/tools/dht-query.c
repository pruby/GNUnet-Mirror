/*
      This file is part of GNUnet
      (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
#include "gnunet_util_config_impl.h"
#include "gnunet_util_error_loggers.h"
#include "gnunet_dht_datastore_memory.h"

static DHT_TableId table;

static char * table_id;

static unsigned int timeout;

static struct GE_Context * ectx;

static char * cfgFilename;

/**
 * All gnunet-dht-query command line options
 */
static struct CommandLineOption gnunetjoinOptions[] = {
  COMMAND_LINE_OPTION_CFG_FILE(&cfgFilename), /* -c */
  COMMAND_LINE_OPTION_HELP(gettext_noop("Query (get KEY, put KEY VALUE, remove KEY VALUE) a DHT table.")), /* -h */
  COMMAND_LINE_OPTION_HOSTNAME, /* -H */
  COMMAND_LINE_OPTION_LOGGING, /* -L */  
  { 't', "table", "NAME",
    gettext_noop("join table called NAME"),
    1, &gnunet_getopt_configure_set_string, &table_id },  
  { 'T', "timeout", "TIME",
    gettext_noop("allow TIME ms to process each command"),
    1, &gnunet_getopt_configure_set_uint, &timeout }, 
  COMMAND_LINE_OPTION_VERSION(PACKAGE_VERSION), /* -v */
  COMMAND_LINE_OPTION_VERBOSE,
  COMMAND_LINE_OPTION_END,
};

static int printCallback(const HashCode512 * hash,
			 const DataContainer * data,
			 void * cls) {
  char * key = cls;
  printf("%s(%s): '%.*s'\n",
	 "get",
	 key,
	 ntohl(data->size),
	 (char*)&data[1]);
  return OK;
}

static void do_get(struct ClientServerConnection * sock,
		   const char * key) {
  int ret;
  HashCode512 hc;

  hash(key,
       strlen(key),
       &hc);
  GE_LOG(ectx, 
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "Issuing '%s(%s)' command.\n",
	 "get", key);
  ret = DHT_LIB_get(&table,
		    DHT_STRING2STRING_BLOCK,
		    1, /* prio */
		    1, /* key count */
		    &hc,
		    getConfigurationInt("DHT-QUERY",
					"TIMEOUT"),
		    &printCallback,
		    (void*) key);
  if (ret == 0)
    printf("%s(%s) operation returned no results.\n",
	   "get",
	   key);
}

static void do_put(struct ClientServerConnection * sock,
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
  GE_LOG(ectx, GE_DEBUG | GE_REQUEST | GE_USER,
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

static void do_remove(struct ClientServerConnection * sock,
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
  GE_LOG(ectx, GE_DEBUG | GE_REQUEST | GE_USER,
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
  int count;
  char ** commands;
  int i;
  struct ClientServerConnection * handle;
  HashCode512 table;
  struct GC_Configuration * cfg;

  ectx = GE_create_context_stderr(NO, 
				  GE_WARNING | GE_ERROR | GE_FATAL |
				  GE_USER | GE_ADMIN | GE_DEVELOPER |
				  GE_IMMEDIATE | GE_BULK);
  GE_setDefaultContext(ectx);
  os_init(ectx);
  cfg = GC_create_C_impl();
  GE_ASSERT(ectx, cfg != NULL);
  i = gnunet_parse_options("gnunet-insert [OPTIONS] FILENAME",
			   ectx,
			   cfg,
			   gnunetjoinOptions,
			   (unsigned int) argc,
			   argv);
  if (i == SYSERR) {
    GC_free(cfg);
    GE_free_context(ectx);
    return 1;
  }
  if (table_id == NULL) {
    printf(_("No table name specified, using `%s'.\n"),
	   "test");
    table_id = STRDUP("test");
  }
  if (OK != enc2hash(table_id,
		     &table)) {
    hash(table_id,
	 strlen(table_id),
	 &table);
  }
  FREE(table_id);
  table_id = NULL;

  count = getConfigurationStringList(&commands);
  handle = getClientSocket();
  if (handle == NULL) {
    fprintf(stderr,
	    _("Failed to connect to gnunetd.\n"));
    GC_free(cfg);
    GE_free_context(ectx);
    return 1;
  }

  for (i=0;i<count;i++) {
    if (0 == strcmp("get", commands[i])) {
      if (i+2 > count) {
	fprintf(stderr,
		_("Command `%s' requires an argument (`%s').\n"),
		"get",
		"key");
	break;
      } else {
	do_get(handle, commands[++i]);
      }
      continue;
    }
    if (0 == strcmp("put", commands[i])) {
      if (i+3 > count) {
	fprintf(stderr,
		_("Command `%s' requires two arguments (`%s' and `%s').\n"),
		"put",
		"key",
		"value");
	break;
      } else {
	do_put(handle, commands[i+1], commands[i+2]);
	i+=2;
      }
      continue;
    }
    if (0 == strcmp("remove", commands[i])) {
      if (i+3 > count) {
	fprintf(stderr,
		_("Command `%s' requires two arguments (`%s' and `%s').\n"),
		"remove",
		"key",
		"value");
	break;
      } else {
	do_remove(handle, commands[i+1], commands[i+2]);
	i+=2;
      }
      continue;
    }
    fprintf(stderr,
	    _("Unsupported command `%s'.  Aborting.\n"),
	    commands[i]);
    break;
  }
  connection_destroy(handle);
  for (i=0;i<count;i++)
    FREE(commands[i]);
  FREE(commands);
  GC_free(cfg);
  GE_free_context(ectx);
  return 0;
}

/* end of dht-query.c */
