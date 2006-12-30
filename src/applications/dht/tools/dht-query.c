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
 * @brief perform DHT operations (insert, lookup)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_protocols.h"
#include "gnunet_util.h"
#include "gnunet_util_crypto.h"
#include "gnunet_dht_lib.h"
#include "gnunet_util_boot.h"
#include "gnunet_util_network_client.h"

#define DEBUG_DHT_QUERY NO

/**
 * How long should a "GET" run (or how long should
 * content last on the network).
 */
static cron_t timeout;

static struct GE_Context * ectx;

static struct GC_Configuration * cfg;

static char * cfgFilename = DEFAULT_CLIENT_CONFIG_FILE;

/**
 * All gnunet-dht-query command line options
 */
static struct CommandLineOption gnunetqueryOptions[] = {
  COMMAND_LINE_OPTION_CFG_FILE(&cfgFilename), /* -c */
  COMMAND_LINE_OPTION_HELP(gettext_noop("Query (get KEY, put KEY VALUE) DHT table.")), /* -h */
  COMMAND_LINE_OPTION_HOSTNAME, /* -H */
  COMMAND_LINE_OPTION_LOGGING, /* -L */
  { 'T', "timeout", "TIME",
    gettext_noop("allow TIME ms to process a GET command or expire PUT content after ms TIME"),
    1, &gnunet_getopt_configure_set_ulong, &timeout },
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
	 ntohl(data->size) - sizeof(DataContainer),
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
#if DEBUG_DHT_QUERY
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "Issuing '%s(%s)' command.\n",
	 "get", 
	 key);
#endif
  if (timeout == 0)
    timeout = 30 * cronSECONDS;
  ret = DHT_LIB_get(cfg,
		    ectx,
		    DHT_STRING2STRING_BLOCK,
		    &hc,
		    timeout,
		    &printCallback,
		    (void*) key);
  if (ret == 0)
    printf(_("%s(%s) operation returned no results.\n"),
	   "get",
	   key);
}

static void do_put(struct ClientServerConnection * sock,
		   const char * key,
		   const char * value) {
  DataContainer * dc;
  HashCode512 hc;

  hash(key, strlen(key), &hc);
  dc = MALLOC(sizeof(DataContainer)
	      + strlen(value));
  dc->size = htonl(strlen(value)
		   + sizeof(DataContainer));
  memcpy(&dc[1],
	 value,
	 strlen(value));
#if DEBUG_DHT_QUERY
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 _("Issuing '%s(%s,%s)' command.\n"),
	 "put",
	 key,
	 value);
#endif
  if (timeout == 0)
    timeout = 30 * cronMINUTES;
  if (OK == DHT_LIB_put(cfg,
			ectx,
			&hc,
			DHT_STRING2STRING_BLOCK,
			timeout + get_time(), /* convert to absolute time */
			dc)) {
    printf(_("'%s(%s,%s)' succeeded\n"),
	   "put",
	   key,
	   value);
  } else {
    printf(_("'%s(%s,%s)' failed.\n"),
	   "put",
	   key, 
	   value);
  }	
  FREE(dc);
}

int main(int argc,
	 char * const * argv) {
  int i;
  struct ClientServerConnection * handle;

  i = GNUNET_init(argc,
		  argv,
		  "gnunet-dht-query",
		  &cfgFilename,
		  gnunetqueryOptions,
		  &ectx,
		  &cfg);
  if (i == -1) {
    GNUNET_fini(ectx, cfg);
    return -1;
  }

  handle = client_connection_create(ectx, cfg);
  if (handle == NULL) {
    fprintf(stderr,
	    _("Failed to connect to gnunetd.\n"));
    GC_free(cfg);
    GE_free_context(ectx);
    return 1;
  }

  while (i < argc) {
    if (0 == strcmp("get", argv[i])) {
      if (i+2 > argc) {
	fprintf(stderr,
		_("Command `%s' requires an argument (`%s').\n"),
		"get",
		"key");
	break;
      } else {
	do_get(handle, argv[i+1]);
	i += 2;
      }
      continue;
    }
    if (0 == strcmp("put", argv[i])) {
      if (i+3 > argc) {
	fprintf(stderr,
		_("Command `%s' requires two arguments (`%s' and `%s').\n"),
		"put",
		"key",
		"value");
	break;
      } else {
	do_put(handle, argv[i+1], argv[i+2]);
	i += 3;
      }
      continue;
    }
    fprintf(stderr,
	    _("Unsupported command `%s'.  Aborting.\n"),
	    argv[i]);
    break;
  }
  connection_destroy(handle);
  GNUNET_fini(ectx, cfg);
  return 0;
}

/* end of dht-query.c */
