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
 * @file dht-join.c
 * @brief join table and provide client store
 * @author Christian Grothoff
 *
 * Todo:
 * - test
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_dht_lib.h"
#include "gnunet_dht_datastore_memory.h"

static int verbose;

static void printHelp() {
  static Help help[] = {
    HELP_CONFIG,
    HELP_HELP,
    HELP_LOGLEVEL,
    { 'm', "memory", "SIZE",
      gettext_noop("allow SIZE bytes of memory for the local table") },
    { 't', "table", "NAME",
      gettext_noop("join table called NAME") },
    HELP_VERSION,
    HELP_VERBOSE,
    HELP_END,
  };
  formatHelp("dht-join [OPTIONS]",
	     _("Join a DHT."),
	     help);
}

static int parseOptions(int argc,
			char ** argv) {
  int c;

  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "memory", 1, 0, 'm' },
      { "table", 1, 0, 't' },
      { "verbose", 0, 0, 'V' },
      { 0,0,0,0 }
    };
    c = GNgetopt_long(argc,
		      argv,
		      "vhH:c:L:dt:m:T:V",
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
    case 'm': {
      unsigned int max;
      if (1 != sscanf(GNoptarg, "%ud", &max)) {
	LOG(LOG_FAILURE,
	    _("You must pass a number to the `%s' option.\n"),
	    "-m");
	return SYSERR;
      } else {	
	setConfigurationInt("DHT-JOIN",
			    "MEMORY",
			    max);
      }
      break;
    }
    case 't':
      FREENONNULL(setConfigurationString("DHT-JOIN",
					 "TABLE",
					 GNoptarg));
      break;
    case 'v':
      printf("dht-join v0.0.0\n");
      return SYSERR;
    case 'V':
      verbose++;
      break;
    default:
      LOG(LOG_FAILURE,
	  _("Use --help to get a list of options.\n"),
	  c);
      return SYSERR;
    } /* end of parsing commandline */
  } /* while (1) */
  if (argc - GNoptind != 0)
    LOG(LOG_WARNING,
	_("Superflous arguments (ignored).\n"));
  return OK;
}

static void dump(const char * fmt,
		    ...) {
  va_list ap;
  if (verbose > 0) {
    va_start(ap, fmt);
    vfprintf(stdout,
	     fmt,
	     ap);
    va_end(ap);
  }
}

#define LOGRET(ret) dump(_("Call to `%s' returns %d.\n"), __FUNCTION__, ret)
#define LOGKEY(key) do { EncName kn; hash2enc(key, &kn); dump(_("Call to `%s' with key `%s'.\n"), __FUNCTION__, &kn); } while (0)
#define LOGVAL(val) dump(_("Call to `%s' with value '%.*s' (%d bytes).\n"), __FUNCTION__, (val == NULL) ? 0 : &val[1], (val == NULL) ? NULL : &val[1], (val == NULL) ? 0 : (ntohl(val->size) - sizeof(DataContainer)))

static int lookup(void * closure,
		  unsigned int type,
		  unsigned int prio,
		  unsigned int keyCount,
		  const HashCode512 * keys,
		  DataProcessor processor,
		  void * pclosure) {
  int ret;
  Blockstore * cls = (Blockstore*) closure;
  LOGKEY(&keys[0]);
  ret = cls->get(cls->closure,
		 type,
		 prio,
		 keyCount,
		 keys,
		 processor,
		 pclosure);
  LOGRET(ret);
  return ret;
}

static int store(void * closure,
		 const HashCode512 * key,
		 const DataContainer * value,
		 unsigned int prio) {
  int ret;
  Blockstore * cls = (Blockstore*) closure;
  LOGKEY(key);
  LOGVAL(value);
  ret = cls->put(cls->closure,
		 key,
		 value,
		 prio);
  LOGRET(ret);
  return ret;
}

static int removeDS(void * closure,
		    const HashCode512 * key,
		    const DataContainer * value) {
  int ret;
  Blockstore * cls = (Blockstore*) closure;
  LOGKEY(key);
  LOGVAL(value);
  ret = cls->del(cls->closure,
		 key,
		 value);
  LOGRET(ret);
  return ret;
}

static int iterate(void * closure,
		   DataProcessor processor,
		   void * parg) {
  int ret;
  Blockstore * cls = (Blockstore*) closure;
  ret = cls->iterate(cls->closure,
		     processor,
		     parg);
  LOGRET(ret);
  return ret;
}

int main(int argc,
	 char **argv) {
  char * tableName;
  unsigned int mem;
  HashCode512 table;
  Blockstore myStore;

  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return 0;

  tableName = getConfigurationString("DHT-JOIN",
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
  mem = getConfigurationInt("DHT-JOIN",
			    "MEMORY");
  if (mem == 0) mem = 65536; /* default: use 64k */
  myStore.closure = create_blockstore_memory(mem);
  myStore.get = &lookup;
  myStore.put = &store;
  myStore.del = &removeDS;
  myStore.iterate = &iterate;

  DHT_LIB_init();
  initializeShutdownHandlers();
  if (OK != DHT_LIB_join(&myStore,
			 &table)) {
    LOG(LOG_WARNING,
	_("Error joining DHT.\n"));
    destroy_blockstore_memory((Blockstore*)myStore.closure);
    doneShutdownHandlers();
    DHT_LIB_done();
    return 1;
  }

  printf(_("Joined DHT.  Press CTRL-C to leave.\n"));
  /* wait for CTRL-C */
  wait_for_shutdown();

  /* shutdown */
  if (OK != DHT_LIB_leave(&table)) {
    LOG(LOG_WARNING,
	_("Error leaving DHT.\n"));
    destroy_blockstore_memory((Blockstore*)myStore.closure);
    doneShutdownHandlers();
    DHT_LIB_done();
    return 1;
  } else {
    destroy_blockstore_memory((Blockstore*)myStore.closure);
    doneShutdownHandlers();
    DHT_LIB_done();
    return 0;
  }
}

/* end of dht-join.c */
