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
 * @file dht-join.c
 * @brief join table and provide client store
 * @author Christian Grothoff
 *
 * Todo:
 * - test
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_util_boot.h"
#include "gnunet_dht_lib.h"
#include "gnunet_dht_datastore_memory.h"

static unsigned int memory = 64 * 1024;

static char * table_id;

static char * cfgFilename;

static int verbose;

static struct GE_Context * ectx;

/**
 * All gnunet-dht-join command line options
 */
static struct CommandLineOption gnunetjoinOptions[] = {
  COMMAND_LINE_OPTION_CFG_FILE(&cfgFilename), /* -c */
  COMMAND_LINE_OPTION_HELP(gettext_noop("Join a DHT.")), /* -h */
  COMMAND_LINE_OPTION_HOSTNAME, /* -H */
  COMMAND_LINE_OPTION_LOGGING, /* -L */
  { 'm', "memory", "SIZE",
    gettext_noop("allow SIZE bytes of memory for the local table"),
    1, &gnunet_getopt_configure_set_uint, &memory },
  { 't', "table", "NAME",
    gettext_noop("join table called NAME"),
    1, &gnunet_getopt_configure_set_string, &table_id },
  COMMAND_LINE_OPTION_VERSION(PACKAGE_VERSION), /* -v */
  COMMAND_LINE_OPTION_VERBOSE,
  COMMAND_LINE_OPTION_END,
};

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
  Blockstore * cls = closure;
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
  Blockstore * cls = closure;
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
  Blockstore * cls = closure;
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
  Blockstore * cls = closure;
  ret = cls->iterate(cls->closure,
		     processor,
		     parg);
  LOGRET(ret);
  return ret;
}

int main(int argc,
	 const char ** argv) {
  int i;
  HashCode512 table;
  struct GC_Configuration * cfg;
  Blockstore myStore;


  i = GNUNET_init(argc,
		  argv,
		  "gnunet-dht-join",
		  &cfgFilename,
		  gnunetjoinOptions,
		  &ectx,
		  &cfg);
  if (i == -1) {
    GNUNET_fini(ectx, cfg);
    return -1;
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
  myStore.closure = create_blockstore_memory(memory);
  myStore.get = &lookup;
  myStore.put = &store;
  myStore.del = &removeDS;
  myStore.iterate = &iterate;

  if (OK != DHT_LIB_join(&myStore,
			 cfg,
			 ectx,
			 &table)) {
    GE_LOG(ectx,
	   GE_WARNING | GE_BULK | GE_USER,
	   _("Error joining DHT.\n"));
    destroy_blockstore_memory((Blockstore*)myStore.closure);
    GC_free(cfg);
    GE_free_context(ectx);
    return 1;
  }

  printf(_("Joined DHT.  Press CTRL-C to leave.\n"));
  GNUNET_SHUTDOWN_WAITFOR();

  i = OK;
  /* shutdown */
  if (OK != DHT_LIB_leave(&table)) {
    i = SYSERR;
    GE_LOG(ectx,
	   GE_WARNING | GE_BULK | GE_USER,
	   _("Error leaving DHT.\n"));
  }

  destroy_blockstore_memory((Blockstore*)myStore.closure);
  GC_free(cfg);
  GE_free_context(ectx);
  if (i != OK)
    return 1;
  return 0;
}

/* end of dht-join.c */
