INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_dht.la 

lib_LTLIBRARIES = \
  libgnunetdht_datastore_memory.la 

libgnunetmodule_dht_la_SOURCES = \
  dht.c \
  datastore_dht_master.c \
  datastore_dht_master.h \
  cs.c 
libgnunetmodule_dht_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/applications/rpc/libgnunetmodule_rpc_util.la
libgnunetmodule_dht_la_LDFLAGS = \
  -export-dynamic -avoid-version -module

libgnunetdht_datastore_memory_la_SOURCES = \
  datastore_memory.c 
libgnunetdht_datastore_memory_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la 
libgnunetdht_datastore_memory_la_LDFLAGS = \
  -export-dynamic 


check_PROGRAMS = \
  datastore_memory_test


TESTS = $(check_PROGRAMS)

datastore_memory_test_SOURCES = \
  datastore_memory_test.c
datastore_memory_test_LDADD = \
  $(top_builddir)/src/applications/dht/module/libgnunetdht_datastore_memory.la \
  $(top_builddir)/src/util/libgnunetutil.la 


