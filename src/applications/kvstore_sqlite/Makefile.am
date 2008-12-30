INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif
plugindir = $(libdir)/GNUnet

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_kvstore_sqlite.la

check_PROGRAMS = \
  kv_sqlitetest

TESTS = $(check_PROGRAMS)

AM_CPPFLAGS = $(CPPFLAGS) $(SQLITE_CPPFLAGS)

libgnunetmodule_kvstore_sqlite_la_SOURCES = \
  kv_sqlite.c 
libgnunetmodule_kvstore_sqlite_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS) \
  $(SQLITE_LDFLAGS)
libgnunetmodule_kvstore_sqlite_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lsqlite3 \
  $(GN_LIBINTL)

EXTRA_DIST = check.conf

kv_sqlitetest_SOURCES = \
 kv_sqlitetest.c 
kv_sqlitetest_LDADD = \
 $(top_builddir)/src/server/libgnunetcore.la  \
 $(top_builddir)/src/util/libgnunetutil.la  
