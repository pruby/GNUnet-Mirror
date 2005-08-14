INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_sqstore_sqlite.la

check_PROGRAMS = \
  sqlitetest

TESTS = $(check_PROGRAMS)

AM_CPPFLAGS = $(CPPFLAGS) $(SQLITE_CPPFLAGS)

libgnunetmodule_sqstore_sqlite_la_SOURCES = \
  sqlite.c 
libgnunetmodule_sqstore_sqlite_la_LDFLAGS = \
  -export-dynamic -avoid-version -module \
  $(SQLITE_LDFLAGS)
libgnunetmodule_sqstore_sqlite_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 -lsqlite3

EXTRA_DIST = check.conf

sqlitetest_SOURCES = \
 sqlitetest.c 
sqlitetest_LDADD = \
 $(top_builddir)/src/server/libgnunetcore.la  \
 $(top_builddir)/src/util/libgnunetutil.la  
