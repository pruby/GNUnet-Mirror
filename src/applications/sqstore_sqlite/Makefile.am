INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_sqstore_sqlite.la

check_PROGRAMS = \
  sqlitetest

TESTS = $(check_PROGRAMS)


libgnunetmodule_sqstore_sqlite_la_SOURCES = \
  sqlite.c 
libgnunetmodule_sqstore_sqlite_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
libgnunetmodule_sqstore_sqlite_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 -lsqlite3


sqlitetest_SOURCES = \
 sqlitetest.c 
sqlitetest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  
