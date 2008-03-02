INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_dstore_sqlite.la

check_PROGRAMS = \
  dstore_test \
  dstore_quota_test

TESTS = $(check_PROGRAMS)

AM_CPPFLAGS = $(CPPFLAGS) $(SQLITE_CPPFLAGS)

libgnunetmodule_dstore_sqlite_la_SOURCES = \
  dstore.c 
libgnunetmodule_dstore_sqlite_la_LDFLAGS = \
  -export-dynamic -avoid-version -module \
  $(SQLITE_LDFLAGS)
libgnunetmodule_dstore_sqlite_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 -lsqlite3

EXTRA_DIST = check.conf

dstore_test_SOURCES = \
 dstore_test.c 
dstore_test_LDADD = \
 $(top_builddir)/src/server/libgnunetcore.la  \
 $(top_builddir)/src/util/libgnunetutil.la  

dstore_quota_test_SOURCES = \
 dstore_quota_test.c 
dstore_quota_test_LDADD = \
 $(top_builddir)/src/server/libgnunetcore.la  \
 $(top_builddir)/src/util/libgnunetutil.la  
