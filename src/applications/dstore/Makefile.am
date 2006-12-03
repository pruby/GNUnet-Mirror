INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_dstore.la

check_PROGRAMS = \
  dstore_test

TESTS = $(check_PROGRAMS)

AM_CPPFLAGS = $(CPPFLAGS) $(SQLITE_CPPFLAGS)

libgnunetmodule_dstore_la_SOURCES = \
  dstore.c 
libgnunetmodule_dstore_la_LDFLAGS = \
  -export-dynamic -avoid-version -module \
  $(SQLITE_LDFLAGS)
libgnunetmodule_dstore_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 -lsqlite3

EXTRA_DIST = check.conf

dstore_test_SOURCES = \
 dstore_test.c 
dstore_test_LDADD = \
 $(top_builddir)/src/server/libgnunetcore.la  \
 $(top_builddir)/src/util/config_impl/libgnunetutil_config.la  \
 $(top_builddir)/src/util/libgnunetutil.la  
