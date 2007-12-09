INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_dstore_mysql.la

check_PROGRAMS = \
  dstore_test

TESTS = $(check_PROGRAMS)

if HAVE_ZLIB
 ZLIB_LNK = -lz
endif

AM_CPPFLAGS = $(CPPFLAGS) $(MYSQL_CPPFLAGS)

libgnunetmodule_dstore_mysql_la_SOURCES = \
  dstore_mysql.c 
libgnunetmodule_dstore_mysql_la_LDFLAGS = \
  -export-dynamic -avoid-version -module \
  $(MYSQL_LDFLAGS)
libgnunetmodule_dstore_mysql_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 -lmysqlclient $(ZLIB_LNK)

EXTRA_DIST = check.conf

dstore_test_SOURCES = \
 dstore_test.c 
dstore_test_LDADD = \
 $(top_builddir)/src/server/libgnunetcore.la  \
 $(top_builddir)/src/util/libgnunetutil.la  
