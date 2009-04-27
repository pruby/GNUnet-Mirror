INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_dhtlog_mysql.la

check_PROGRAMS = \
  dhtlog_test

TESTS = $(check_PROGRAMS)

if HAVE_ZLIB
 ZLIB_LNK = -lz
endif

AM_CPPFLAGS = $(CPPFLAGS) $(MYSQL_CPPFLAGS)

libgnunetmodule_dhtlog_mysql_la_SOURCES = \
  dhtlog_mysql.c 
libgnunetmodule_dhtlog_mysql_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS) \
  $(MYSQL_LDFLAGS)
libgnunetmodule_dhtlog_mysql_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/libs/mysql/libgnunetmysql.la \
 -lmysqlclient $(ZLIB_LNK) \
 $(GN_LIBINTL)

EXTRA_DIST = check.conf

dhtlog_test_SOURCES = \
 dhtlog_test.c 
dhtlog_test_LDADD = \
 $(top_builddir)/src/server/libgnunetcore.la  \
 $(top_builddir)/src/util/libgnunetutil.la  
