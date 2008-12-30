INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif
plugindir = $(libdir)/GNUnet

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_sqstore_mysql.la

check_PROGRAMS = \
  mysqltest \
  mysqltest2 \
  mysqltest3

TESTS = $(check_PROGRAMS)

if HAVE_ZLIB
 ZLIB_LNK = -lz
endif

AM_CPPFLAGS = $(CPPFLAGS) $(MYSQL_CPPFLAGS)

libgnunetmodule_sqstore_mysql_la_SOURCES = \
  mysql.c 
libgnunetmodule_sqstore_mysql_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS) \
  $(MYSQL_LDFLAGS)
libgnunetmodule_sqstore_mysql_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/libs/mysql/libgnunetmysql.la \
 $(ZLIB_LNK) \
 $(GN_LIBINTL)

EXTRA_DIST = check.conf

mysqltest_SOURCES = \
 mysqltest.c 
mysqltest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/server/libgnunetcore.la

mysqltest2_SOURCES = \
 mysqltest2.c 
mysqltest2_LDADD = \
 $(top_builddir)/src/server/libgnunetcore.la  \
 $(top_builddir)/src/util/libgnunetutil.la  

mysqltest3_SOURCES = \
 mysqltest3.c 
mysqltest3_LDADD = \
 $(top_builddir)/src/server/libgnunetcore.la  \
 $(top_builddir)/src/util/libgnunetutil.la  
