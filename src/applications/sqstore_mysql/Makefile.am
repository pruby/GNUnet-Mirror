INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_sqstore_mysql.la

check_PROGRAMS = \
  mysqltest

TESTS = $(check_PROGRAMS)


libgnunetmodule_sqstore_mysql_la_SOURCES = \
  mysql.c 
libgnunetmodule_sqstore_mysql_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
libgnunetmodule_sqstore_mysql_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 -lmysqlclient -lz


mysqltest_SOURCES = \
 mysqltest.c 
mysqltest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/server/libgnunetcore.la