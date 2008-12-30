SUBDIRS = .
INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

AM_CPPFLAGS = $(CPPFLAGS) $(MYSQL_CPPFLAGS)

if HAVE_ZLIB
 ZLIB_LNK = -lz
endif

lib_LTLIBRARIES = \
  libgnunetmysql.la

libgnunetmysql_la_SOURCES = \
  lmysql.c 
libgnunetmysql_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(MYSQL_LDFLAGS)
libgnunetmysql_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lmysqlclient $(ZLIB_LNK) \
  $(GN_LIBINTL)

