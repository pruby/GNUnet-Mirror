SUBDIRS = .
INCLUDES = -I$(top_srcdir)/src/include

if HAVE_ZLIB
 ZLIB_LNK = -lz
endif

lib_LTLIBRARIES = \
  libgnunetmysql.la

libgnunetmysql_la_SOURCES = \
  lmysql.c 
libgnunetmysql_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lmysqlclient $(ZLIB_LNK)

