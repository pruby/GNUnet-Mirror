INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = \
  libgnunetecrs.la 

libgnunetecrs_la_SOURCES = \
  directory.c \
  download.c \
  ecrs.c ecrs.h \
  keyspace.c \
  meta.c \
  namespace.c \
  search.c \
  tree.c tree.h \
  unindex.c \
  upload.c \
  uri.c uri.h
libgnunetecrs_la_LIBADD = \
 -lz \
 -lextractor \
 $(top_builddir)/src/applications/fs/libecrs_core.la \
 $(top_builddir)/src/applications/fs/lib/libgnunetfs.la \
 $(top_builddir)/src/applications/getoption/libgnunetgetoption_api.la \
 $(top_builddir)/src/util/libgnunetutil.la 


check_PROGRAMS = \
  metatest \
  uritest 

TESTS = $(check_PROGRAMS)

uritest_SOURCES = \
  uritest.c 
uritest_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la 


metatest_SOURCES = \
  metatest.c 
metatest_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la 

