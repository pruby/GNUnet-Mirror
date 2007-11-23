INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = \
  libgnunetecrs.la 

libgnunetecrs_la_SOURCES = \
  directory.c \
  download.c \
  ecrs.c ecrs.h \
  helper.c \
  indexinfo.c \
  keyspace.c \
  meta.c \
  namespace.c \
  parser.c \
  search.c \
  tree.c tree.h \
  unindex.c \
  upload.c \
  uri.c uri.h
libgnunetecrs_la_LIBADD = \
 -lz \
 -lextractor \
 $(top_builddir)/src/applications/identity/libgnunetidentity_api.la \
 $(top_builddir)/src/applications/fs/libecrs_core.la \
 $(top_builddir)/src/applications/fs/lib/libgnunetfs.la \
 $(top_builddir)/src/applications/getoption/libgnunetgetoption_api.la \
 $(top_builddir)/src/util/libgnunetutil.la 


check_PROGRAMS = \
  bincodertest \
  downloadtest \
  namespacetest \
  uritest \
  metatest \
  metatest2 \
  searchtest \
  directorytest \
  ecrstest 

TESTS = $(check_PROGRAMS)

bincodertest_SOURCES = \
  bincodertest.c 
bincodertest_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la 

uritest_SOURCES = \
  uritest.c 
uritest_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la 

namespacetest_SOURCES = \
  namespacetest.c 
namespacetest_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la 

metatest_SOURCES = \
  metatest.c 
metatest_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la 

metatest2_SOURCES = \
  metatest2.c 
metatest2_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la 


ecrstest_SOURCES = \
  ecrstest.c
ecrstest_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la 

downloadtest_SOURCES = \
  downloadtest.c
downloadtest_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la 

searchtest_SOURCES = \
  searchtest.c
searchtest_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la 

directorytest_SOURCES = \
  directorytest.c
directorytest_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la 

EXTRA_DIST = \
  check.conf peer.conf bincoder.c
