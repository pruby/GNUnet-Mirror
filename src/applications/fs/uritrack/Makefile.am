INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = \
  libgnuneturitrack.la 

libgnuneturitrack_la_SOURCES = \
  file_info.c \
  uri_info.c \
  callbacks.c callbacks.h
libgnuneturitrack_la_LIBADD = \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
 $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
 $(top_builddir)/src/util/libgnunetutil.la 


check_PROGRAMS = \
  tracktest

TESTS = $(check_PROGRAMS)

tracktest_SOURCES = \
  tracktest.c 
tracktest_LDADD = \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la \
  $(top_builddir)/src/applications/fs/uritrack/libgnuneturitrack.la 

EXTRA_DIST = \
  check.conf
