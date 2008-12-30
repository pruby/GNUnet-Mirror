INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif
lib_LTLIBRARIES = \
  libgnuneturitrack.la 

libgnuneturitrack_la_SOURCES = \
  file_info.c \
  uri_info.c \
  callbacks.c callbacks.h
libgnuneturitrack_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnuneturitrack_la_LIBADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


check_PROGRAMS = \
  tracktest

TESTS = $(check_PROGRAMS)

tracktest_SOURCES = \
  tracktest.c 
tracktest_LDADD = \
  $(top_builddir)/src/applications/fs/uritrack/libgnuneturitrack.la 

EXTRA_DIST = \
  check.conf
