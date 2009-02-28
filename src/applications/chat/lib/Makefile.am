INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

lib_LTLIBRARIES = \
  libgnunetchatapi.la

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

libgnunetchatapi_la_SOURCES = \
  messaging.c 
libgnunetchatapi_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunetchatapi_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

check_PROGRAMS = \
  loopback_test

TESTS = $(check_PROGRAMS)

EXTRA_DIST = check.conf

loopback_test_SOURCES = \
  loopback_test.c 
loopback_test_LDADD = \
  $(top_builddir)/src/applications/testing/libgnunettestingapi.la \
  $(top_builddir)/src/applications/stats/libgnunetstatsapi.la \
  $(top_builddir)/src/applications/chat/lib/libgnunetchatapi.la \
  $(top_builddir)/src/util/libgnunetutil.la 
