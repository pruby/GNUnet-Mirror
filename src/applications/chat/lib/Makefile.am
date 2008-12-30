INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

lib_LTLIBRARIES = \
  libgnunetchat_api.la

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

libgnunetchat_api_la_SOURCES = \
  messaging.c 
libgnunetchat_api_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunetchat_api_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

check_PROGRAMS = \
  loopback_test

TESTS = $(check_PROGRAMS)

loopback_test_SOURCES = \
  loopback_test.c 
loopback_test_LDADD = \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/chat/lib/libgnunetchat_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 
