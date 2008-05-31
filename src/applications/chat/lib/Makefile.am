INCLUDES = -I$(top_srcdir)/src/include

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

libgnunetchat_api_la_SOURCES = \
  clientapi.c 
libgnunetchat_api_la_LIBADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/libgnunetutil.la 

check_PROGRAMS = \
  loopback_test

TESTS = $(check_PROGRAMS)

loopback_test_SOURCES = \
  loopback_test.c 
chattest_LDADD = \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/chat/lib/libgnunetchat_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 
