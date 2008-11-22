INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_advertising.la 

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

libgnunetmodule_advertising_la_SOURCES = \
  advertising.c \
  bootstrap.c \
  bootstrap.h
libgnunetmodule_advertising_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_advertising_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)



if HAVE_MHD
  httptest = advertisingtest_http 
endif

check_PROGRAMS = \
  advertisingtest_tcp \
  advertisingtest_udp $(httptest) 

TESTS = $(check_PROGRAMS)

advertisingtest_tcp_SOURCES = \
  advertising_test.c 
advertisingtest_tcp_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 

advertisingtest_udp_SOURCES = \
  advertising_test.c 
advertisingtest_udp_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 

advertisingtest_http_SOURCES = \
  advertising_test.c 
advertisingtest_http_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 



EXTRA_DIST = \
  check.conf 
