INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif
plugindir = $(libdir)/GNUnet

bin_PROGRAMS = \
  gnunet-tbench

plugin_LTLIBRARIES = \
  libgnunetmodule_tbench.la


gnunet_tbench_SOURCES = \
  gnunet-tbench.c \
  tbench.h
gnunet_tbench_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


libgnunetmodule_tbench_la_SOURCES = \
  tbench.c \
  tbench.h
libgnunetmodule_tbench_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_tbench_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


if HAVE_MHD
  httptest = tbenchtest_http 
endif

check_PROGRAMS = \
  tbenchtest_tcp \
  tbenchtest_udp $(httptest)

TESTS = $(check_PROGRAMS)

tbenchtest_tcp_SOURCES = \
  tbenchtest.c 
tbenchtest_tcp_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstatsapi.la \
  $(top_builddir)/src/applications/testing/libgnunettestingapi.la \
  $(top_builddir)/src/util/libgnunetutil.la 

tbenchtest_udp_SOURCES = \
  tbenchtest.c 
tbenchtest_udp_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstatsapi.la \
  $(top_builddir)/src/applications/testing/libgnunettestingapi.la \
  $(top_builddir)/src/util/libgnunetutil.la 

tbenchtest_http_SOURCES = \
  tbenchtest.c 
tbenchtest_http_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstatsapi.la \
  $(top_builddir)/src/applications/testing/libgnunettestingapi.la \
  $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  check.conf 
