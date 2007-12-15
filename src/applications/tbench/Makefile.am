INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la 

bin_PROGRAMS = \
  gnunet-tbench

plugin_LTLIBRARIES = \
  libgnunetmodule_tbench.la


gnunet_tbench_SOURCES = \
  gnunet-tbench.c \
  tbench.h



libgnunetmodule_tbench_la_SOURCES = \
  tbench.c\
  tbench.h
libgnunetmodule_tbench_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la 
libgnunetmodule_tbench_la_LDFLAGS = \
  -export-dynamic -avoid-version -module


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
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 

tbenchtest_udp_SOURCES = \
  tbenchtest.c 
tbenchtest_udp_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 

tbenchtest_http_SOURCES = \
  tbenchtest.c 
tbenchtest_http_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  check.conf 
