INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_session.la 

libgnunetmodule_session_la_SOURCES = \
  cache.c cache.h \
  connect.c 
libgnunetmodule_session_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la 
libgnunetmodule_session_la_LDFLAGS = \
  -export-dynamic -avoid-version -module

if HAVE_MHD
  httptest = sessiontest_http sessiontest_nat_http
endif

check_PROGRAMS = \
  sessiontest_tcp \
  sessiontest_udp \
  sessiontest_nat $(httptest)

TESTS = $(check_PROGRAMS)

sessiontest_tcp_SOURCES = \
  sessiontest.c 
sessiontest_tcp_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 

sessiontest_udp_SOURCES = \
  sessiontest.c 
sessiontest_udp_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 

sessiontest_http_SOURCES = \
  sessiontest.c 
sessiontest_http_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 

sessiontest_nat_SOURCES = \
  sessiontest_nat.c 
sessiontest_nat_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/identity/libgnunetidentity_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 


sessiontest_nat_http_SOURCES = \
  sessiontest_nat_http.c 
sessiontest_nat_http_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/identity/libgnunetidentity_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  check.conf \
  tcp-peer.conf \
  nat-peer.conf \
  http-peer.conf \
  nat-http-peer.conf
