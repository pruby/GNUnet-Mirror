INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_session.la 

libgnunetmodule_session_la_SOURCES = \
  connect.c 
libgnunetmodule_session_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la 
libgnunetmodule_session_la_LDFLAGS = \
  -export-dynamic -avoid-version -module

if HAVE_MHD
  httptest = sessiontest_http sessiontest2_http
endif

check_PROGRAMS = \
  sessiontest_tcp \
  sessiontest_udp \
  sessiontest2 $(httptest)

TESTS = $(check_PROGRAMS)

sessiontest_tcp_SOURCES = \
  sessiontest.c 
sessiontest_tcp_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la  \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la  \
  $(top_builddir)/src/util/libgnunetutil.la 

sessiontest_udp_SOURCES = \
  sessiontest.c 
sessiontest_udp_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la  \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la  \
  $(top_builddir)/src/util/libgnunetutil.la 

sessiontest_http_SOURCES = \
  sessiontest.c 
sessiontest_http_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la  \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la  \
  $(top_builddir)/src/util/libgnunetutil.la 

sessiontest2_SOURCES = \
  sessiontest2.c 
sessiontest2_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/identity/libgnunetidentity_api.la \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la  \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la  \
  $(top_builddir)/src/util/libgnunetutil.la 


sessiontest2_http_SOURCES = \
  sessiontest_http.c 
sessiontest2_http_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/identity/libgnunetidentity_api.la \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la  \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la  \
  $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  check.conf \
  tcp-peer.conf \
  nat-peer.conf \
  http-peer.conf \
  nat-http-peer.conf
