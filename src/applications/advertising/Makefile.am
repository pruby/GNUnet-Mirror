INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_advertising.la 

libgnunetmodule_advertising_la_SOURCES = \
  advertising.c \
  bootstrap.c \
  bootstrap.h
libgnunetmodule_advertising_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
 $(top_builddir)/src/util/cron/libgnunetutil_cron.la
libgnunetmodule_advertising_la_LDFLAGS = \
  -export-dynamic -avoid-version -module

check_PROGRAMS = \
  advertising_test \
  advertising_test_udp 

TESTS = $(check_PROGRAMS)

advertising_test_SOURCES = \
  advertising_test.c 
advertising_test_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la \
  $(top_builddir)/src/util/libgnunetutil.la 

advertising_test_udp_SOURCES = \
  advertising_test.c 
advertising_test_udp_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la \
  $(top_builddir)/src/util/libgnunetutil.la 



EXTRA_DIST = \
  check.conf 
