INCLUDES = -I$(top_srcdir)/src/include 

lib_LTLIBRARIES = \
  libgnunetdht_api.la 

bin_PROGRAMS = \
  gnunet-dht-query 

libgnunetdht_api_la_SOURCES = \
  dht_api.c 
libgnunetdht_api_la_LIBADD = \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la \
  $(top_builddir)/src/util/libgnunetutil.la

gnunet_dht_query_SOURCES = \
  dht-query.c
gnunet_dht_query_LDADD =  \
  $(top_builddir)/src/applications/dht/tools/libgnunetdht_api.la \
  $(top_builddir)/src/util/boot/libgnunetutil_boot.la \
  $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la \
  $(top_builddir)/src/util/libgnunetutil.la




check_PROGRAMS = \
  dhttest2 \
  dhttest

TESTS = $(check_PROGRAMS)

dhttest2_SOURCES = \
  dhttest2.c 
dhttest2_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/applications/dht/tools/libgnunetdht_api.la \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la \
  $(top_builddir)/src/util/libgnunetutil.la 

dhttest_SOURCES = \
  dhttest.c 
dhttest_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/applications/dht/tools/libgnunetdht_api.la \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la \
  $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  check.conf 
