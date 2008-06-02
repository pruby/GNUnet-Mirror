INCLUDES = -I$(top_srcdir)/src/include 

lib_LTLIBRARIES = \
  libgnunetdht_api.la 

noinst_PROGRAMS = \
  gnunet-dht-query 

libgnunetdht_api_la_SOURCES = \
  dht_api.c dht_api.h
libgnunetdht_api_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la

gnunet_dht_query_SOURCES = \
  dht-query.c
gnunet_dht_query_LDADD =  \
  $(top_builddir)/src/applications/dht/tools/libgnunetdht_api.la \
  $(top_builddir)/src/util/libgnunetutil.la




check_PROGRAMS = \
  dht_loopback_test \
  dht_twopeer_test \
  dht_multipeer_test 

TESTS = $(check_PROGRAMS)

dht_loopback_test_SOURCES = \
  dht_loopback_test.c 
dht_loopback_test_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/applications/dht/tools/libgnunetdht_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 

dht_twopeer_test_SOURCES = \
  dht_twopeer_test.c 
dht_twopeer_test_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/applications/dht/tools/libgnunetdht_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 

dht_multipeer_test_SOURCES = \
  dht_multipeer_test.c 
dht_multipeer_test_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/applications/dht/tools/libgnunetdht_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  check.conf 
