INCLUDES = -I$(top_srcdir)/src/include 

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

lib_LTLIBRARIES = \
  libgnunetdvdhtapi.la 

noinst_PROGRAMS = \
  gnunet-dvdht-query 

libgnunetdvdhtapi_la_SOURCES = \
  dv_dht_api.c
libgnunetdvdhtapi_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunetdvdhtapi_la_LIBADD = \
  $(top_builddir)/src/applications/stats/libgnunetstatsapi.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_dvdht_query_SOURCES = \
  dht-query.c
gnunet_dvdht_query_LDADD =  \
  $(top_builddir)/src/applications/dv_dht/tools/libgnunetdvdhtapi.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

bin_PROGRAMS = \
  dv_dht_driver \
  dv_dht_driver_new


dv_dht_driver_SOURCES = \
  dv_dht_driver.c
dv_dht_driver_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstatsapi.la \
  $(top_builddir)/src/applications/testing/libgnunettestingapi.la \
  $(top_builddir)/src/applications/testing/libgnunetremoteapi.la \
  $(top_builddir)/src/applications/dv_dht/tools/libgnunetdvdhtapi.la \
  $(top_builddir)/src/util/libgnunetutil.la

dv_dht_driver_new_SOURCES = \
  dv_dht_driver_new.c
dv_dht_driver_new_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstatsapi.la \
  $(top_builddir)/src/applications/testing/libgnunettestingapi.la \
  $(top_builddir)/src/applications/testing/libgnunetremoteapi.la \
  $(top_builddir)/src/applications/dv_dht/tools/libgnunetdvdhtapi.la \
  $(top_builddir)/src/util/libgnunetutil.la

check_PROGRAMS = \
  dv_dht_loopback_test \
  dv_dht_twopeer_test \
  dv_dht_multipeer_test \
  dv_dht_multi_topology_test

TESTS = $(check_PROGRAMS)

dv_dht_loopback_test_SOURCES = \
  dv_dht_loopback_test.c 
dv_dht_loopback_test_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstatsapi.la \
  $(top_builddir)/src/applications/testing/libgnunettestingapi.la \
  $(top_builddir)/src/applications/dv_dht/tools/libgnunetdvdhtapi.la \
  $(top_builddir)/src/util/libgnunetutil.la 

dv_dht_twopeer_test_SOURCES = \
  dv_dht_twopeer_test.c 
dv_dht_twopeer_test_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstatsapi.la \
  $(top_builddir)/src/applications/testing/libgnunettestingapi.la \
  $(top_builddir)/src/applications/dv_dht/tools/libgnunetdvdhtapi.la \
  $(top_builddir)/src/util/libgnunetutil.la 

dv_dht_multipeer_test_SOURCES = \
  dv_dht_multipeer_test.c 
dv_dht_multipeer_test_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstatsapi.la \
  $(top_builddir)/src/applications/testing/libgnunettestingapi.la \
  $(top_builddir)/src/applications/dv_dht/tools/libgnunetdvdhtapi.la \
  $(top_builddir)/src/util/libgnunetutil.la 
  
dv_dht_multi_topology_test_SOURCES = \
  dv_dht_multi_topology_test.c 
dv_dht_multi_topology_test_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstatsapi.la \
  $(top_builddir)/src/applications/testing/libgnunettestingapi.la \
  $(top_builddir)/src/applications/testing/libgnunetremoteapi.la \
  $(top_builddir)/src/applications/dv_dht/tools/libgnunetdvdhtapi.la \
  $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  check.conf \
  dv_test.conf \
  gnunetd_dv.conf
