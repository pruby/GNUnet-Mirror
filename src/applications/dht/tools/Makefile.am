INCLUDES = -I$(top_srcdir)/src/include 

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

lib_LTLIBRARIES = \
  libgnunetdhtapi.la 

noinst_PROGRAMS = \
  gnunet-dht-query 

libgnunetdhtapi_la_SOURCES = \
  dht_api.c
libgnunetdhtapi_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunetdhtapi_la_LIBADD = \
  $(top_builddir)/src/applications/stats/libgnunetstatsapi.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_dht_query_SOURCES = \
  dht-query.c
gnunet_dht_query_LDADD =  \
  $(top_builddir)/src/applications/dht/tools/libgnunetdhtapi.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)




check_PROGRAMS = \
  dht_loopback_test \
  dht_twopeer_test \
  dht_multipeer_test 

TESTS = $(check_PROGRAMS)

dht_loopback_test_SOURCES = \
  dht_loopback_test.c 
dht_loopback_test_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstatsapi.la \
  $(top_builddir)/src/applications/testing/libgnunettestingapi.la \
  $(top_builddir)/src/applications/dht/tools/libgnunetdhtapi.la \
  $(top_builddir)/src/util/libgnunetutil.la 

# This test requires an API change before we can
# integrate it by default...
#dht_expiration_test_SOURCES = \
#  dht_expiration_test.c 
#dht_expiration_test_LDADD = \
#  $(top_builddir)/src/applications/stats/libgnunetstatsapi.la \
#  $(top_builddir)/src/applications/testing/libgnunettestingapi.la \
#  $(top_builddir)/src/applications/dht/tools/libgnunetdhtapi.la \
#  $(top_builddir)/src/util/libgnunetutil.la 

dht_twopeer_test_SOURCES = \
  dht_twopeer_test.c 
dht_twopeer_test_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstatsapi.la \
  $(top_builddir)/src/applications/testing/libgnunettestingapi.la \
  $(top_builddir)/src/applications/dht/tools/libgnunetdhtapi.la \
  $(top_builddir)/src/util/libgnunetutil.la 

dht_multipeer_test_SOURCES = \
  dht_multipeer_test.c 
dht_multipeer_test_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstatsapi.la \
  $(top_builddir)/src/applications/testing/libgnunettestingapi.la \
  $(top_builddir)/src/applications/dht/tools/libgnunetdhtapi.la \
  $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  check.conf 
