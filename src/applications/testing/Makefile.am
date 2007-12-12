INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

lib_LTLIBRARIES = \
  libgnunettesting_api.la

libgnunettesting_api_la_SOURCES = \
  testing.c 
libgnunettesting_api_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/applications/identity/libgnunetidentity_api.la 


check_PROGRAMS = \
  testingtest \
  testingtest_loop

TESTS = $(check_PROGRAMS)

testingtest_SOURCES = \
 testingtest.c 
testingtest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/applications/testing/libgnunettesting_api.la


testingtest_loop_SOURCES = \
 testingtest_loop.c 
testingtest_loop_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/applications/testing/libgnunettesting_api.la


pkgdata_DATA = \
 gnunet-testing.conf

EXTRA_DIST = \
 $(pkgdata_DATA)
