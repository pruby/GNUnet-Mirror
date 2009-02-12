INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif
plugindir = $(libdir)/GNUnet

lib_LTLIBRARIES = \
  libgnunettestingapi.la \
  libgnunetremoteapi.la

libgnunettestingapi_la_SOURCES = \
  testing.c 
libgnunettestingapi_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunettestingapi_la_LIBADD = \
  $(top_builddir)/src/applications/identity/libgnunetidentityapi.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) 

libgnunetremoteapi_la_SOURCES = \
  remote.c remote.h
libgnunetremoteapi_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunetremoteapi_la_LIBADD = \
  $(top_builddir)/src/applications/identity/libgnunetidentityapi.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) 

bin_PROGRAMS = \
  remotetest

check_PROGRAMS = \
  testingtest \
  testingtest_loop

TESTS = $(check_PROGRAMS)

testingtest_SOURCES = \
 testingtest.c 
testingtest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/applications/testing/libgnunettestingapi.la

remotetest_SOURCES = \
 remotetest.c
remotetest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/applications/testing/libgnunetremoteapi.la


testingtest_loop_SOURCES = \
 testingtest_loop.c 
testingtest_loop_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/applications/testing/libgnunettestingapi.la


pkgdata_DATA = \
 gnunet-testing.conf \
 gnunet-lab-testing.conf \
 gnunetd.conf.skel

EXTRA_DIST = \
 $(pkgdata_DATA) remotetopologies.c
