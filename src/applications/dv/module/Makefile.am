INCLUDES = -I$(top_srcdir)/src/include

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

plugindir = $(libdir)/GNUnet

noinst_LTLIBRARIES = libheap.la 

libheap_la_SOURCES = \
  dv.c heap.c

plugin_LTLIBRARIES = \
  libgnunetmodule_dv.la \
  libgnunetmodule_dv_tbench.la

libgnunetmodule_dv_la_SOURCES = \
  dv.c heap.c \
  service.c
libgnunetmodule_dv_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_dv_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

libgnunetmodule_dv_tbench_la_SOURCES = \
  dv_tbench.c \
  dv_tbench.h
libgnunetmodule_dv_tbench_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_dv_tbench_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

  
check_PROGRAMS = \
 heaptest \
 dv_heaptest \
 dvtest
 
TESTS = $(check_PROGRAMS)

dvtest_SOURCES = \
 dvtest.c
dvtest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/applications/dv/module/libheap.la \
 $(top_builddir)/src/applications/stats/libgnunetstatsapi.la \
 $(top_builddir)/src/applications/testing/libgnunetremoteapi.la \
 $(top_builddir)/src/applications/testing/libgnunettestingapi.la

heaptest_SOURCES = \
 heaptest.c
heaptest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/applications/dv/module/libheap.la

dv_heaptest_SOURCES = \
 dv_heaptest.c
dv_heaptest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/applications/dv/module/libheap.la

EXTRA_DIST = \
  check.conf \
  dv_test.conf \
  gnunetd_dv.conf

