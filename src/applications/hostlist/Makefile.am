INCLUDES = -I$(top_srcdir)/src/include


if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif
plugindir = $(libdir)/GNUnet

LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_hostlist.la


libgnunetmodule_hostlist_la_SOURCES = \
  hostlist.c
libgnunetmodule_hostlist_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_hostlist_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lmicrohttpd \
  $(GN_LIBINTL)


check_PROGRAMS = \
  hostlisttest 

TESTS = $(check_PROGRAMS)

hostlisttest_SOURCES = \
  hostlisttest.c 
hostlisttest_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstatsapi.la \
  $(top_builddir)/src/applications/testing/libgnunettestingapi.la \
  $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  check.conf \
  tcp-peer.conf \
  nat-peer.conf
