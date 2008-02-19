INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_hostlist.la


libgnunetmodule_hostlist_la_SOURCES = \
  hostlist.c
libgnunetmodule_hostlist_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la  -lmicrohttpd
libgnunetmodule_hostlist_la_LDFLAGS = \
  -export-dynamic -avoid-version -module



check_PROGRAMS = \
  hostlisttest 

TESTS = $(check_PROGRAMS)

hostlisttest_SOURCES = \
  hostlisttest.c 
hostlisttest_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  check.conf \
  tcp-peer.conf \
  nat-peer.conf