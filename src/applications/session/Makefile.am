INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_session.la 

libgnunetmodule_session_la_SOURCES = \
  connect.c 
libgnunetmodule_session_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la 
libgnunetmodule_session_la_LDFLAGS = \
  -export-dynamic -avoid-version -module



check_PROGRAMS = \
  sessiontest 

TESTS = $(check_PROGRAMS)

sessiontest_SOURCES = \
  sessiontest.c 
sessiontest_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  peer1.conf \
  peer2.conf \
  peer1/.hostkey \
  peer2/.hostkey 
