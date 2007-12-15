INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

LDADD =  \
  $(top_builddir)/src/util/libgnunetutil.la 

bin_PROGRAMS = \
  gnunet-tracekit

plugin_LTLIBRARIES = \
  libgnunetmodule_tracekit.la

lib_LTLIBRARIES = \
  libgnunettracekit_api.la

gnunet_tracekit_SOURCES = \
  gnunet-tracekit.c \
  tracekit.h

gnunet_tracekit_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/applications/tracekit/libgnunettracekit_api.la 


libgnunetmodule_tracekit_la_SOURCES = \
  tracekit.c \
  tracekit.h

libgnunetmodule_tracekit_la_LIBADD = \
  $(LDADD)

libgnunetmodule_tracekit_la_LDFLAGS = \
  -export-dynamic -avoid-version -module

libgnunettracekit_api_la_SOURCES = \
  clientapi.c 
libgnunettracekit_api_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = check.conf

check_PROGRAMS = \
  tracekittest

TESTS = $(check_PROGRAMS)

tracekittest_SOURCES = \
  tracekittest.c 
tracekittest_LDADD = \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/tracekit/libgnunettracekit_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 
