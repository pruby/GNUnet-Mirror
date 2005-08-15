INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la 

bin_PROGRAMS = \
  gnunet-tbench
plugin_LTLIBRARIES = \
  libgnunetmodule_tbench.la


gnunet_tbench_SOURCES = \
  gnunet-tbench.c \
  tbench.h

libgnunetmodule_tbench_la_SOURCES = \
  tbench.c\
  tbench.h
libgnunetmodule_tbench_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunetmodule_tbench_la_LDFLAGS = \
  -export-dynamic -avoid-version -module



check_PROGRAMS = \
  tbenchtest \
  tbenchtest_udp

TESTS = $(check_PROGRAMS)

tbenchtest_SOURCES = \
  tbenchtest.c 
tbenchtest_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 

tbenchtest_udp_SOURCES = \
  tbenchtest_udp.c 
tbenchtest_udp_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  peer1.conf \
  peer2.conf \
  peer1/.hostkey \
  peer2/.hostkey \
  peer1udp.conf \
  peer2udp.conf \
  peer1-udp/.hostkey \
  peer2-udp/.hostkey 
