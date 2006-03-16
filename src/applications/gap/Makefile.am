INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_gap.la


libgnunetmodule_gap_la_SOURCES = \
  gap.c gap.h
libgnunetmodule_gap_la_LDFLAGS = \
  -export-dynamic -avoid-version -module \
  $(LDADD)



check_PROGRAMS = \
  gaptest 

TESTS = $(check_PROGRAMS)

gaptest_SOURCES = \
  gaptest.c 
gaptest_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  peer1.conf \
  peer2.conf \
  peer1/.hostkey \
  peer2/.hostkey 
