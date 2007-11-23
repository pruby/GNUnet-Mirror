INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_gap.la


libgnunetmodule_gap_la_SOURCES = \
  gap.c gap.h \
  pid_table.c pid_table.h
libgnunetmodule_gap_la_LDFLAGS = \
  -export-dynamic -avoid-version -module \
  $(LDADD)



check_PROGRAMS = \
  gaptest gaptest2 gaptest3

TESTS = $(check_PROGRAMS)

gaptest_SOURCES = \
  gaptest.c 
gaptest_LDADD = \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/libgnunetutil.la 


gaptest2_SOURCES = \
  gaptest2.c 
gaptest2_LDADD = \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/libgnunetutil.la 


gaptest3_SOURCES = \
  gaptest3.c 
gaptest3_LDADD = \
  $(top_builddir)/src/applications/identity/libgnunetidentity_api.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/libgnunetutil.la 


EXTRA_DIST = \
  check.conf
