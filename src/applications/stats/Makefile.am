INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_stats.la

lib_LTLIBRARIES = \
  libgnunetstats_api.la

bin_PROGRAMS = \
 gnunet-stats

EXTRA_DIST = \
  sqstats.c

gnunet_stats_SOURCES = \
 gnunet-stats.c 	
gnunet_stats_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)

libgnunetstats_api_la_SOURCES = \
  clientapi.c 
libgnunetstats_api_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunetstats_api_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL) 

libgnunetmodule_stats_la_SOURCES = \
  statistics.c \
  statistics.h
libgnunetmodule_stats_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_stats_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)

