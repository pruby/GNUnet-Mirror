INCLUDES = -I$(top_srcdir)/src/include

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_stats.la

lib_LTLIBRARIES = \
  libgnunetstats_api.la

bin_PROGRAMS = \
 gnunet-stats


gnunet_stats_SOURCES = \
 gnunet-stats.c 	
gnunet_stats_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/util/libgnunetutil.la

libgnunetstats_api_la_SOURCES = \
  clientapi.c 
libgnunetstats_api_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la

libgnunetmodule_stats_la_SOURCES = \
  statistics.c \
  statistics.h
libgnunetmodule_stats_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunetmodule_stats_la_LDFLAGS = \
  -export-dynamic -avoid-version -module

