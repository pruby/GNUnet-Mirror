INCLUDES = -I$(top_srcdir)/src/include

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_stats.la

bin_PROGRAMS = \
 gnunet-stats


gnunet_stats_SOURCES = \
 gnunet-stats.c 	

libgnunetmodule_stats_la_SOURCES = \
  statistics.c \
  statistics.h
libgnunetmodule_stats_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunetmodule_stats_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
