INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_gap.la


libgnunetmodule_gap_la_SOURCES = \
  gap.c 
libgnunetmodule_gap_la_LDFLAGS = \
  -export-dynamic -avoid-version -module

