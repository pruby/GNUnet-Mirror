INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_topology.la 

libgnunetmodule_topology_la_SOURCES = \
  topology.c 
libgnunetmodule_topology_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la 
libgnunetmodule_topology_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
