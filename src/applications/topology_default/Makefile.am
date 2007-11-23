INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_topology_default.la 

libgnunetmodule_topology_default_la_SOURCES = \
  topology.c 
libgnunetmodule_topology_default_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la 
libgnunetmodule_topology_default_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
