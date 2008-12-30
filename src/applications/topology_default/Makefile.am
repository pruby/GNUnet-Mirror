if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif
INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_topology_default.la 

libgnunetmodule_topology_default_la_SOURCES = \
  topology.c 
libgnunetmodule_topology_default_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_topology_default_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
