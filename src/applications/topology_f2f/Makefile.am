INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_topology_f2f.la 

libgnunetmodule_topology_f2f_la_SOURCES = \
  topology.c 
libgnunetmodule_topology_f2f_la_LIBADD = \
  $(top_builddir)/src/util/cron/libgnunetutil_cron.la \
  $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
  $(top_builddir)/src/util/libgnunetutil.la 
libgnunetmodule_topology_f2f_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
