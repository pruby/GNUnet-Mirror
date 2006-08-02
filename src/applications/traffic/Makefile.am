INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

lib_LTLIBRARIES = \
  libgnunetmodule_traffic_api.la

plugin_LTLIBRARIES = \
  libgnunetmodule_traffic.la


libgnunetmodule_traffic_api_la_SOURCES = \
  clientapi.c 
libgnunetmodule_traffic_api_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la


libgnunetmodule_traffic_la_SOURCES = \
  traffic.c traffic.h
libgnunetmodule_traffic_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunetmodule_traffic_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
