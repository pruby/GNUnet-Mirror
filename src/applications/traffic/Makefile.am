INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

lib_LTLIBRARIES = \
  libgnunettraffic_api.la

plugin_LTLIBRARIES = \
  libgnunetmodule_traffic.la


libgnunettraffic_api_la_SOURCES = \
  clientapi.c 
libgnunettraffic_api_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la 


libgnunetmodule_traffic_la_SOURCES = \
  traffic.c traffic.h
libgnunetmodule_traffic_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunetmodule_traffic_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
