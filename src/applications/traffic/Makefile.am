INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

lib_LTLIBRARIES = \
  libgnunettrafficapi.la

plugin_LTLIBRARIES = \
  libgnunetmodule_traffic.la


libgnunettrafficapi_la_SOURCES = \
  clientapi.c 
libgnunettrafficapi_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunettrafficapi_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) 


libgnunetmodule_traffic_la_SOURCES = \
  traffic.c traffic.h
libgnunetmodule_traffic_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_traffic_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
