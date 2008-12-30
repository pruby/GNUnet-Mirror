if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif
INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_transport.la 


libgnunetmodule_transport_la_SOURCES = \
  transport.c 
libgnunetmodule_transport_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_transport_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
