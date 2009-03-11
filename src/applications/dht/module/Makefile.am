INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_dht.la 

libgnunetmodule_dht_la_SOURCES = \
  cs.c \
  routing.c routing.h \
  service.c service.h \
  table.c table.h 
libgnunetmodule_dht_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_dht_la_LIBADD = -lm \
  $(top_builddir)/src/applications/rpc/libgnunetrpcutil.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
