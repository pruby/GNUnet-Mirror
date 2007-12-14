INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_dht.la 

libgnunetmodule_dht_la_SOURCES = \
  cs.c \
  routing.c routing.h \
  service.c \
  table.c table.h 

libgnunetmodule_dht_la_LIBADD = -lm \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/applications/rpc/libgnunetrpc_util.la
libgnunetmodule_dht_la_LDFLAGS = \
  -export-dynamic -avoid-version -module




