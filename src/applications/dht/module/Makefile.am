INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_dht.la 

libgnunetmodule_dht_la_SOURCES = \
  table.c table.h \
  dstore.c dstore.h \
  routing.c routing.h \
  service.c service.h

libgnunetmodule_dht_la_LIBADD = \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
 $(top_builddir)/src/util/containers/libgnunetutil_containers.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/cron/libgnunetutil_cron.la \
 $(top_builddir)/src/applications/rpc/libgnunetmodule_rpc_util.la
libgnunetmodule_dht_la_LDFLAGS = \
  -export-dynamic -avoid-version -module




