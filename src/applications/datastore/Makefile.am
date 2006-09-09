INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_datastore.la

libgnunetmodule_datastore_la_SOURCES = \
  filter.c filter.h \
  prefetch.c prefetch.h \
  datastore.c 
libgnunetmodule_datastore_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
libgnunetmodule_datastore_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/cron/libgnunetutil_cron.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
 $(top_builddir)/src/util/containers/libgnunetutil_containers.la 

