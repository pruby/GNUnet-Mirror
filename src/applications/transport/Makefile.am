INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_transport.la 


libgnunetmodule_transport_la_SOURCES = \
  transport.c 
libgnunetmodule_transport_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/cron/libgnunetutil_cron.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la 
libgnunetmodule_transport_la_LDFLAGS = \
  -export-dynamic -avoid-version -module

