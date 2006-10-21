INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

LDADD =  \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la \
  $(top_builddir)/src/util/boot/libgnunetutil_boot.la \
  $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
  $(top_builddir)/src/util/cron/libgnunetutil_cron.la 

bin_PROGRAMS = \
  gnunet-tracekit

plugin_LTLIBRARIES = \
  libgnunetmodule_tracekit.la


gnunet_tracekit_SOURCES = \
  gnunet-tracekit.c \
  tracekit.h


libgnunetmodule_tracekit_la_SOURCES = \
  tracekit.c \
  tracekit.h

libgnunetmodule_tracekit_la_LIBADD = \
  $(LDADD)

libgnunetmodule_tracekit_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
