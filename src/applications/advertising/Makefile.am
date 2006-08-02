INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_advertising.la 

libgnunetmodule_advertising_la_SOURCES = \
  advertising.c \
  bootstrap.c \
  bootstrap.h
libgnunetmodule_advertising_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
 $(top_builddir)/src/util/cron/libgnunetutil_cron.la
libgnunetmodule_advertising_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
