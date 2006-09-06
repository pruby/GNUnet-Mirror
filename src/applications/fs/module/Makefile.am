INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_fs.la


libgnunetmodule_fs_la_SOURCES = \
  anonymity.c anonymity.h \
  fs.c \
  ondemand.c ondemand.h \
  migration.c migration.h \
  querymanager.c querymanager.h
libgnunetmodule_fs_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
libgnunetmodule_fs_la_LIBADD = \
 $(top_builddir)/src/applications/fs/libecrs_core.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
 $(top_builddir)/src/util/cron/libgnunetutil_cron.la \
 $(top_builddir)/src/util/libgnunetutil.la 

