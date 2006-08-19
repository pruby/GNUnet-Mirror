INCLUDES = -I$(top_srcdir)/src/include

AM_CFLAGS = $(GTK_CFLAGS)

plugindir = $(libdir)/GNUnet

# GNU Gettext support
LIBS = @LIBINTL@ @LIBS@

lib_LTLIBRARIES = libgnunetsetup.la

libgnunetsetup_la_SOURCES = \
  gns.c

libgnunetsetup_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/loggers/libgnunetutil_logging.la \
 $(top_builddir)/src/util/config_impl/libgnunetutil_config.la 

libgnunetsetup_la_LDFLAGS = \
 -export-dynamic

