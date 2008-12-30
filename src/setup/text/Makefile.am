INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
 libgnunetsetup_text.la 

libgnunetsetup_text_la_SOURCES = \
  conf.c conf.h
libgnunetsetup_text_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetsetup_text_la_LIBADD = \
  $(top_builddir)/src/setup/lib/libgnunetsetup.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
