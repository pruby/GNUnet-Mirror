INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

# GNU Gettext support
LIBS = @LIBINTL@ @LIBS@

plugin_LTLIBRARIES = \
 libgnunetsetup_text.la 

libgnunetsetup_text_la_SOURCES = \
  conf.c conf.h

libgnunetsetup_text_la_LDFLAGS = \
 -export-dynamic -avoid-version -module

libgnunetsetup_text_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/setup/lib/libgnunetsetup.la
