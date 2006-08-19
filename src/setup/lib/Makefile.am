INCLUDES = -I$(top_srcdir)/src/include

AM_CFLAGS = $(GTK_CFLAGS)

plugindir = $(libdir)/GNUnet

# GNU Gettext support
LIBS = @LIBINTL@ @LIBS@

lib_LTLIBRARIES = libgnunetsetup.la

EXTRA_DIST = \
 lex.zconf.c \
 lkc_proto.h \
 bool.h 

BUILT_SOURCES = \
 lkc_defs.h

lkc_defs.h: $(srcdir)/lkc_proto.h
	sed < $(srcdir)/lkc_proto.h > $@ 's/P(\([^,]*\),.*/#define \1 (\*\1_p)/'

libgnunetsetup_la_SOURCES = \
 confdata.c confdata.h \
 expr.c \
 expr.h \
 lkc.h \
 menu.c \
 recreate.c recreate.h \
 symbol.c \
 zconf.tab.h \
 zconf_tab.c zconf_tab.h \
 wizard_util.c \
 wizard_util.h

libgnunetsetup_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/loggers/libgnunetutil_logging.la \
 $(top_builddir)/src/util/config_impl/libgnunetutil_config.la 

libgnunetsetup_la_LDFLAGS = \
 -export-dynamic

