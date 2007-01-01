INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

# GNU Gettext support
LIBS = @LIBINTL@ @LIBS@

plugin_LTLIBRARIES = \
 libgnunetsetup_curses.la

libgnunetsetup_curses_la_SOURCES = \
 mconf.c mconf.h \
 wizard_curs.c wizard_curs.h

libgnunetsetup_curses_la_LDFLAGS = \
 -lncursesw -ldialog -lm \
 -export-dynamic -avoid-version -module

libgnunetsetup_curses_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/setup/lib/libgnunetsetup.la

