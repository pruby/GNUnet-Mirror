INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

# GNU Gettext support
LIBS = @LIBINTL@ @LIBS@

plugin_LTLIBRARIES = \
 libgnunetsetup_curses.la

if HAVE_GUILE
GUILE_SRC = \
	 mconf.c mconf.h
endif

EXTRA_DIST = mconf.c mconf.h

libgnunetsetup_curses_la_SOURCES = \
 $(GUILE_SRC) \
 wizard_curs.c wizard_curs.h

if HAVE_DIALOG
DIALOG_LIBS = -ldialog
endif

if HAVE_CDIALOG
DIALOG_LIBS = -lcdialog
endif

libgnunetsetup_curses_la_LDFLAGS = \
 -lncursesw $(DIALOG_LIBS) -lm \
 -export-dynamic -avoid-version -module

libgnunetsetup_curses_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/setup/lib/libgnunetsetup.la

