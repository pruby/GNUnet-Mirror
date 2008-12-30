INCLUDES = -I$(top_srcdir)/src/include -I$(top_srcdir)/src/setup/lib

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
 libgnunetsetup_curses.la

if HAVE_GUILE
GUILE_SRC = \
	 mconf.c mconf.h
endif

EXTRA_DIST = mconf.c mconf.h


if HAVE_DIALOG
DIALOG_LIBS = -ldialog
endif

if HAVE_CDIALOG
DIALOG_LIBS = -lcdialog
endif

libgnunetsetup_curses_la_SOURCES = \
 $(GUILE_SRC) \
 wizard_curs.c wizard_curs.h
libgnunetsetup_curses_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
libgnunetsetup_curses_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/setup/lib/libgnunetsetup.la \
 -lncursesw $(DIALOG_LIBS) -lm \
 $(GN_LIBINTL)

