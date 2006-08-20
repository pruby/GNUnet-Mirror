INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

# GNU Gettext support
LIBS = @LIBINTL@ @LIBS@

plugin_LTLIBRARIES = \
 libgnunetsetup_curses.la

if HAVE_CURSES
if HAVE_PDCURSES
 pdcurses_lib = -lpdcurses
else
 curses_lib = -lncurses
endif
endif

libgnunetsetup_curses_la_SOURCES = \
 mconf.c mconf.h \
 mconf_checklist.c \
 mconf_colors.h \
 mconf_dialog.h \
 mconf_inputbox.c \
 mconf_menubox.c \
 mconf_msgbox.c \
 mconf_textbox.c \
 mconf_util.c \
 mconf_yesno.c \
 wizard_curs.c \
 wizard_curs.h

libgnunetsetup_curses_la_LDFLAGS = \
 $(curses_lib) $(pdcurses_lib) \
 -export-dynamic -avoid-version -module

libgnunetsetup_curses_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/setup/lib/libgnunetsetup.la

