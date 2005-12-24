INCLUDES = -I$(top_srcdir)/src/include

AM_CFLAGS = $(GTK_CFLAGS)

plugindir = $(libdir)/GNUnet

# GNU Gettext support
LIBS = @LIBINTL@ @LIBS@

if MINGW
 WINTOOL = gnunet-win-tool
endif

bin_PROGRAMS = \
 gnunet-setup \
 $(WINTOOL)

if HAVE_CURSES
 curses_libs = \
	libgnunetsetup_curses.la
endif

if HAVE_GTK
 gtk_libs = \
	libgnunetsetup_gtk.la
endif

lib_LTLIBRARIES = libgnunetsetup.la

plugin_LTLIBRARIES = \
 $(curses_libs) \
 $(gtk_libs)

BUILT_SOURCES = \
 lkc_defs.h

EXTRA_DIST = \
 images.c \
 lex.zconf.c \
 lkc_proto.h \
 bool.h \
 wizard_gtk.h

if HAVE_CURSES
if HAVE_PDCURSES
 pdcurses_lib = -lpdcurses
else
 curses_lib = -lncurses
endif
endif

lkc_defs.h: $(srcdir)/lkc_proto.h
	sed < $(srcdir)/lkc_proto.h > $@ 's/P(\([^,]*\),.*/#define \1 (\*\1_p)/'

libgnunetsetup_la_SOURCES = \
 conf.c conf.h \
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
 $(top_builddir)/src/util/libgnunetutil.la

libgnunetsetup_la_LDFLAGS = \
 -export-dynamic -avoid-version

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
 libgnunetsetup.la

libgnunetsetup_gtk_la_SOURCES = \
 gconf_callbacks.h \
 gconf_interface.h \
 gconf_support.h \
 gconf_interface.c \
 gconf_support.c \
 gconf.c gconf.h \
 wizard_callbacks.h \
 wizard_interface.h \
 wizard_support.h \
 wizard_callbacks.c \
 wizard_interface.c \
 wizard.c wizard.h

libgnunetsetup_gtk_la_LDFLAGS = \
 $(GTK_LIBS) @EXT_LIB_PATH@ @EXT_LIBS@ -lgthread-2.0 \
 -export-dynamic -avoid-version -module
 
libgnunetsetup_gtk_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunetsetup.la

gnunet_setup_SOURCES = \
 gnunet-setup.c
 
gnunet_setup_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunetsetup.la

gnunet_win_tool_SOURCE = \
 gnunet-win-tool.c

gnunet_win_tool_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la
