INCLUDES = -I$(top_srcdir)/src/include

AM_CFLAGS = $(GTK_CFLAGS)

# GNU Gettext support
LIBS = @LIBINTL@ @LIBS@

if MINGW
 WINTOOL = gnunet-win-tool
endif

bin_PROGRAMS = \
 gnunet-setup \
 $(WINTOOL)

BUILT_SOURCES = \
 lkc_defs.h

EXTRA_DIST = \
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

if HAVE_CURSES
mconf_src = \
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
  wizard_curs.c wizard_curs.h
endif

if HAVE_GTK
 gconf_libs = $(GTK_LIBS) @EXT_LIB_PATH@ $(LDADD) @EXT_LIBS@ -lgthread-2.0

 gconf_src = \
   gconf_callbacks.h \
   gconf_interface.h \
   gconf_support.h \
   gconf_interface.c \
   gconf_support.c \
   gconf.c gconf.h \
   images.c 

 gbasic_src = \
   wizard_callbacks.h \
   wizard_interface.h \
   wizard_support.h \
   wizard_callbacks.c \
   wizard_interface.c \
   wizard.c wizard.h
endif


gnunet_setup_SOURCES = \
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
 $(mconf_src) \
 $(gconf_src) \
 $(gbasic_src) \
 $(wizard_util_src) \
 wizard_util.c wizard_util.h \
 gnunet-setup.c

gnunet_setup_LDFLAGS = \
 $(curses_lib) $(pdcurses_lib) $(gconf_libs)

gnunet_setup_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la

gnunet_win_tool_SOURCE = \
 gnunet-win-tool.c

gnunet_win_tool_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la
