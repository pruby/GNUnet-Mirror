INCLUDES = -I$(top_srcdir)/src/include

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
 qconf.h \
 bool.h

if HAVE_CURSES
 curses_lib = -lncurses
endif

lkc_defs.h: $(srcdir)/lkc_proto.h
	sed < $(srcdir)/lkc_proto.h > $@ 's/P(\([^,]*\),.*/#define \1 (\*\1_p)/'


if HAVE_CURSES
mconf_src = \
  mconf.c \
  mconf_checklist.c \
  mconf_colors.h \
  mconf_dialog.h \
  mconf_inputbox.c \
  mconf_menubox.c \
  mconf_msgbox.c \
  mconf_textbox.c \
  mconf_util.c \
  mconf_yesno.c
endif

gnunet_setup_SOURCES = \
 conf.c \
 confdata.c \
 expr.c \
 expr.h \
 lkc.h \
 $(mconf_src) \
 menu.c \
 symbol.c \
 zconf.tab.h \
 zconf_tab.c \
 gnunet-setup.c

gnunet_setup_LDFLAGS = \
 $(curses_lib)

gnunet_setup_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la

gnunet_win_tool_SOURCE = \
 gnunet-win-tool.c

gnunet_win_tool_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la
