INCLUDES = -I$(top_srcdir)/src/include

if HAVE_GTK
 gtk_dir = gtk
endif
if HAVE_QT
 qt_dir = qt
endif
if MACOSX
if HAVE_GUILE
 cocoa_dir = cocoa
endif
endif
if HAVE_DIALOG
 curses_dir = ncurses
endif
if HAVE_CDIALOG
 curses_dir = ncurses
endif

if !MINGW
if HAVE_GUILE
 textdir=text
endif
endif

SUBDIRS = lib $(textdir) . $(curses_dir) $(gtk_dir) $(qt_dir) $(cocoa_dir) .

plugindir = $(libdir)/GNUnet

if MINGW
 WINTOOL = gnunet-win-tool
endif

bin_PROGRAMS = \
 gnunet-setup \
 $(WINTOOL)

gnunet_setup_SOURCES = \
 gnunet-setup.c
gnunet_setup_LDADD = \
 $(top_builddir)/src/setup/lib/libgnunetsetup.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(GN_LIBINTL)

gnunet_win_tool_SOURCE = \
 gnunet-win-tool.c

gnunet_win_tool_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 
