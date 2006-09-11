INCLUDES = -I$(top_srcdir)/src/include

if HAVE_GTK
 gtk_dir = gtk
endif
if HAVE_DIALOG
 curses_dir = ncurses
endif

if !MINGW
 textdir=text
endif

SUBDIRS = lib $(textdir) . $(curses_dir) $(gtk_dir) .

plugindir = $(libdir)/GNUnet

# GNU Gettext support
LIBS = @LIBINTL@ @LIBS@

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
 $(top_builddir)/src/util/loggers/libgnunetutil_logging.la \
 $(top_builddir)/src/util/config_impl/libgnunetutil_config.la 

gnunet_win_tool_SOURCE = \
 gnunet-win-tool.c

gnunet_win_tool_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/loggers/libgnunetutil_logging.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
 $(top_builddir)/src/util/config_impl/libgnunetutil_config.la 
