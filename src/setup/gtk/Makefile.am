INCLUDES = -I$(top_srcdir)/src/include -I../lib

AM_CFLAGS = $(GTK_CFLAGS)

plugindir = $(libdir)/GNUnet

# GNU Gettext support
LIBS = @LIBINTL@ @LIBS@

plugin_LTLIBRARIES = \
  libgnunetsetup_gtk.la

EXTRA_DIST = \
 wizard.glade 

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(pkgdatadir)
	$(INSTALL_DATA) gnunet-setup.glade $(DESTDIR)$(pkgdatadir)
	@$(NORMAL_INSTALL)

libgnunetsetup_gtk_la_SOURCES = \
 about.c \
 gconf.c gconf.h \
 glade_support.h glade_support.c \
 wizard_gtk.c wizard_gtk.h

libgnunetsetup_gtk_la_LDFLAGS = \
 $(GTK_LIBS) @EXT_LIB_PATH@ @EXT_LIBS@ \
 -export-dynamic -avoid-version -module

libgnunetsetup_gtk_la_CFLAGS = \
 -I$(top_scrdir)/include \
 @GNUNETGTK_CFLAGS@ \
 @GTK_CFLAGS@ 

libgnunetsetup_gtk_la_LIBADD = \
 @GTK_LIBS@ @EXT_LIB_PATH@ @EXT_LIBS@ \
 @GNUNETGTK_LIBS@ \
  $(INTLLIBS) \
  -lgthread-2.0 \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/setup/lib/libgnunetsetup.la

