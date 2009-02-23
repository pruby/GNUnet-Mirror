INCLUDES = -I$(top_srcdir)/src/include -I$(top_srcdir)/src/setup/lib

gnunetincludedir = $(includedir)/GNUnet

gnunetinclude_HEADERS = GNUNETSetupView.h

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetsetup_cocoa.la

if HAVE_GUILE
GUILE_SRC = \
  GNUNETSetupView.m GNUNETSetupView.h \
  config_cocoa.m config_cocoa.h
endif

EXTRA_DIST = \
  GNUNETSetupView.m GNUNETSetupView.h \
  config_cocoa.m config_cocoa.h

libgnunetsetup_cocoa_la_SOURCES = \
  $(GUILE_SRC) \
  PackingBoxContainer.m PackingBoxContainer.h
libgnunetsetup_cocoa_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS) \
  -framework Cocoa
libgnunetsetup_cocoa_la_LIBADD = \
  $(top_builddir)/src/setup/lib/libgnunetsetup.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

