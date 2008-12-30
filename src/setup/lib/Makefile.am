INCLUDES = -I$(top_srcdir)/src/include

AM_CFLAGS = $(GTK_CFLAGS)

plugindir = $(libdir)/GNUnet

lib_LTLIBRARIES = libgnunetsetup.la

if HAVE_GUILE
 GUILE_SRC = \
    gns.c \
    tree.c tree.h
 GUILE_LIB = -lguile -lgmp
endif

libgnunetsetup_la_SOURCES = \
  $(GUILE_SRC) \
  wizard_util.c wizard_util.h
libgnunetsetup_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunetsetup_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GUILE_LIB) \
  $(GN_LIBINTL) \
  $(LIBLTDL) \
  $(LIBADD_DL)

