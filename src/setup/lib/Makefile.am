INCLUDES = -I$(top_srcdir)/src/include

AM_CFLAGS = $(GTK_CFLAGS)

plugindir = $(libdir)/GNUnet

# GNU Gettext support
LIBS = @LIBINTL@ @LIBS@

lib_LTLIBRARIES = libgnunetsetup.la

if HAVE_GUILE
 GUILE_SRC = \
    gns.c \
    tree.c tree.h
 GUILE_LIB = -lguile
endif

libgnunetsetup_la_SOURCES = \
	$(GUILE_SRC) \
  wizard_util.c wizard_util.h

libgnunetsetup_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

libgnunetsetup_la_LDFLAGS = \
 -export-dynamic $(GUILE_LIB)

libgnunetsetup_la_CFLAGS = -I$(top_scrdir)/include 


