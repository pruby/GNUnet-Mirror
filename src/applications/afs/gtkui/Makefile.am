INCLUDES = -I$(top_srcdir)/src/include



LDADD = \
  $(top_builddir)/src/applications/afs/esed2/libgnunetmodule__afs_esed2.la \
  $(top_builddir)/src/util/libgnunetutil.la

AM_CFLAGS = $(GTK_CFLAGS)

bin_PROGRAMS = \
  gnunet-gtk

pkgdata_DATA = \
  gnunet_logo.png

DEFS = -DDATADIR=\"$(pkgdatadir)\" @DEFS@

EXTRA_DIST = \
  gnunet_logo.png

gnunet_gtk_LDADD = \
  $(GTK_LIBS) @EXT_LIB_PATH@ $(LDADD) @EXT_LIBS@ -lgthread-2.0

gnunet_gtk_SOURCES = \
  main.c \
  search.c  \
  saveas.c  \
  download.c \
  directory.c \
  gtk26about.c \
  gtk26about.h \
  pseudonyms.c \
  namespace.c \
  helper.c \
  insert.c\
  insertprogress.c\
  delete.c\
  directorydisplay.c \
  about.c \
  statistics.c \
  statistics.h \
  main.h \
  search.h  \
  saveas.h  \
  download.h \
  directory.h \
  pseudonyms.h \
  namespace.h \
  helper.h \
  insert.h\
  insertprogress.h\
  delete.h\
  directorydisplay.h \
  about.h
