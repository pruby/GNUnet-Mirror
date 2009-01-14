INCLUDES = -I$(top_srcdir)/src/include

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_dv.la

libgnunetmodule_dv_la_SOURCES = \
  dv.c heap.c
libgnunetmodule_dv_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_dv_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
