INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_datastore.la

libgnunetmodule_datastore_la_SOURCES = \
  filter.c filter.h \
  prefetch.c prefetch.h \
  datastore.c 
libgnunetmodule_datastore_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_datastore_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

