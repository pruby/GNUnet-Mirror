INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_datastore.la


libgnunetmodule_datastore_la_SOURCES = \
  filter.c filter.h \
  prefetch.c prefetch.h \
  datastore.c 
libgnunetmodule_datastore_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
libgnunetmodule_datastore_la_LIBADD = \
  $(LDADD)

