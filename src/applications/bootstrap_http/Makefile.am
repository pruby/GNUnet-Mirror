INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_bootstrap.la 

libgnunetmodule_bootstrap_la_SOURCES = \
  http.c 
libgnunetmodule_bootstrap_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la 
libgnunetmodule_bootstrap_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
