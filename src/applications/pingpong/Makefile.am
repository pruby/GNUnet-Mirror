INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_pingpong.la 

libgnunetmodule_pingpong_la_SOURCES = \
  pingpong.c 
libgnunetmodule_pingpong_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la 
libgnunetmodule_pingpong_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
