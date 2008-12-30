INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif
plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_pingpong.la 

libgnunetmodule_pingpong_la_SOURCES = \
  pingpong.c 
libgnunetmodule_pingpong_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_pingpong_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) 
