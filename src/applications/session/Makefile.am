INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_session.la 

libgnunetmodule_session_la_SOURCES = \
  connect.c 
libgnunetmodule_session_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la 
libgnunetmodule_session_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
