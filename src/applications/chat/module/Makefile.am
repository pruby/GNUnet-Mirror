INCLUDES = -I$(top_srcdir)/src/include

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_chat.la

libgnunetmodule_chat_la_SOURCES = \
  chat.c 
libgnunetmodule_chat_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_chat_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
