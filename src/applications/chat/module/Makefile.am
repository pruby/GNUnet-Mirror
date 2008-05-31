INCLUDES = -I$(top_srcdir)/src/include

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_chat.la

libgnunetmodule_chat_la_SOURCES = \
  chat.c 
libgnunetmodule_chat_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunetmodule_chat_la_LDFLAGS = \
  -export-dynamic -avoid-version -module

