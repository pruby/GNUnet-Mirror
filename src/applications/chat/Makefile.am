INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

bin_PROGRAMS = \
  gnunet-chat

lib_LTLIBRARIES = \
  libgnunetstats_api.la

plugin_LTLIBRARIES = \
  libgnunetmodule_chat.la

gnunet_chat_SOURCES = \
  gnunet-chat.c 
gnunet_chat_LDADD = \
  $(top_builddir)/src/applications/chat/libgnunetchat.so \
  $(top_builddir)/src/util/libgnunetutil.la

libgnunetchat_api_la_SOURCES = \
  clientapi.c 
libgnunetchat_api_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la

libgnunetmodule_chat_la_SOURCES = \
  chat.c \
  chat.h
libgnunetmodule_chat_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
libgnunetmodule_chat_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la 
