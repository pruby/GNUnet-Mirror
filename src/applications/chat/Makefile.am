INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

LDADD =  \
  $(top_builddir)/src/util/libgnunetutil.la 

bin_PROGRAMS = \
  gnunet-chat

plugin_LTLIBRARIES = \
  libgnunetmodule_chat.la


gnunet_chat_SOURCES = \
  gnunet-chat.c \
  chat.h 

libgnunetmodule_chat_la_SOURCES = \
  chat.c \
  chat.h
libgnunetmodule_chat_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
libgnunetmodule_chat_la_LIBADD = \
  $(LDADD)
