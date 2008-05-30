INCLUDES = -I$(top_srcdir)/src/include

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_chat.la

lib_LTLIBRARIES = \
  libgnunetchat_api.la

bin_PROGRAMS = \
 gnunet-chat

gnunet_chat_SOURCES = \
 gnunet-chat.c 	
gnunet_chat_LDADD = \
  $(top_builddir)/src/applications/chat/libgnunetchat_api.la 

libgnunetchat_api_la_SOURCES = \
  clientapi.c 
libgnunetchat_api_la_LIBADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/libgnunetutil.la 

libgnunetmodule_chat_la_SOURCES = \
  chat.c chat.h \
  chat_p2p.c chat_p2p.h
libgnunetmodule_chat_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunetmodule_chat_la_LDFLAGS = \
  -export-dynamic -avoid-version -module



check_PROGRAMS = \
  chattest

TESTS = $(check_PROGRAMS)

chattest_SOURCES = \
  chattest.c 
chattest_LDADD = \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/chat/libgnunetchat_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 
