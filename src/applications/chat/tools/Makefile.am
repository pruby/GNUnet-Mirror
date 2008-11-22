INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

bin_PROGRAMS = \
 gnunet-chat

gnunet_chat_SOURCES = \
 gnunet-chat.c 	
gnunet_chat_LDADD = \
  $(top_builddir)/src/applications/chat/lib/libgnunetchat_api.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
