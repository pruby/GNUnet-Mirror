INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la 

bin_PROGRAMS = \
  gnunet-testbed

plugin_LTLIBRARIES = \
  libgnunetmodule_testbed.la


gnunet_testbed_SOURCES = \
  gnunet-testbed.c \
  testbed.h \
  socket.c \
  socket.h \
  commands.c \
  get-stats.c \
  get-stats.h \
  commands.h


libgnunetmodule_testbed_la_SOURCES = \
  testbed.c\
  testbed.h

libgnunetmodule_testbed_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la

libgnunetmodule_testbed_la_LDFLAGS = \
  -export-dynamic -avoid-version -module

EXTRA_DIST = \
  functions.sh \
  connect.php3 \
  display.php3 \
  startup.php3 
