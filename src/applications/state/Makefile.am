INCLUDES = -I$(top_srcdir)/src/include

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_state.la

lib_LTLIBRARIES = \
  libgnunetstate_api.la

bin_PROGRAMS = \
 gnunet-stats

libgnunetmodule_state_la_SOURCES = \
  state.c
libgnunetmodule_state_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunetmodule_state_la_LDFLAGS = \
  -export-dynamic -avoid-version -module

check_PROGRAMS = \
 statetest

TESTS = $(check_PROGRAMS)

statetest_SOURCES = \
 statetest.c
statetest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

