INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif
plugindir = $(libdir)/GNUnet

lib_LTLIBRARIES = \
  libgnunetrpcutil.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_rpc.la

libgnunetmodule_rpc_la_SOURCES = \
  rpc.c 
libgnunetmodule_rpc_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_rpc_la_LIBADD = \
  $(top_builddir)/src/applications/rpc/libgnunetrpcutil.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

libgnunetrpcutil_la_SOURCES = \
  parameters.c 
libgnunetrpcutil_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunetrpcutil_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la 


check_PROGRAMS = \
  parameterstest 

TESTS = $(check_PROGRAMS)

parameterstest_SOURCES = \
  parameterstest.c 

parameterstest_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la 
