INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

lib_LTLIBRARIES = \
  libgnunetmodule_rpc_util.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_rpc.la

libgnunetmodule_rpc_la_SOURCES = \
  rpc.c 

libgnunetmodule_rpc_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/applications/rpc/libgnunetmodule_rpc_util.la

libgnunetmodule_rpc_la_LDFLAGS = \
  -export-dynamic -avoid-version -module

libgnunetmodule_rpc_util_la_SOURCES = \
  parameters.c 

libgnunetmodule_rpc_util_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la 


check_PROGRAMS = \
  parameterstest 

TESTS = $(check_PROGRAMS)

parameterstest_SOURCES = \
  parameterstest.c 

parameterstest_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la 
