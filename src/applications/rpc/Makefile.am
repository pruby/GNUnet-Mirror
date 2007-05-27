INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

lib_LTLIBRARIES = \
  libgnunetrpc_util.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_rpc.la

libgnunetmodule_rpc_la_SOURCES = \
  rpc.c 

libgnunetmodule_rpc_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/util/cron/libgnunetutil_cron.la \
  $(top_builddir)/src/util/containers/libgnunetutil_containers.la \
  $(top_builddir)/src/applications/rpc/libgnunetrpc_util.la

libgnunetmodule_rpc_la_LDFLAGS = \
  -export-dynamic -avoid-version -module

libgnunetrpc_util_la_SOURCES = \
  parameters.c 

libgnunetrpc_util_la_LIBADD = \
  $(top_builddir)/src/util/containers/libgnunetutil_containers.la \
  $(top_builddir)/src/util/libgnunetutil.la 


check_PROGRAMS = \
  parameterstest 

TESTS = $(check_PROGRAMS)

parameterstest_SOURCES = \
  parameterstest.c 

parameterstest_LDADD = \
  $(top_builddir)/src/util/containers/libgnunetutil_containers.la \
  $(top_builddir)/src/util/libgnunetutil.la 
