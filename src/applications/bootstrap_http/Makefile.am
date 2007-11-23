INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_bootstrap.la 

libgnunetmodule_bootstrap_la_SOURCES = \
  http.c 
libgnunetmodule_bootstrap_la_LIBADD = @LIBCURL@ \
 $(top_builddir)/src/util/libgnunetutil.la 
libgnunetmodule_bootstrap_la_LDFLAGS = \
  -export-dynamic -avoid-version -module 
libgnunetmodule_bootstrap_la_CPPFLAGS = \
 @LIBCURL_CPPFLAGS@ 


check_PROGRAMS = \
  httptest

TESTS = $(check_PROGRAMS)

httptest_SOURCES = \
  httptest.c 
httptest_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la 

