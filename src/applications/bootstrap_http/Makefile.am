INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_bootstrap.la 

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

libgnunetmodule_bootstrap_la_SOURCES = \
  http.c 
libgnunetmodule_bootstrap_la_LIBADD = @LIBCURL@ \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(GN_LIBINTL) 
libgnunetmodule_bootstrap_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_bootstrap_la_CPPFLAGS = \
 @LIBCURL_CPPFLAGS@ 


check_PROGRAMS = \
  httptest

TESTS = $(check_PROGRAMS)

httptest_SOURCES = \
  httptest.c 
httptest_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la 

