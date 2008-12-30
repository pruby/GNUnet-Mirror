INCLUDES = -I$(top_srcdir)/src/include


if USE_COVERAGE
  coverageflags = -fprofile-arcs -ftest-coverage
endif

AM_CFLAGS = $(GTK_CFLAGS) $(coverageflags)

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_upnp.la

libgnunetmodule_upnp_la_SOURCES = \
 error.c error.h \
 init.c \
 ip.c ip.h \
 util.c util.h \
 upnp.c upnp.h \
 xmlnode.c xmlnode.h 

libgnunetmodule_upnp_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_upnp_la_CFLAGS = \
 -I$(top_scrdir)/include \
 @LIBCURL_CPPFLAGS@ @XML_CPPFLAGS@
libgnunetmodule_upnp_la_LIBADD = \
 @EXT_LIB_PATH@ @EXT_LIBS@ @XML_LIBS@ @LIBCURL@ \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(GN_LIBINTL) 

check_PROGRAMS = \
 upnptest 

TESTS = $(check_PROGRAMS)

upnptest_SOURCES = \
 upnptest.c 
upnptest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 


