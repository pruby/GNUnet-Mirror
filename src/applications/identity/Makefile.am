INCLUDES = -I$(top_srcdir)/src/include


if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif
plugindir = $(libdir)/GNUnet

lib_LTLIBRARIES = \
  libgnunetidentity_api.la

plugin_LTLIBRARIES = \
  libgnunetmodule_identity.la 

EXTRA_DIST = \
  check.conf

libgnunetmodule_identity_la_SOURCES = \
  identity.c identity.h \
  hostkey.c hostkey.h
libgnunetmodule_identity_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_identity_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


libgnunetidentity_api_la_SOURCES = \
  clientapi.c 
libgnunetidentity_api_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunetidentity_api_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) 


check_PROGRAMS = \
  identitytest


TESTS = $(check_PROGRAMS)

identitytest_SOURCES = \
 identitytest.c 
identitytest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/applications/identity/libgnunetidentity_api.la \
 $(top_builddir)/src/server/libgnunetcore.la  
