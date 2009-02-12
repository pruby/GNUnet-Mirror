INCLUDES = -I$(top_srcdir)/src/include


if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif
plugindir = $(libdir)/GNUnet

lib_LTLIBRARIES = \
  libgnunetidentityapi.la

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


libgnunetidentityapi_la_SOURCES = \
  clientapi.c 
libgnunetidentityapi_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunetidentityapi_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) 


check_PROGRAMS = \
  identitytest


TESTS = $(check_PROGRAMS)

identitytest_SOURCES = \
 identitytest.c 
identitytest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/applications/identity/libgnunetidentityapi.la \
 $(top_builddir)/src/server/libgnunetcore.la  
