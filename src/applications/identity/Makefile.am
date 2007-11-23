INCLUDES = -I$(top_srcdir)/src/include

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
libgnunetmodule_identity_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la
libgnunetmodule_identity_la_LDFLAGS = \
  -export-dynamic -avoid-version -module


libgnunetidentity_api_la_SOURCES = \
  clientapi.c 
libgnunetidentity_api_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la 


check_PROGRAMS = \
  identitytest


TESTS = $(check_PROGRAMS)

identitytest_SOURCES = \
 identitytest.c 
identitytest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/applications/identity/libgnunetidentity_api.la \
 $(top_builddir)/src/server/libgnunetcore.la  
