INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_identity.la 

EXTRA_DIST = \
  check.conf

libgnunetmodule_identity_la_SOURCES = \
  identity.c \
  hostkey.c \
  hostkey.h
libgnunetmodule_identity_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la 
libgnunetmodule_identity_la_LDFLAGS = \
  -export-dynamic -avoid-version -module


check_PROGRAMS = \
  identitytest


TESTS = $(check_PROGRAMS)

identitytest_SOURCES = \
 identitytest.c 
identitytest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/server/libgnunetcore.la  
