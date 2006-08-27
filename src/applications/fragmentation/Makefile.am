INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_fragmentation.la 

libgnunetmodule_fragmentation_la_SOURCES = \
  fragmentation.c 
libgnunetmodule_fragmentation_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la  \
 $(top_builddir)/src/util/cron/libgnunetutil_cron.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la 
libgnunetmodule_fragmentation_la_LDFLAGS = \
  -export-dynamic -avoid-version -module


################################
# TESTCASES 
################################

EXTRA_DIST = check.conf

check_PROGRAMS = \
 fragmentationtest

TESTS = $(check_PROGRAMS)

fragmentationtest_SOURCES = \
 fragmentationtest.c 
fragmentationtest_LDADD = \
 $(top_builddir)/src/util/cron/libgnunetutil_cron.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
 $(top_builddir)/src/util/libgnunetutil.la  

