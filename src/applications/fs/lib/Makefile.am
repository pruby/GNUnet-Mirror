INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = \
  libgnunetfs.la

libgnunetfs_la_SOURCES = \
  fslib.c 
libgnunetfs_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/applications/fs/libecrs_core.la


check_PROGRAMS = \
  fslibtest

TESTS = $(check_PROGRAMS)

fslibtest_SOURCES = \
  fslibtest.c
fslibtest_LDADD = \
  $(top_builddir)/src/applications/fs/lib/libgnunetfs.la \
  $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  check.conf
