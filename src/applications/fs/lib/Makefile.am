INCLUDES = -I$(top_srcdir)/src/include


if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

lib_LTLIBRARIES = \
  libgnunetfs.la

libgnunetfs_la_SOURCES = \
  fslib.c 
libgnunetfs_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunetfs_la_LIBADD = \
  $(top_builddir)/src/applications/fs/libgnunetecrscore.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


check_PROGRAMS = \
  fslibtest

TESTS = $(check_PROGRAMS)

fslibtest_SOURCES = \
  fslibtest.c
fslibtest_LDADD = \
  $(top_builddir)/src/applications/fs/lib/libgnunetfs.la \
  $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  check.conf \
  peer.conf
