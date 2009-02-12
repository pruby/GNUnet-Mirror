SUBDIRS = \
 . gap lib ecrs uritrack namespace fsui collection tools 


if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = \
  libgnunetecrscore.la 

libgnunetecrscore_la_SOURCES = \
  ecrs_core.c
libgnunetecrscore_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunetecrscore_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


check_PROGRAMS = \
  ecrs_core_test

TESTS = $(check_PROGRAMS)

ecrs_core_test_SOURCES = \
  ecrs_core_test.c 
ecrs_core_test_LDADD = \
  $(top_builddir)/src/applications/fs/libgnunetecrscore.la 

