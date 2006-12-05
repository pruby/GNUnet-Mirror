SUBDIRS = \
 . module lib ecrs uritrack namespace fsui collection tools 

INCLUDES = -I$(top_srcdir)/src/include

noinst_LTLIBRARIES = \
  libecrs_core.la 

libecrs_core_la_SOURCES = \
  ecrs_core.c
libecrs_core_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la


check_PROGRAMS = \
  ecrs_core_test

TESTS = $(check_PROGRAMS)

ecrs_core_test_SOURCES = \
  ecrs_core_test.c 
ecrs_core_test_LDADD = \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la \
  $(top_builddir)/src/applications/fs/libecrs_core.la 

