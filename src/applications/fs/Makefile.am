SUBDIRS = \
 . gap lib ecrs uritrack pseudonyms namespace fsui collection tools 

INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = \
  libgnunetecrs_core.la 

libgnunetecrs_core_la_SOURCES = \
  ecrs_core.c
libgnunetecrs_core_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la


check_PROGRAMS = \
  ecrs_core_test

TESTS = $(check_PROGRAMS)

ecrs_core_test_SOURCES = \
  ecrs_core_test.c 
ecrs_core_test_LDADD = \
  $(top_builddir)/src/applications/fs/libgnunetecrs_core.la 

