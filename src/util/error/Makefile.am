INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

noinst_LTLIBRARIES = \
  liberror.la

liberror_la_SOURCES = \
  error.c


check_PROGRAMS = \
 error_test

TESTS = $(check_PROGRAMS)

error_test_SOURCES = \
 error_test.c
error_test_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  
