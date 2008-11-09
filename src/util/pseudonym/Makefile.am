INCLUDES = -I$(top_srcdir)/src/include

noinst_LTLIBRARIES = \
  libpseudonym.la 
if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

libpseudonym_la_SOURCES = \
  common.c common.h \
  names.c \
  info.c info.h \
  notification.c  notification.h 

check_PROGRAMS = \
  info_test

TESTS = $(check_PROGRAMS)

EXTRA_DIST = check.conf 

info_test_SOURCES = \
  info_test.c 
info_test_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la 


