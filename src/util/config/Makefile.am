INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

noinst_LTLIBRARIES = \
  libconfig.la

libconfig_la_SOURCES = \
  config.c

check_PROGRAMS = \
 configtest 

TESTS = $(check_PROGRAMS)

configtest_SOURCES = \
 configtest.c
configtest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 


EXTRA_DIST = \
  testconfig.conf 
