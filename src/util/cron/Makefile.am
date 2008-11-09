INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

noinst_LTLIBRARIES = \
  libcron.la

libcron_la_SOURCES = \
 cron.c

check_PROGRAMS = \
 crontest \
 timertest

TESTS = $(check_PROGRAMS)

crontest_SOURCES = \
 crontest.c
crontest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  



timertest_SOURCES = \
 timertest.c
timertest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

