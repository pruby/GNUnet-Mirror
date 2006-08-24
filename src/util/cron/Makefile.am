INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .

lib_LTLIBRARIES = \
  libgnunetutil_cron.la

libgnunetutil_cron_la_SOURCES = \
 cron.c
libgnunetutil_cron_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

check_PROGRAMS = \
 crontest \
 timertest

TESTS = $(check_PROGRAMS)

crontest_SOURCES = \
 crontest.c
crontest_LDADD = \
 $(top_builddir)/src/util/cron/libgnunetutil_cron.la \
 $(top_builddir)/src/util/libgnunetutil.la  



timertest_SOURCES = \
 timertest.c
timertest_LDADD = \
 $(top_builddir)/src/util/cron/libgnunetutil_cron.la \
 $(top_builddir)/src/util/libgnunetutil.la  

