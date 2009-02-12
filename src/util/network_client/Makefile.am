INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif
noinst_LTLIBRARIES = \
  libnetwork_client.la

libnetwork_client_la_SOURCES = \
 daemon.c \
 tcpio.c 

check_PROGRAMS = \
 tcpiotest 

TESTS = $(check_PROGRAMS)

tcpiotest_SOURCES = \
 tcpiotest.c
tcpiotest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 


EXTRA_DIST = check.conf
