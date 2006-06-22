INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .

noinst_LTLIBRARIES = \
  libnetwork.la

libnetwork_la_SOURCES = \
 endian.c \
 io.c \
 ipcheck.c \
 port.c \
 tcp_return.c \
 tcpio.c 

check_PROGRAMS = \
 tcpiotest 

TESTS = $(check_PROGRAMS)

tcpiotest_SOURCES = \
 tcpiotest.c
tcpiotest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  



