INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .

lib_LTLIBRARIES = \
  libgnunetutil_network_client.la

libgnunetutil_network_client_la_SOURCES = \
 daemon.c \
 tcpio.c 
libgnunetutil_network_client_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

check_PROGRAMS = \
 tcpiotest 

TESTS = $(check_PROGRAMS)

tcpiotest_SOURCES = \
 tcpiotest.c
tcpiotest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/config_impl/libgnunetutil_config.la \
 $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la 


EXTRA_DIST = check.conf