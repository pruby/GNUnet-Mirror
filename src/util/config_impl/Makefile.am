INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .

noinst_LTLIBRARIES = \
  libconfigimpl.la

libconfigimpl_la_SOURCES = \
  impl.c

check_PROGRAMS = \
 configtest 

TESTS = $(check_PROGRAMS)

configtest_SOURCES = \
 configtest.c
configtest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 


EXTRA_DIST = \
  testconfig.conf 
