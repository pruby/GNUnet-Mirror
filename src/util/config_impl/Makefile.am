INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .

lib_LTLIBRARIES = \
  libgnunetutil_config.la

libgnunetutil_config_la_SOURCES = \
  impl.c

libgnunetutil_config_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la 


check_PROGRAMS = \
 configtest 

TESTS = $(check_PROGRAMS)

configtest_SOURCES = \
 configtest.c
configtest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/loggers/libgnunetutil_logging.la \
 $(top_builddir)/src/util/config_impl/libgnunetutil_config.la 


EXTRA_DIST = \
  testconfig.conf 
