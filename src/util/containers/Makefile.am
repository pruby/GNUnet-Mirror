SUBDIRS = .

INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

noinst_LTLIBRARIES = libcontainers.la

libcontainers_la_SOURCES = \
 bloomfilter.c \
 meta.c \
 multihashmap.c 

libcontainers_la_LIBADD = \
 -lz \
 -lextractor 

check_PROGRAMS = \
 bloomtest \
 maptest \
 metatest 

TESTS = $(check_PROGRAMS)

bloomtest_SOURCES = \
 bloomtest.c
bloomtest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

maptest_SOURCES = \
 maptest.c
maptest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

metatest_SOURCES = \
 metatest.c
metatest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 
