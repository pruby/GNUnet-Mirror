SUBDIRS = .

INCLUDES = -I$(top_srcdir)/src/include

noinst_LTLIBRARIES = libcontainers.la

libcontainers_la_SOURCES = \
 bloomfilter.c \
 meta.c 

libcontainers_la_LIBADD = \
 -lz \
 -lextractor 

check_PROGRAMS = \
 bloomtest \
 metatest

TESTS = $(check_PROGRAMS)

bloomtest_SOURCES = \
 bloomtest.c
bloomtest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 


metatest_SOURCES = \
 metatest.c
metatest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 
