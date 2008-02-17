SUBDIRS = .

INCLUDES = -I$(top_srcdir)/src/include

noinst_LTLIBRARIES = libcontainers.la

libcontainers_la_SOURCES = \
 bloomfilter.c 

check_PROGRAMS = \
 bloomtest 

TESTS = $(check_PROGRAMS)

bloomtest_SOURCES = \
 bloomtest.c
bloomtest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 
