INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .

noinst_LTLIBRARIES = \
  libstring.la

libstring_la_SOURCES = \
  string.c \
  xmalloc.c \
  dlmalloc.c \
  dlmalloc.h

check_PROGRAMS = \
 xmalloctest 

TESTS = $(check_PROGRAMS)

xmalloctest_SOURCES = \
 xmalloctest.c 
xmalloctest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la

