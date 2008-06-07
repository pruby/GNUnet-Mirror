INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .

noinst_LTLIBRARIES = \
  libstring.la

libstring_la_SOURCES = \
  parser.c \
  string.c \
  xmalloc.c 

check_PROGRAMS = \
 xmalloctest 

TESTS = $(check_PROGRAMS)

xmalloctest_SOURCES = \
 xmalloctest.c 
xmalloctest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la

