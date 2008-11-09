INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .
if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

noinst_LTLIBRARIES = \
  libgetopt.la

libgetopt_la_SOURCES = \
  getopt.c \
  setoption.c \
  printhelp.c \
  printversion.c 

