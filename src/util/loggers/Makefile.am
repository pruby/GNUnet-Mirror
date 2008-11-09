INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .
if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

noinst_LTLIBRARIES = \
  libloggers.la

libloggers_la_SOURCES = \
  file.c memory.c
# smtp.c


