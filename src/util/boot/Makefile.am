INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

noinst_LTLIBRARIES = \
  libboot.la

libboot_la_SOURCES = \
  startup.c

EXTRA_DIST = lib_argz.c lib_mempcpy.c lib_strnlen.c lib_strndup.c

