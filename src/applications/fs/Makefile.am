SUBDIRS = \
 . module lib ecrs fsui tools

INCLUDES = -I$(top_srcdir)/src/include

noinst_LTLIBRARIES = \
  libecrs_core.la 

libecrs_core_la_SOURCES = \
  ecrs_core.c
libecrs_core_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la 
