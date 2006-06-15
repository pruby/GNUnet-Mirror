INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .

lib_LTLIBRARIES = \
  libgnunetutil_logging.la

libgnunetutil_logging_la_SOURCES = \
  file.c memory.c
# smtp.c

libgnunetutil_logging_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

