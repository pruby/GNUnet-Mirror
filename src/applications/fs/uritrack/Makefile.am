INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = \
  libgnuneturitrack.la 

libgnuneturitrack_la_SOURCES = \
  file_info.c \
  callbacks.c callbacks.h
libgnuneturitrack_la_LIBADD = \
 $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
 $(top_builddir)/src/util/libgnunetutil.la 

