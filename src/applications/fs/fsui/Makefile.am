INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = \
  libgnunetfsui.la 


libgnunetfsui_la_SOURCES = \
  collection.c \
  download.c \
  file_info.c \
  fsui.c fsui.h \
  helper.c \
  namespace_info.c \
  search.c \
  upload.c
libgnunetfsui_la_LIBADD = \
 -lextractor \
 $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
 $(top_builddir)/src/util/libgnunetutil.la 


check_PROGRAMS = \
  fsuitest 

TESTS = $(check_PROGRAMS)

fsuitest_SOURCES = \
  fsuitest.c 
fsuitest_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 
