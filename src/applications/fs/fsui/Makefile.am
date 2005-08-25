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
  unindex.c \
  upload.c
libgnunetfsui_la_LIBADD = \
 -lextractor \
 $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
 $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  check.conf


check_PROGRAMS = \
  fsuitest \
  fsuitest2 \
  searchtest \
  downloadtest \
  namespace_infotest

TESTS = $(check_PROGRAMS)

fsuitest_SOURCES = \
  fsuitest.c 
fsuitest_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

fsuitest2_SOURCES = \
  fsuitest2.c 
fsuitest2_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

namespace_infotest_SOURCES = \
  namespace_infotest.c 
namespace_infotest_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

searchtest_SOURCES = \
  searchtest.c 
searchtest_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

downloadtest_SOURCES = \
  downloadtest.c 
downloadtest_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

