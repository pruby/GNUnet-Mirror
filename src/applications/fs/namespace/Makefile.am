INCLUDES = -I$(top_srcdir)/src/include


if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

lib_LTLIBRARIES = \
  libgnunetnamespace.la 

libgnunetnamespace_la_SOURCES = \
  common.c common.h \
  info.c \
  root_info.c \
  update_info.c \
  uri.c 
libgnunetnamespace_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunetnamespace_la_LIBADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) 

check_PROGRAMS = \
  namespace_infotest \
  namespace_update_test

TESTS = $(check_PROGRAMS)

EXTRA_DIST = check.conf peer.conf

namespace_infotest_SOURCES = \
  namespace_infotest.c 
namespace_infotest_LDADD = \
  $(top_builddir)/src/applications/fs/namespace/libgnunetnamespace.la \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/libgnunetutil.la 

namespace_update_test_SOURCES = \
  namespace_update_test.c 
namespace_update_test_LDADD = \
  $(top_builddir)/src/applications/fs/namespace/libgnunetnamespace.la \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/libgnunetutil.la 


