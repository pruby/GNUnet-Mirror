INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = \
  libgnunetnamespace.la 

libgnunetnamespace_la_SOURCES = \
  namespace_info.c 
libgnunetnamespace_la_LIBADD = \
 $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
 $(top_builddir)/src/util/libgnunetutil.la 

check_PROGRAMS = \
  namespace_infotest

TESTS = $(check_PROGRAMS)

EXTRA_DIST = check.conf peer.conf

namespace_infotest_SOURCES = \
  namespace_infotest.c 
namespace_infotest_LDADD = \
  $(top_builddir)/src/applications/fs/namespace/libgnunetnamespace.la \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la \
  $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
  $(top_builddir)/src/util/libgnunetutil.la 


