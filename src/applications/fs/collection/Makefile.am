INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = \
  libgnunetcollection.la 

libgnunetcollection_la_SOURCES = \
  collection.c 
libgnunetcollection_la_LIBADD = \
 $(top_builddir)/src/applications/fs/namespace/libgnunetnamespace.la \
 $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
 $(top_builddir)/src/util/libgnunetutil.la 

check_PROGRAMS = \
  collectiontest 

TESTS = $(check_PROGRAMS)

collectiontest_SOURCES = \
  collectiontest.c 
collectiontest_LDADD = \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la  \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la  \
  $(top_builddir)/src/applications/fs/collection/libgnunetcollection.la 

EXTRA_DIST = \
  check.conf peer.conf
