INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_fs.la


libgnunetmodule_fs_la_SOURCES = \
  anonymity.c anonymity.h \
  fs.c  \
  fs_dht.c fs_dht.h \
  gap.c gap.h \
  migration.c migration.h \
  ondemand.c ondemand.h \
  plan.c plan.h \
  pid_table.c pid_table.h \
  querymanager.c querymanager.h \
  shared.c shared.h 

libgnunetmodule_fs_la_LDFLAGS = \
  -export-dynamic -avoid-version -module -lm
libgnunetmodule_fs_la_LIBADD = \
 $(top_builddir)/src/applications/fs/libecrs_core.la \
 $(top_builddir)/src/util/libgnunetutil.la 



check_PROGRAMS = \
  test_loopback \
  test_linear_topology \
  test_multi_results \
  test_star_topology 

TESTS = $(check_PROGRAMS)

test_loopback_SOURCES = \
  test_loopback.c 
test_loopback_LDADD = \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/libgnunetutil.la 


test_linear_topology_SOURCES = \
  test_linear_topology.c 
test_linear_topology_LDADD = \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/libgnunetutil.la 

test_multi_results_SOURCES = \
  test_multi_results.c 
test_multi_results_LDADD = \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/libgnunetutil.la 


test_star_topology_SOURCES = \
  test_star_topology.c 
test_star_topology_LDADD = \
  $(top_builddir)/src/applications/identity/libgnunetidentity_api.la \
  $(top_builddir)/src/applications/testing/libgnunettesting_api.la \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/libgnunetutil.la 


EXTRA_DIST = \
  check.conf
