INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = \
  libgnunetfsui.la 

noinst_PROGRAMS = fsui-loader

libgnunetfsui_la_SOURCES = \
  deserialize.c \
  download.c \
  fsui.c fsui.h \
  search.c \
  serialize.c \
  unindex.c \
  upload.c
libgnunetfsui_la_LIBADD = \
 -lextractor \
 $(top_builddir)/src/applications/identity/libgnunetidentity_api.la \
 $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
 $(top_builddir)/src/applications/fs/namespace/libgnunetnamespace.la \
 $(top_builddir)/src/applications/fs/uritrack/libgnuneturitrack.la \
 $(top_builddir)/src/util/cron/libgnunetutil_cron.la \
 $(top_builddir)/src/util/loggers/libgnunetutil_logging.la \
 $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la \
 $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  check.conf \
  peer.conf

fsui_loader_SOURCES = \
 fsui-loader.c 
fsui_loader_LDADD = \
 $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la  \
 $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
 $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
 $(top_builddir)/src/util/config_impl/libgnunetutil_config.la \
 $(top_builddir)/src/util/libgnunetutil.la 

check_PROGRAMS = \
  fsuitest \
  fsuitest2 \
  searchtest \
  serializetest \
  serializetest2 \
  serializetest3 \
  serializetest4 \
  downloadtest 

TESTS = $(check_PROGRAMS)

fsuitest_SOURCES = \
  fsuitest.c 
fsuitest_LDADD = \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la  \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la  \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

fsuitest2_SOURCES = \
  fsuitest2.c 
fsuitest2_LDADD = \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la  \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la  \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

searchtest_SOURCES = \
  searchtest.c 
searchtest_LDADD = \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la  \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la  \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

downloadtest_SOURCES = \
  downloadtest.c 
downloadtest_LDADD = \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la  \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la  \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

serializetest_SOURCES = \
  serializetest.c 
serializetest_LDADD = \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la  \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la  \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

serializetest2_SOURCES = \
  serializetest2.c 
serializetest2_LDADD = \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la  \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la  \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

serializetest3_SOURCES = \
  serializetest3.c 
serializetest3_LDADD = \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la  \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la  \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 


serializetest4_SOURCES = \
  serializetest4.c 
serializetest4_LDADD = \
  $(top_builddir)/src/util/config_impl/libgnunetutil_config.la  \
  $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la  \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

