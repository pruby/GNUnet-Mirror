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
 $(top_builddir)/src/applications/fs/lib/libgnunetfs.la \
 $(top_builddir)/src/applications/fs/namespace/libgnunetnamespace.la \
 $(top_builddir)/src/applications/fs/uritrack/libgnuneturitrack.la \
 $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  check.conf \
  peer.conf

fsui_loader_SOURCES = \
 fsui-loader.c 
fsui_loader_LDADD = \
 $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
 $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
 $(top_builddir)/src/util/libgnunetutil.la 

check_PROGRAMS = \
  fsui_start_stop_test \
  basic_fsui_test \
  upload_unindex_persistence_test \
  search_ranking_test \
  search_persistence_test \
  search_pause_resume_persistence_test \
  search_linked_download_persistence_test \
  recursive_download_test \
  download_persistence_test \
  recursive_download_persistence_test 

TESTS = $(check_PROGRAMS)

basic_fsui_test_SOURCES = \
  basic_fsui_test.c 
basic_fsui_test_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

fsui_start_stop_test_SOURCES = \
  fsui_start_stop_test.c 
fsui_start_stop_test_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

search_pause_resume_persistence_test_SOURCES = \
  search_pause_resume_persistence_test.c 
search_pause_resume_persistence_test_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

search_ranking_test_SOURCES = \
  search_ranking_test.c 
search_ranking_test_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

download_persistence_test_SOURCES = \
  download_persistence_test.c 
download_persistence_test_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

recursive_download_test_SOURCES = \
  recursive_download_test.c 
recursive_download_test_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

upload_unindex_persistence_test_SOURCES = \
  upload_unindex_persistence_test.c 
upload_unindex_persistence_test_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

search_linked_download_persistence_test_SOURCES = \
  search_linked_download_persistence_test.c 
search_linked_download_persistence_test_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

search_persistence_test_SOURCES = \
  search_persistence_test.c 
search_persistence_test_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 


recursive_download_persistence_test_SOURCES = \
  recursive_download_persistence_test.c 
recursive_download_persistence_test_LDADD = \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/util/libgnunetutil.la 

