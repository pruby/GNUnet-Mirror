INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = \
  libgnunetmodule__afs_esed2.la 

libgnunetmodule__afs_esed2_la_SOURCES = \
  block.c \
  contentencoding.c \
  collection.c \
  deleteutil.c \
  directory.c \
  downloadutil.c \
  insertutil.c \
  keywords.c \
  nblock.c \
  policy.c \
  pseudonym.c \
  requestmanager.c \
  sblock.c \
  searchutil.c \
  priority.c \
  uri.c \
  resume.c

if USE_LIBEXTRACTOR
libgnunetmodule__afs_esed2_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lextractor 
else
libgnunetmodule__afs_esed2_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la 
endif

################################
# TESTCASES 
################################

check_PROGRAMS = \
 uritest

TESTS = $(check_PROGRAMS)

uritest_SOURCES = \
 uritest.c 
uritest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/applications/afs/esed2/libgnunetmodule__afs_esed2.la




