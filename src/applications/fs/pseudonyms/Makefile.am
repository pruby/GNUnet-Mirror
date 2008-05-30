INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = \
  libgnunetpseudonym.la 

libgnunetpseudonym_la_SOURCES = \
  common.c common.h \
  names.c \
  info.c info.h \
  notification.c  notification.h 
libgnunetpseudonym_la_LIBADD = \
 $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
 $(top_builddir)/src/util/libgnunetutil.la 

check_PROGRAMS = \
  info_test

TESTS = $(check_PROGRAMS)

EXTRA_DIST = check.conf 

info_test_SOURCES = \
  info_test.c 
info_test_LDADD = \
  $(top_builddir)/src/applications/fs/pseudonyms/libgnunetpseudonym.la \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/libgnunetutil.la 


