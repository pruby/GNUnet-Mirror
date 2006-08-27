SUBDIRS = .

INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = libgnunetutil_containers.la

libgnunetutil_containers_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la 

libgnunetutil_containers_la_LDFLAGS = \
 -version-info 0:0:0

libgnunetutil_containers_la_SOURCES = \
 bloomfilter.c \
 hashtable.c \
 vector.c 

check_PROGRAMS = \
 bloomtest \
 hashtabletest \
 vectortest 

TESTS = $(check_PROGRAMS)

bloomtest_SOURCES = \
 bloomtest.c
bloomtest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/containers/libgnunetutil_containers.la 

hashtabletest_SOURCES = \
 hashtabletest.c
hashtabletest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  \
 $(top_builddir)/src/util/containers/libgnunetutil_containers.la 

vectortest_SOURCES = \
 vectortest.c
vectortest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  \
 $(top_builddir)/src/util/containers/libgnunetutil_containers.la   

