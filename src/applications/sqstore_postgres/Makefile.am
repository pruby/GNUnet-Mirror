INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif
plugindir = $(libdir)/GNUnet

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_sqstore_postgres.la

check_PROGRAMS = \
  postgres_test \
  postgres_test2 \
  postgres_test3

TESTS = $(check_PROGRAMS)

AM_CPPFLAGS = $(CPPFLAGS) $(POSTGRES_CPPFLAGS)

libgnunetmodule_sqstore_postgres_la_SOURCES = \
  postgres.c 
libgnunetmodule_sqstore_postgres_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS) \
  $(POSTGRES_LDFLAGS)
libgnunetmodule_sqstore_postgres_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lpq \
  $(GN_LIBINTL)

EXTRA_DIST = check.conf

postgres_test_SOURCES = \
 postgres_test.c 
postgres_test_LDADD = \
 $(top_builddir)/src/server/libgnunetcore.la  \
 $(top_builddir)/src/util/libgnunetutil.la  


postgres_test2_SOURCES = \
 postgres_test2.c 
postgres_test2_LDADD = -lpq \
 $(top_builddir)/src/server/libgnunetcore.la  \
 $(top_builddir)/src/util/libgnunetutil.la  



postgres_test3_SOURCES = \
 postgres_test3.c 
postgres_test3_LDADD = \
 $(top_builddir)/src/server/libgnunetcore.la  \
 $(top_builddir)/src/util/libgnunetutil.la  
