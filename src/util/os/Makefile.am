INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .
if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

EXTRA_DIST = check.conf

noinst_LTLIBRARIES = \
  libos.la

libos_la_SOURCES = \
 console.c \
 cpustatus.c \
 daemon.c \
 dso.c \
 init.c \
 osconfig.c \
 priority.c \
 semaphore.c \
 statuscalls.c \
 time.c \
 user.c \
 installpath.c

check_PROGRAMS = \
 daemontest \
 semaphoretest \
 statuscallstest

TESTS = $(check_PROGRAMS)

daemontest_SOURCES = \
 daemontest.c 
daemontest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 


semaphoretest_SOURCES = \
 semaphoretest.c
semaphoretest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

statuscallstest_SOURCES = \
 statuscallstest.c
statuscallstest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  
